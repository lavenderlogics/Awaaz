import { NextResponse } from "next/server";
import { getRedisClient, invalidateDashboardCache } from "@/lib/redis/client";
import {
  DEFAULT_APPROVER_EMAIL,
  notifyAdminsOfPendingApplicant,
} from "@/lib/security/admin-notify";
import { insertCommitteeMemberResilient } from "@/lib/security/committee-roles";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

/**
 * Handles committee access & admin-upgrade requests:
 * - New signups register into `committee_members` as `is_active: false` (`role: "member"`).
 * - Existing non-admin officers can submit `{ requestAdminUpgrade: true }`.
 * - Both trigger a single-use HMAC-signed verification email to `ADMIN_NOTIFICATION_EMAIL` (`agrawalvantika@gmail.com`).
 */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-access-request"),
    { limit: 10, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many access requests. Please wait before retrying." },
      { status: 429 }
    );
  }

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return NextResponse.json(
      { error: "Server Supabase configuration is incomplete." },
      { status: 503 }
    );
  }

  let body: Record<string, unknown> = {};
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }

  const admin = createAdminClient();
  const supabase = await createClient();
  const {
    data: { user: sessionUser },
  } = await supabase.auth.getUser();

  let applicantUserId: string;
  let applicantEmail: string;
  let applicantName: string;

  if (sessionUser) {
    applicantUserId = sessionUser.id;
    applicantEmail = sessionUser.email ?? "";
    const metaName =
      typeof sessionUser.user_metadata?.full_name === "string"
        ? sessionUser.user_metadata.full_name
        : "";
    applicantName =
      readNonEmptyString(body.fullName, 2, 120) ??
      readNonEmptyString(metaName, 2, 120) ??
      applicantEmail.split("@")[0] ??
      "Committee Applicant";
  } else {
    const candidateId =
      typeof body.userId === "string" ? body.userId.trim() : "";
    const candidateEmail =
      typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!isUuid(candidateId) || !candidateEmail) {
      return NextResponse.json(
        { error: "Authentication or valid signup userId and email required." },
        { status: 401 }
      );
    }

    const { data: userLookup, error: userErr } =
      await admin.auth.admin.getUserById(candidateId);
    if (
      userErr ||
      !userLookup.user ||
      (userLookup.user.email ?? "").toLowerCase() !== candidateEmail
    ) {
      return NextResponse.json(
        { error: "Unable to verify signup user identity." },
        { status: 403 }
      );
    }

    const createdMs = Date.parse(userLookup.user.created_at);
    if (!Number.isFinite(createdMs) || Date.now() - createdMs > 15 * 60_000) {
      return NextResponse.json(
        { error: "Please sign in first to submit an access request." },
        { status: 401 }
      );
    }

    applicantUserId = userLookup.user.id;
    applicantEmail = userLookup.user.email ?? candidateEmail;
    const metaName =
      typeof userLookup.user.user_metadata?.full_name === "string"
        ? userLookup.user.user_metadata.full_name
        : "";
    applicantName =
      readNonEmptyString(body.fullName, 2, 120) ??
      readNonEmptyString(metaName, 2, 120) ??
      applicantEmail.split("@")[0] ??
      "Committee Applicant";
  }

  const origin = new URL(request.url).origin;
  const targetAdminEmail =
    process.env.ADMIN_NOTIFICATION_EMAIL?.trim().toLowerCase() ||
    DEFAULT_APPROVER_EMAIL;

  const { data: existing } = await admin
    .from("committee_members")
    .select("user_id, full_name, role, is_active")
    .eq("user_id", applicantUserId)
    .maybeSingle();

  if (existing) {
    if (existing.is_active === true) {
      if (existing.role !== "admin" && body.requestAdminUpgrade === true) {
        const redis = getRedisClient();
        const upgradeKey = `awaaz:approval:upgrade-cooldown:${applicantUserId}`;
        const inCooldown = redis ? await redis.get(upgradeKey) : null;
        if (inCooldown) {
          return NextResponse.json({
            status: "upgrade_requested",
            emailSent: false,
            targetAdminEmail,
            message: `Admin upgrade verification was already sent recently to ${targetAdminEmail}.`,
          });
        }

        const notify = await notifyAdminsOfPendingApplicant(admin, {
          origin,
          applicantUserId,
          applicantEmail,
          applicantName: existing.full_name || applicantName,
          requestType: "admin_upgrade",
        });

        if (redis && notify.emailSent) {
          await redis.set(upgradeKey, "1", { ex: 300 });
        }

        return NextResponse.json({
          status: "upgrade_requested",
          emailSent: notify.emailSent,
          emailConfigured: notify.emailConfigured,
          targetAdminEmail: notify.targetAdminEmail,
          reason: notify.reason,
        });
      }

      return NextResponse.json({
        status: "active",
        role: existing.role,
        emailSent: false,
      });
    }

    let reminderSent = false;
    let emailConfigured = false;
    let reason: string | undefined;

    if (body.resendNotification === true) {
      const redis = getRedisClient();
      const cooldownKey = `awaaz:approval:notify-cooldown:${applicantUserId}`;
      const alreadyNotified = redis ? await redis.get(cooldownKey) : null;
      if (!alreadyNotified) {
        const notify = await notifyAdminsOfPendingApplicant(admin, {
          origin,
          applicantUserId,
          applicantEmail,
          applicantName: existing.full_name || applicantName,
          requestType: "new_signup",
        });
        reminderSent = notify.emailSent;
        emailConfigured = notify.emailConfigured;
        reason = notify.reason;
        if (redis && notify.emailSent) {
          await redis.set(cooldownKey, "1", { ex: 300 });
        }
      } else {
        emailConfigured = true;
        reason = `Verification email was already sent to ${targetAdminEmail} within the last 5 minutes.`;
      }
    }

    return NextResponse.json({
      status: "pending",
      emailSent: reminderSent,
      emailConfigured,
      targetAdminEmail,
      reason,
      message: `Your access request is awaiting confirmation by ${targetAdminEmail}.`,
    });
  }

  let initialRole: "member" | "admin" = "member";
  let initialActive = false;
  const bootstrapEmail = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  if (
    bootstrapEmail &&
    sessionUser?.email_confirmed_at &&
    applicantEmail.toLowerCase() === bootstrapEmail
  ) {
    const { count: adminCount } = await admin
      .from("committee_members")
      .select("user_id", { head: true, count: "exact" })
      .eq("role", "admin")
      .eq("is_active", true);
    if ((adminCount ?? 0) === 0) {
      initialRole = "admin";
      initialActive = true;
    }
  }

  const { role: recordedRole, error: insertError } =
    await insertCommitteeMemberResilient(admin, {
      userId: applicantUserId,
      fullName: applicantName,
      preferredRole: initialRole,
      isActive: initialActive,
    });

  if (insertError) {
    return NextResponse.json(
      { error: `Failed to record committee request: ${insertError.message}` },
      { status: 500 }
    );
  }

  await invalidateDashboardCache();

  if (initialActive) {
    return NextResponse.json(
      {
        status: "active",
        role: recordedRole,
        emailSent: false,
      },
      { status: 201 }
    );
  }

  const notifyResult = await notifyAdminsOfPendingApplicant(admin, {
    origin,
    applicantUserId,
    applicantEmail,
    applicantName,
    requestType: "new_signup",
  });

  const redis = getRedisClient();
  if (redis && notifyResult.emailSent) {
    await redis.set(`awaaz:approval:notify-cooldown:${applicantUserId}`, "1", {
      ex: 300,
    });
  }

  return NextResponse.json(
    {
      status: "pending",
      emailSent: notifyResult.emailSent,
      emailConfigured: notifyResult.emailConfigured,
      targetAdminEmail: notifyResult.targetAdminEmail,
      notifiedAdminCount: notifyResult.notifiedAdminCount,
      reason: notifyResult.reason,
    },
    { status: 201 }
  );
}
