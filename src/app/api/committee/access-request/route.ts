import { NextResponse } from "next/server";
import { getRedisClient, invalidateDashboardCache } from "@/lib/redis/client";
import { notifyAdminsOfPendingApplicant } from "@/lib/security/admin-notify";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

/**
 * Registers a newly signed-up or verified user into `committee_members` as
 * `is_active: false` (pending admin confirmation) and emails active admins.
 * Never allows self-activation or client-chosen roles.
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
    // Immediate post-signUp registration before email link confirmation:
    // verify strictly against Supabase Auth user creation timestamp and email.
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

  const { data: existing } = await admin
    .from("committee_members")
    .select("user_id, full_name, role, is_active")
    .eq("user_id", applicantUserId)
    .maybeSingle();

  if (existing) {
    if (existing.is_active === true) {
      return NextResponse.json({
        status: "active",
        role: existing.role,
        emailSent: false,
      });
    }

    // Already pending: allow throttled admin reminder email only if requested and not recently sent.
    let reminderSent = false;
    let emailConfigured = Boolean(process.env.RESEND_API_KEY?.trim());
    if (body.resendNotification === true) {
      const redis = getRedisClient();
      const cooldownKey = `awaaz:approval:notify-cooldown:${applicantUserId}`;
      const alreadyNotified = redis ? await redis.get(cooldownKey) : null;
      if (!alreadyNotified) {
        const origin = new URL(request.url).origin;
        const notify = await notifyAdminsOfPendingApplicant(admin, {
          origin,
          applicantUserId,
          applicantEmail,
          applicantName: existing.full_name || applicantName,
        });
        reminderSent = notify.emailSent;
        emailConfigured = notify.emailConfigured;
        if (redis) {
          await redis.set(cooldownKey, "1", { ex: 300 });
        }
      }
    }

    return NextResponse.json({
      status: "pending",
      emailSent: reminderSent,
      emailConfigured,
      message:
        "Your access request is pending confirmation by a committee administrator.",
    });
  }

  // Optional zero-admin bootstrap ONLY when 0 active admins exist AND BOOTSTRAP_ADMIN_EMAIL matches verified email
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

  const { error: insertError } = await admin.from("committee_members").insert({
    user_id: applicantUserId,
    full_name: applicantName,
    role: initialRole,
    is_active: initialActive,
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
        role: initialRole,
        emailSent: false,
      },
      { status: 201 }
    );
  }

  const origin = new URL(request.url).origin;
  const notifyResult = await notifyAdminsOfPendingApplicant(admin, {
    origin,
    applicantUserId,
    applicantEmail,
    applicantName,
  });

  const redis = getRedisClient();
  if (redis) {
    await redis.set(`awaaz:approval:notify-cooldown:${applicantUserId}`, "1", {
      ex: 300,
    });
  }

  return NextResponse.json(
    {
      status: "pending",
      emailSent: notifyResult.emailSent,
      emailConfigured: notifyResult.emailConfigured,
      notifiedAdminCount: notifyResult.notifiedAdminCount,
      reason: notifyResult.reason,
    },
    { status: 201 }
  );
}
