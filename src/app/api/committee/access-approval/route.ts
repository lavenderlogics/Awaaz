import { NextResponse } from "next/server";
import { invalidateDashboardCache } from "@/lib/redis/client";
import {
  consumeAdminApprovalToken,
  inspectAdminApprovalToken,
} from "@/lib/security/approval-tokens";
import { upsertApprovedCommitteeMemberResilient } from "@/lib/security/committee-roles";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { createAdminClient } from "@/lib/supabase/admin";

const NO_STORE = { "Cache-Control": "no-store" } as const;

/** Inspects a signed admin email approval token without consuming it. */
export async function GET(request: Request) {
  const token = new URL(request.url).searchParams.get("token")?.trim() ?? "";
  if (!token) {
    return NextResponse.json(
      { valid: false, error: "Approval token is required." },
      { status: 400, headers: NO_STORE }
    );
  }

  const payload = await inspectAdminApprovalToken(token);
  if (!payload) {
    return NextResponse.json(
      {
        valid: false,
        error: "This approval link is invalid, expired, or has already been used.",
      },
      { status: 400, headers: NO_STORE }
    );
  }

  return NextResponse.json(
    {
      valid: true,
      applicantName: payload.applicantName,
      applicantEmail: payload.applicantEmail,
      applicantUserId: payload.applicantUserId,
      action: payload.action,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    },
    { headers: NO_STORE }
  );
}

/** Atomically consumes the single-use approval token and applies the admin's decision. */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-email-approval"),
    { limit: 20, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many approval submissions. Please wait." },
      { status: 429, headers: NO_STORE }
    );
  }

  let body: { token?: unknown };
  try {
    body = (await request.json()) as { token?: unknown };
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400, headers: NO_STORE }
    );
  }

  const token = typeof body.token === "string" ? body.token.trim() : "";
  if (!token) {
    return NextResponse.json(
      { error: "Approval token is required." },
      { status: 400, headers: NO_STORE }
    );
  }

  const payload = await consumeAdminApprovalToken(token);
  if (!payload) {
    return NextResponse.json(
      {
        error:
          "This approval link is invalid, expired, or was already consumed.",
      },
      { status: 400, headers: NO_STORE }
    );
  }

  const admin = createAdminClient();

  // Verify approving admin is still an active admin in committee_members
  const { data: adminMember } = await admin
    .from("committee_members")
    .select("user_id, role, is_active")
    .eq("user_id", payload.adminMemberId)
    .maybeSingle();

  if (
    !adminMember ||
    adminMember.is_active !== true ||
    adminMember.role !== "admin"
  ) {
    return NextResponse.json(
      { error: "Approving administrator account is no longer active." },
      { status: 403, headers: NO_STORE }
    );
  }

  if (payload.action === "reject") {
    // Only delete unapproved pending applicants; never delete already-active officers
    // if rejecting an admin-upgrade request.
    await admin
      .from("committee_members")
      .delete()
      .eq("user_id", payload.applicantUserId)
      .neq("is_active", true);

    await invalidateDashboardCache();
    return NextResponse.json(
      {
        ok: true,
        decision: "rejected",
        applicantName: payload.applicantName,
        applicantEmail: payload.applicantEmail,
      },
      { headers: NO_STORE }
    );
  }

  const assignedRole = payload.action === "approve_admin" ? "admin" : "member";
  const { role: savedRole, error } =
    await upsertApprovedCommitteeMemberResilient(admin, {
      userId: payload.applicantUserId,
      fullName: payload.applicantName,
      preferredRole: assignedRole,
    });

  if (error) {
    return NextResponse.json(
      { error: error.message },
      { status: 500, headers: NO_STORE }
    );
  }

  await invalidateDashboardCache();
  return NextResponse.json(
    {
      ok: true,
      decision: assignedRole === "admin" ? "approved_admin" : "approved_member",
      role: savedRole,
      applicantName: payload.applicantName,
      applicantEmail: payload.applicantEmail,
    },
    { headers: NO_STORE }
  );
}
