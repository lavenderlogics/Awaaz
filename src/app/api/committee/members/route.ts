import { NextResponse } from "next/server";
import { invalidateDashboardCache } from "@/lib/redis/client";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { updateCommitteeMemberResilient } from "@/lib/security/committee-roles";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

const ALLOWED_MEMBER_ROLES = new Set([
  "admin",
  "investigator",
  "reviewer",
  "member",
]);

/** Admin-only RBAC endpoint for managing committee officer roles and active status. */
export async function PATCH(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-members-rbac"),
    { limit: 20, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many role management requests." },
      { status: 429 }
    );
  }

  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  if (auth.member.role !== "admin") {
    return NextResponse.json(
      { error: "Forbidden: Only committee admins may modify member roles." },
      { status: 403 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const targetUserId =
    typeof body.memberId === "string" ? body.memberId.trim() : "";
  if (!isUuid(targetUserId)) {
    return NextResponse.json(
      { error: "Valid memberId UUID is required." },
      { status: 400 }
    );
  }

  const updates: { role?: string; is_active?: boolean } = {};
  if (typeof body.role === "string") {
    const normalizedRole = body.role.trim().toLowerCase();
    if (!ALLOWED_MEMBER_ROLES.has(normalizedRole)) {
      return NextResponse.json(
        { error: "Role must be admin, investigator, reviewer, or member." },
        { status: 400 }
      );
    }
    if (targetUserId === auth.member.user_id && normalizedRole !== "admin") {
      return NextResponse.json(
        { error: "You cannot demote your own active admin account." },
        { status: 400 }
      );
    }
    updates.role = normalizedRole;
  }

  if (typeof body.isActive === "boolean") {
    if (targetUserId === auth.member.user_id && !body.isActive) {
      return NextResponse.json(
        { error: "You cannot deactivate your own committee session." },
        { status: 400 }
      );
    }
    updates.is_active = body.isActive;
  }

  if (Object.keys(updates).length === 0) {
    return NextResponse.json(
      { error: "Provide role or isActive update fields." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const { appliedUpdates, error } = await updateCommitteeMemberResilient(admin, {
    memberId: targetUserId,
    updates,
    allowRoleFallback: updates.is_active === true,
  });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  await invalidateDashboardCache();
  return NextResponse.json({
    ok: true,
    memberId: targetUserId,
    updates: appliedUpdates,
  });
}

/** Admin-only endpoint to reject/remove a pending (`is_active !== true`) access request. */
export async function DELETE(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-members-reject"),
    { limit: 20, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many member management requests." },
      { status: 429 }
    );
  }

  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  if (auth.member.role !== "admin") {
    return NextResponse.json(
      { error: "Forbidden: Only committee admins may reject access requests." },
      { status: 403 }
    );
  }

  const memberId = new URL(request.url).searchParams.get("memberId")?.trim() ?? "";
  if (!isUuid(memberId)) {
    return NextResponse.json(
      { error: "Valid memberId UUID query parameter is required." },
      { status: 400 }
    );
  }
  if (memberId === auth.member.user_id) {
    return NextResponse.json(
      { error: "Cannot delete your own active admin account." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const { error } = await admin
    .from("committee_members")
    .delete()
    .eq("user_id", memberId)
    .neq("is_active", true);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  await invalidateDashboardCache();
  return NextResponse.json({ ok: true, rejectedMemberId: memberId });
}
