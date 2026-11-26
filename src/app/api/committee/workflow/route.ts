import { NextResponse } from "next/server";
import { invalidateDashboardCache } from "@/lib/redis/client";
import { appendAuditLog } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

const ALLOWED_PRIORITIES = new Set(["standard", "elevated", "immediate"]);

/**
 * Protected committee triage workflow actions (`set_priority`, `assign_case`, `add_followup_note`).
 * Stores hash-chained audit records and invalidates dashboard cache.
 */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-workflow"),
    { limit: 40, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many workflow updates. Please slow down." },
      { status: 429 }
    );
  }

  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const action = typeof body.action === "string" ? body.action.trim() : "";
  const complaintId =
    typeof body.complaintId === "string" ? body.complaintId.trim() : "";

  if (!isUuid(complaintId)) {
    return NextResponse.json(
      { error: "Valid complaintId UUID is required." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const { data: complaint } = await admin
    .from("complaints")
    .select("id")
    .eq("id", complaintId)
    .maybeSingle();

  if (!complaint) {
    return NextResponse.json({ error: "Complaint not found." }, { status: 404 });
  }

  if (action === "set_priority") {
    const priority =
      typeof body.priority === "string" ? body.priority.trim() : "";
    if (!ALLOWED_PRIORITIES.has(priority)) {
      return NextResponse.json(
        { error: "Priority must be standard, elevated, or immediate." },
        { status: 400 }
      );
    }

    await Promise.all([
      appendAuditLog(admin, {
        complaintId,
        actorMemberId: auth.member.user_id,
        eventType: "PRIORITY_UPDATED",
        eventDetails: { priority, memberRole: auth.member.role },
      }),
      invalidateDashboardCache(),
    ]);

    return NextResponse.json({ ok: true, complaintId, priority });
  }

  if (action === "assign_case") {
    const rawAssignee = body.assigneeMemberId;
    const assigneeMemberId =
      rawAssignee === null || rawAssignee === ""
        ? null
        : typeof rawAssignee === "string"
          ? rawAssignee.trim()
          : undefined;

    if (
      assigneeMemberId === undefined ||
      (assigneeMemberId !== null && !isUuid(assigneeMemberId))
    ) {
      return NextResponse.json(
        { error: "assigneeMemberId must be a valid member UUID or null." },
        { status: 400 }
      );
    }

    // RBAC: Non-admin officers may self-assign or claim unassigned cases,
    // while admins can assign or reassign across any active officer.
    if (
      auth.member.role !== "admin" &&
      assigneeMemberId !== null &&
      assigneeMemberId !== auth.member.user_id
    ) {
      return NextResponse.json(
        { error: "Only committee admins may assign cases to other officers." },
        { status: 403 }
      );
    }

    if (assigneeMemberId) {
      const { data: targetMember } = await admin
        .from("committee_members")
        .select("user_id, is_active")
        .eq("user_id", assigneeMemberId)
        .maybeSingle();
      if (!targetMember || targetMember.is_active !== true) {
        return NextResponse.json(
          { error: "Selected assignee is not an active committee member." },
          { status: 400 }
        );
      }
    }

    await Promise.all([
      appendAuditLog(admin, {
        complaintId,
        actorMemberId: auth.member.user_id,
        eventType: "CASE_ASSIGNED",
        eventDetails: {
          assigneeMemberId,
          memberRole: auth.member.role,
        },
      }),
      invalidateDashboardCache(),
    ]);

    return NextResponse.json({ ok: true, complaintId, assigneeMemberId });
  }

  if (action === "add_followup_note") {
    const note = readNonEmptyString(body.note, 3, 1000);
    if (!note) {
      return NextResponse.json(
        { error: "Follow-up note must be between 3 and 1000 characters." },
        { status: 400 }
      );
    }

    await Promise.all([
      appendAuditLog(admin, {
        complaintId,
        actorMemberId: auth.member.user_id,
        eventType: "COMMITTEE_FOLLOWUP_NOTE",
        eventDetails: {
          note,
          memberRole: auth.member.role,
        },
      }),
      invalidateDashboardCache(),
    ]);

    return NextResponse.json({ ok: true, complaintId, note });
  }

  return NextResponse.json(
    { error: "Unsupported workflow action." },
    { status: 400 }
  );
}
