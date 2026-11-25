import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { isUuid, isValidComplaintStatus } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

/** Updates a complaint's workflow status and records an audit log entry. */
export async function PATCH(request: Request) {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  let body: { complaintId?: unknown; status?: unknown };
  try {
    body = (await request.json()) as { complaintId?: unknown; status?: unknown };
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (!isUuid(body.complaintId) || !isValidComplaintStatus(body.status)) {
    return NextResponse.json(
      { error: "Valid complaintId and status are required." },
      { status: 400 }
    );
  }

  const complaintId = (body.complaintId as string).trim();
  const status = (body.status as string).trim();
  const admin = createAdminClient();

  const { error } = await admin
    .from("complaints")
    .update({ status, updated_at: new Date().toISOString() })
    .eq("id", complaintId);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  await appendAuditLog(admin, {
    complaintId,
    actorMemberId: auth.member.user_id,
    eventType: "STATUS_UPDATED",
    eventDetails: { newStatus: status },
  });

  return NextResponse.json({ ok: true, complaintId, status });
}
