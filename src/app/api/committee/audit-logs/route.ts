import { NextResponse } from "next/server";
import { type AuditLogRow, verifyAuditChain } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { isUuid } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

/** Protected endpoint returning hash-chained audit logs and chain verification status. */
export async function GET(request: Request) {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  const url = new URL(request.url);
  const complaintId = url.searchParams.get("complaintId");
  if (complaintId && !isUuid(complaintId)) {
    return NextResponse.json(
      { error: "Invalid complaintId filter." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const { data: fullChainRows, error: chainError } = await admin
    .from("audit_logs")
    .select(
      "id, complaint_id, actor_member_id, event_type, event_details, previous_hash, entry_hash, created_at"
    )
    .order("id", { ascending: true })
    .limit(500);

  if (chainError) {
    return NextResponse.json({ error: chainError.message }, { status: 500 });
  }

  const ascending = (fullChainRows ?? []) as AuditLogRow[];
  const chainValid = verifyAuditChain(ascending);

  const filtered = complaintId
    ? ascending.filter((r) => r.complaint_id === complaintId)
    : ascending;

  return NextResponse.json({
    chainValid,
    logs: filtered.slice().reverse().slice(0, 100),
  });
}
