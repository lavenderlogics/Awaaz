import { NextResponse } from "next/server";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { REQUIRED_UNLOCK_APPROVALS } from "@/lib/security/crypto";
import { createAdminClient } from "@/lib/supabase/admin";

function extractForwardedRecipients(rawShare: string): string[] {
  try {
    const parsed = JSON.parse(rawShare) as Record<string, unknown>;
    if (
      parsed &&
      parsed.version === 2 &&
      parsed.scheme === "C2-FORWARDED-RSA-OAEP-256" &&
      parsed.recipients &&
      typeof parsed.recipients === "object" &&
      !Array.isArray(parsed.recipients)
    ) {
      return Object.keys(parsed.recipients as Record<string, unknown>);
    }
    return [];
  } catch {
    return [];
  }
}

/** Protected committee dashboard data feed (never returns encrypted_payload ciphertext). */
export async function GET() {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  const admin = createAdminClient();

  const [complaintsRes, approvalsRes, evidenceRes, membersRes] =
    await Promise.all([
      admin
        .from("complaints")
        .select(
          "id, category, status, encryption_algorithm, retention_until, created_at, updated_at"
        )
        .order("created_at", { ascending: false })
        .limit(100),
      admin
        .from("unlock_approvals")
        .select("complaint_id, member_id, encrypted_key_share, approved_at"),
      admin
        .from("evidence_files")
        .select("id, complaint_id, mime_type, file_size, created_at"),
      admin
        .from("committee_members")
        .select("user_id, full_name, role, public_key, is_active")
        .order("created_at", { ascending: true }),
    ]);

  if (complaintsRes.error) {
    return NextResponse.json(
      { error: complaintsRes.error.message },
      { status: 500 }
    );
  }

  const approvalsByComplaint = new Map<
    string,
    Array<{
      memberId: string;
      approvedAt: string | null;
      forwardedToIds: string[];
    }>
  >();
  for (const row of approvalsRes.data ?? []) {
    const list = approvalsByComplaint.get(row.complaint_id) ?? [];
    list.push({
      memberId: row.member_id,
      approvedAt: row.approved_at,
      forwardedToIds: extractForwardedRecipients(row.encrypted_key_share),
    });
    approvalsByComplaint.set(row.complaint_id, list);
  }

  const evidenceCountByComplaint = new Map<string, number>();
  for (const row of evidenceRes.data ?? []) {
    evidenceCountByComplaint.set(
      row.complaint_id,
      (evidenceCountByComplaint.get(row.complaint_id) ?? 0) + 1
    );
  }

  const complaints = (complaintsRes.data ?? []).map((row) => {
    const approvals = approvalsByComplaint.get(row.id) ?? [];
    const forwardedToMeCount = approvals.filter(
      (a) =>
        a.memberId !== auth.member.user_id &&
        a.forwardedToIds.includes(auth.member.user_id)
    ).length;

    return {
      id: row.id,
      category: row.category,
      status: row.status ?? "submitted",
      encryptionAlgorithm: row.encryption_algorithm ?? "AES-256-GCM",
      retentionUntil: row.retention_until,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      approvalCount: approvals.length,
      requiredApprovals: REQUIRED_UNLOCK_APPROVALS,
      approvedByMe: approvals.some((a) => a.memberId === auth.member.user_id),
      forwardedToMeCount,
      evidenceCount: evidenceCountByComplaint.get(row.id) ?? 0,
    };
  });

  const members = (membersRes.data ?? []).map((m) => ({
    userId: m.user_id,
    fullName: m.full_name,
    role: m.role,
    hasPublicKey: Boolean(m.public_key),
    isActive: m.is_active !== false,
  }));

  return NextResponse.json(
    {
      currentMember: {
        userId: auth.member.user_id,
        fullName: auth.member.full_name,
        role: auth.member.role,
        hasPublicKey: Boolean(auth.member.public_key),
        publicKeyPem: auth.member.public_key,
      },
      members,
      complaints,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
