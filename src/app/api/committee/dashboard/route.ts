import { NextResponse } from "next/server";
import {
  DASHBOARD_CACHE_KEY,
  getCachedJson,
  setCachedJson,
} from "@/lib/redis/client";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { REQUIRED_UNLOCK_APPROVALS } from "@/lib/security/crypto";
import { createAdminClient } from "@/lib/supabase/admin";

interface CachedDashboardSnapshot {
  complaintsRows: Array<{
    id: string;
    category: string;
    status: string | null;
    encryption_algorithm: string | null;
    retention_until: string | null;
    created_at: string | null;
    updated_at: string | null;
  }>;
  approvalRows: Array<{
    complaintId: string;
    memberId: string;
    approvedAt: string | null;
    forwardedToIds: string[];
  }>;
  evidenceRows: Array<{ complaint_id: string }>;
  membersRows: Array<{
    user_id: string;
    full_name: string;
    role: string;
    hasPublicKey: boolean;
    is_active: boolean | null;
  }>;
  workflowByComplaint: Record<
    string,
    {
      priority: string;
      assignedMemberId: string | null;
      followUpCount: number;
      shreddedCount: number;
    }
  >;
}

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

  let snapshot = await getCachedJson<CachedDashboardSnapshot>(DASHBOARD_CACHE_KEY);
  let cacheStatus: "HIT" | "MISS" = "HIT";

  if (!snapshot) {
    cacheStatus = "MISS";
    const admin = createAdminClient();

    const [complaintsRes, approvalsRes, evidenceRes, membersRes, workflowRes] =
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
        admin
          .from("audit_logs")
          .select("id, complaint_id, event_type, event_details")
          .in("event_type", [
            "PRIORITY_UPDATED",
            "CASE_ASSIGNED",
            "REPORTER_FOLLOWUP_SENT",
            "COMMITTEE_FOLLOWUP_NOTE",
            "EVIDENCE_AUTO_SHREDDED",
          ])
          .order("id", { ascending: true })
          .limit(500),
      ]);

    if (complaintsRes.error) {
      return NextResponse.json(
        { error: complaintsRes.error.message },
        { status: 500 }
      );
    }

    const workflowByComplaint: CachedDashboardSnapshot["workflowByComplaint"] = {};
    for (const row of workflowRes.data ?? []) {
      const current =
        workflowByComplaint[row.complaint_id] ?? {
          priority: "standard",
          assignedMemberId: null,
          followUpCount: 0,
          shreddedCount: 0,
        };
      const details = (row.event_details ?? {}) as Record<string, unknown>;
      if (row.event_type === "PRIORITY_UPDATED" && typeof details.priority === "string") {
        current.priority = details.priority;
      } else if (row.event_type === "CASE_ASSIGNED") {
        current.assignedMemberId =
          typeof details.assigneeMemberId === "string"
            ? details.assigneeMemberId
            : null;
      } else if (
        row.event_type === "REPORTER_FOLLOWUP_SENT" ||
        row.event_type === "COMMITTEE_FOLLOWUP_NOTE"
      ) {
        current.followUpCount += 1;
      } else if (row.event_type === "EVIDENCE_AUTO_SHREDDED") {
        current.shreddedCount += Number(details.deletedFileCount ?? 0);
      }
      workflowByComplaint[row.complaint_id] = current;
    }

    snapshot = {
      complaintsRows: complaintsRes.data ?? [],
      approvalRows: (approvalsRes.data ?? []).map((row) => ({
        complaintId: row.complaint_id,
        memberId: row.member_id,
        approvedAt: row.approved_at,
        forwardedToIds: extractForwardedRecipients(row.encrypted_key_share),
      })),
      evidenceRows: evidenceRes.data ?? [],
      membersRows: (membersRes.data ?? []).map((m) => ({
        user_id: m.user_id,
        full_name: m.full_name,
        role: m.role,
        hasPublicKey: Boolean(m.public_key),
        is_active: m.is_active,
      })),
      workflowByComplaint,
    };

    await setCachedJson(DASHBOARD_CACHE_KEY, snapshot, 45);
  }

  const approvalsByComplaint = new Map<
    string,
    Array<{
      memberId: string;
      approvedAt: string | null;
      forwardedToIds: string[];
    }>
  >();
  for (const row of snapshot.approvalRows) {
    const list = approvalsByComplaint.get(row.complaintId) ?? [];
    list.push({
      memberId: row.memberId,
      approvedAt: row.approvedAt,
      forwardedToIds: row.forwardedToIds,
    });
    approvalsByComplaint.set(row.complaintId, list);
  }

  const evidenceCountByComplaint = new Map<string, number>();
  for (const row of snapshot.evidenceRows) {
    evidenceCountByComplaint.set(
      row.complaint_id,
      (evidenceCountByComplaint.get(row.complaint_id) ?? 0) + 1
    );
  }

  const complaints = snapshot.complaintsRows.map((row) => {
    const approvals = approvalsByComplaint.get(row.id) ?? [];
    const forwardedToMeCount = approvals.filter(
      (a) =>
        a.memberId !== auth.member.user_id &&
        a.forwardedToIds.includes(auth.member.user_id)
    ).length;

    const wf = snapshot.workflowByComplaint?.[row.id];

    return {
      id: row.id,
      category: row.category,
      status: row.status ?? "submitted",
      priority: wf?.priority ?? "standard",
      assignedMemberId: wf?.assignedMemberId ?? null,
      followUpCount: wf?.followUpCount ?? 0,
      shreddedCount: wf?.shreddedCount ?? 0,
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

  const members = snapshot.membersRows.map((m) => ({
    userId: m.user_id,
    fullName: m.full_name,
    role: m.role,
    hasPublicKey: m.hasPublicKey,
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
    {
      headers: {
        "Cache-Control": "no-store",
        "X-Dashboard-Cache": cacheStatus,
      },
    }
  );
}
