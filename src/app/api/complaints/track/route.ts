import { NextResponse } from "next/server";
import { PLANNED_CASE_STAGES } from "@/lib/constants";
import { safeEqualHex, sha256Hex } from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isValidCaseIdFormat, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";

interface AuditRow {
  id: number;
  event_type: string;
  event_details: Record<string, unknown> | null;
  entry_hash: string;
  created_at: string;
}

function buildPublicTimeline(rows: AuditRow[]) {
  const stageLabels = new Map<string, string>(
    PLANNED_CASE_STAGES.map((stage) => [stage.id, stage.label])
  );

  const timeline: Array<{
    id: number;
    eventType: string;
    title: string;
    detail: string;
    createdAt: string;
    digest?: string;
  }> = [];

  const deletionReceipts: Array<{
    receiptId: string;
    shreddedAt: string;
    deletedFileCount: number;
    receiptDigest: string;
  }> = [];

  for (const row of rows) {
    const details = row.event_details ?? {};
    switch (row.event_type) {
      case "COMPLAINT_SUBMITTED":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Encrypted Complaint Submitted",
          detail:
            "Browser-encrypted payload received and queued for 2-of-N committee review.",
          createdAt: row.created_at,
        });
        break;
      case "STATUS_UPDATED": {
        const rawStatus =
          typeof details.newStatus === "string" ? details.newStatus : "updated";
        const label = stageLabels.get(rawStatus) ?? rawStatus;
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: `Status Updated to ${label}`,
          detail: "Updated by an authorized campus committee officer.",
          createdAt: row.created_at,
        });
        break;
      }
      case "EVIDENCE_UPLOADED":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Encrypted Evidence Attached",
          detail:
            "Additional AWZ1 browser-encrypted evidence file verified and stored.",
          createdAt: row.created_at,
        });
        break;
      case "UNLOCK_APPROVED":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Committee Co-Approval Recorded",
          detail:
            "An authorized officer forwarded an encrypted key share for local decryption.",
          createdAt: row.created_at,
        });
        break;
      case "PRIORITY_UPDATED":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Review Priority Updated",
          detail: `Queue priority set to ${typeof details.priority === "string" ? details.priority : "updated"}.`,
          createdAt: row.created_at,
        });
        break;
      case "CASE_ASSIGNED":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Case Assigned for Investigation",
          detail: "An active committee officer was assigned to review this report.",
          createdAt: row.created_at,
        });
        break;
      case "EVIDENCE_AUTO_SHREDDED": {
        const receiptId =
          typeof details.receiptId === "string" ? details.receiptId : String(row.id);
        const shreddedAt =
          typeof details.shreddedAt === "string"
            ? details.shreddedAt
            : row.created_at;
        const deletedFileCount = Number(details.deletedFileCount ?? 0);
        const receiptDigest =
          typeof details.receiptDigest === "string"
            ? details.receiptDigest
            : row.entry_hash;

        deletionReceipts.push({
          receiptId,
          shreddedAt,
          deletedFileCount,
          receiptDigest,
        });

        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Expired Evidence Auto-Shredded",
          detail: `${deletedFileCount} encrypted file(s) permanently purged after retention expiry.`,
          createdAt: row.created_at,
          digest: receiptDigest,
        });
        break;
      }
      case "REPORTER_FOLLOWUP_SENT":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Encrypted Reporter Follow-Up Sent",
          detail: "Follow-up message encrypted in browser for committee review.",
          createdAt: row.created_at,
        });
        break;
      case "COMMITTEE_FOLLOWUP_NOTE":
        timeline.push({
          id: row.id,
          eventType: row.event_type,
          title: "Committee Follow-Up Posted",
          detail: "Committee posted a status note (requires Recovery Secret to view).",
          createdAt: row.created_at,
        });
        break;
      default:
        break;
    }
  }

  return { timeline, deletionReceipts };
}

/** Anonymous Case ID status lookup returning non-sensitive timeline & recovery-gated follow-ups. */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "track-complaint"),
    { limit: 20, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many tracking requests. Please try again later." },
      { status: 429 }
    );
  }

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return NextResponse.json(
      {
        error:
          "Server Supabase credentials are incomplete. Configure SUPABASE_SERVICE_ROLE_KEY on the server.",
      },
      { status: 503 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (!isValidCaseIdFormat(body.caseCode)) {
    return NextResponse.json(
      { error: "Please enter a valid Case ID (e.g. AWZ-XXXX-XXXX-XXXX)." },
      { status: 400 }
    );
  }

  const normalizedCaseCode = (body.caseCode as string).trim().toUpperCase();
  const caseCodeHash = sha256Hex(normalizedCaseCode);
  const recoverySecret = readNonEmptyString(body.recoverySecret, 4, 64);

  const admin = createAdminClient();
  const { data: complaint, error } = await admin
    .from("complaints")
    .select(
      "id, category, status, encryption_algorithm, recovery_secret_hash, retention_until, created_at, updated_at"
    )
    .eq("case_code_hash", caseCodeHash)
    .maybeSingle();

  if (error) {
    return NextResponse.json(
      { error: "Unable to look up complaint status." },
      { status: 500 }
    );
  }

  if (!complaint) {
    return NextResponse.json(
      { found: false, error: "No complaint matches that Case ID." },
      { status: 404 }
    );
  }

  const [evidenceCountRes, auditRes] = await Promise.all([
    admin
      .from("evidence_files")
      .select("id", { head: true, count: "exact" })
      .eq("complaint_id", complaint.id),
    admin
      .from("audit_logs")
      .select("id, event_type, event_details, entry_hash, created_at")
      .eq("complaint_id", complaint.id)
      .order("id", { ascending: true })
      .limit(100),
  ]);

  let recoveryVerified: boolean | null = null;
  if (recoverySecret) {
    const submittedRecoveryHash = sha256Hex(recoverySecret.toUpperCase());
    recoveryVerified = safeEqualHex(
      submittedRecoveryHash,
      complaint.recovery_secret_hash
    );
  }

  const auditRows = (auditRes.data ?? []) as AuditRow[];
  const { timeline, deletionReceipts } = buildPublicTimeline(auditRows);

  const followUpMessages =
    recoveryVerified === true
      ? auditRows
          .filter(
            (r) =>
              r.event_type === "COMMITTEE_FOLLOWUP_NOTE" ||
              r.event_type === "REPORTER_FOLLOWUP_SENT"
          )
          .map((r) => {
            const d = r.event_details ?? {};
            if (r.event_type === "COMMITTEE_FOLLOWUP_NOTE") {
              return {
                id: r.id,
                sender: "committee" as const,
                note: typeof d.note === "string" ? d.note : "",
                createdAt: r.created_at,
              };
            }
            return {
              id: r.id,
              sender: "reporter" as const,
              note:
                "Encrypted follow-up message sent (AES-256-GCM ciphertext stored for committee decryption).",
              createdAt: r.created_at,
            };
          })
      : [];

  return NextResponse.json({
    found: true,
    complaintId: recoveryVerified === true ? complaint.id : undefined,
    caseCode: normalizedCaseCode,
    category: complaint.category,
    status: complaint.status ?? "submitted",
    encryptionAlgorithm: complaint.encryption_algorithm,
    createdAt: complaint.created_at,
    updatedAt: complaint.updated_at,
    retentionUntil: complaint.retention_until,
    evidenceCount: evidenceCountRes.count ?? 0,
    recoveryVerified,
    timeline,
    deletionReceipts,
    followUpMessages,
  });
}
