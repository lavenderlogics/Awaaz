import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

const ALLOWED_ACTIONS = new Set([
  "share_forward",
  "complaint_decrypt",
  "evidence_decrypt",
]);
const ALLOWED_OUTCOMES = new Set(["succeeded", "failed"]);

const FORBIDDEN_FIELDS = [
  "privateKeyPem",
  "privateKey",
  "plaintextShare",
  "rawShare",
  "aesKey",
  "rawDek",
  "decryptedPayload",
] as const;

/**
 * Records every committee unlock or evidence-decryption attempt (succeeded or failed)
 * into the tamper-evident SHA-256 audit log without accepting any secrets or plaintext.
 */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-unlock-attempt"),
    { limit: 60, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many unlock audit requests." },
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

  if (FORBIDDEN_FIELDS.some((field) => body[field] !== undefined)) {
    return NextResponse.json(
      { error: "Sensitive cryptographic material is forbidden on audit routes." },
      { status: 400 }
    );
  }

  const complaintId = typeof body.complaintId === "string" ? body.complaintId.trim() : "";
  const action = typeof body.action === "string" ? body.action.trim() : "";
  const outcome = typeof body.outcome === "string" ? body.outcome.trim() : "";
  const fileId = typeof body.fileId === "string" ? body.fileId.trim() : undefined;
  const reasonCode = readNonEmptyString(body.reasonCode, 1, 64) ?? undefined;

  if (!isUuid(complaintId) || !ALLOWED_ACTIONS.has(action) || !ALLOWED_OUTCOMES.has(outcome)) {
    return NextResponse.json(
      { error: "Valid complaintId, action, and outcome are required." },
      { status: 400 }
    );
  }
  if (fileId && !isUuid(fileId)) {
    return NextResponse.json({ error: "Invalid fileId UUID." }, { status: 400 });
  }

  const admin = createAdminClient();
  const { data: exists } = await admin
    .from("complaints")
    .select("id")
    .eq("id", complaintId)
    .maybeSingle();

  if (!exists) {
    return NextResponse.json({ error: "Complaint not found." }, { status: 404 });
  }

  const eventType =
    action === "evidence_decrypt" && outcome === "succeeded"
      ? "EVIDENCE_ACCESSED"
      : outcome === "succeeded"
        ? "UNLOCK_ATTEMPT_SUCCEEDED"
        : "UNLOCK_ATTEMPT_FAILED";

  await appendAuditLog(admin, {
    complaintId,
    actorMemberId: auth.member.user_id,
    eventType,
    eventDetails: {
      action,
      outcome,
      memberRole: auth.member.role,
      ...(fileId ? { fileId } : {}),
      ...(reasonCode ? { reasonCode } : {}),
    },
  });

  return NextResponse.json({ ok: true, eventType });
}
