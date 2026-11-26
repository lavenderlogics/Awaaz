import { NextResponse } from "next/server";
import { invalidateDashboardCache } from "@/lib/redis/client";
import { appendAuditLog } from "@/lib/security/audit";
import {
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
  safeEqualHex,
  sha256Hex,
  validateEncryptedComplaintEnvelope,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import {
  isUuid,
  isValidCaseIdFormat,
  readNonEmptyString,
} from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";

const FORBIDDEN_PLAINTEXT_MESSAGE_FIELDS = [
  "message",
  "text",
  "body",
  "content",
  "description",
] as const;

/**
 * Accepts ONLY browser-encrypted AES-256-GCM + 2-of-N Shamir follow-up messages
 * from a reporter holding a valid Case ID + Recovery Secret.
 */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "reporter-followup-message"),
    { limit: 15, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many follow-up messages. Please try again later." },
      { status: 429 }
    );
  }

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return NextResponse.json(
      { error: "Server Supabase credentials are incomplete." },
      { status: 503 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (FORBIDDEN_PLAINTEXT_MESSAGE_FIELDS.some((f) => body[f] !== undefined)) {
    return NextResponse.json(
      {
        error:
          "Plaintext follow-up messages are forbidden. Encrypt inside the browser first.",
      },
      { status: 400 }
    );
  }

  const rawRecovery = readNonEmptyString(body.recoverySecret, 6, 64);
  if (!isValidCaseIdFormat(body.caseCode) || !rawRecovery || !isUuid(body.messageId)) {
    return NextResponse.json(
      { error: "Valid Case ID, Recovery Secret, and messageId UUID are required." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const caseCodeHash = sha256Hex((body.caseCode as string).trim().toUpperCase());
  const { data: complaint, error } = await admin
    .from("complaints")
    .select("id, recovery_secret_hash")
    .eq("case_code_hash", caseCodeHash)
    .maybeSingle();

  if (error || !complaint) {
    return NextResponse.json(
      { error: "Invalid Case ID or Recovery Secret." },
      { status: 403 }
    );
  }

  const recoveryHash = sha256Hex(rawRecovery.toUpperCase());
  if (!safeEqualHex(recoveryHash, complaint.recovery_secret_hash)) {
    return NextResponse.json(
      { error: "Invalid Case ID or Recovery Secret." },
      { status: 403 }
    );
  }

  const { data: committeeRows } = await admin
    .from("committee_members")
    .select("user_id, public_key")
    .eq("is_active", true)
    .not("public_key", "is", null);

  const activeMemberIds = new Set(
    (committeeRows ?? [])
      .filter(
        (row): row is { user_id: string; public_key: string } =>
          typeof row.user_id === "string" &&
          typeof row.public_key === "string" &&
          isValidRsaPublicKeyPem(row.public_key)
      )
      .map((row) => row.user_id)
  );

  if (activeMemberIds.size < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json(
      {
        error: `Encrypted follow-up requires at least ${REQUIRED_UNLOCK_APPROVALS} committee keys.`,
      },
      { status: 503 }
    );
  }

  const envelopeCheck = validateEncryptedComplaintEnvelope(
    body.encryptedEnvelope,
    activeMemberIds
  );
  if (!envelopeCheck.ok) {
    return NextResponse.json({ error: envelopeCheck.error }, { status: 400 });
  }

  const messageId = (body.messageId as string).trim();
  const nowIso = new Date().toISOString();

  await Promise.all([
    appendAuditLog(admin, {
      complaintId: complaint.id,
      actorMemberId: null,
      eventType: "REPORTER_FOLLOWUP_SENT",
      eventDetails: {
        messageId,
        sentAt: nowIso,
        clientEncrypted: true,
        envelope: envelopeCheck.envelope,
      },
    }),
    invalidateDashboardCache(),
  ]);

  return NextResponse.json(
    { ok: true, messageId, sentAt: nowIso },
    { status: 201 }
  );
}
