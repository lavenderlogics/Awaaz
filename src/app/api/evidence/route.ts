import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import {
  type CommitteeRecipientKey,
  encryptEvidenceBuffer,
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
  safeEqualHex,
  sha256Hex,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  isValidCaseIdFormat,
  MAX_EVIDENCE_BYTES,
  readNonEmptyString,
} from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { EVIDENCE_BUCKET_NAME } from "@/lib/supabase/health";

/** Follow-up encrypted evidence upload authorized by Case ID + Recovery Secret. */
export async function POST(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "upload-evidence"),
    { limit: 10, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many evidence upload requests. Please try again later." },
      { status: 429 }
    );
  }

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return NextResponse.json(
      { error: "Server Supabase credentials are incomplete." },
      { status: 503 }
    );
  }

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return NextResponse.json(
      { error: "Expected multipart/form-data payload." },
      { status: 400 }
    );
  }

  const rawCaseCode = formData.get("caseCode");
  const rawRecoverySecret = readNonEmptyString(
    formData.get("recoverySecret"),
    6,
    64
  );
  const file = formData.get("file");

  if (!isValidCaseIdFormat(rawCaseCode) || !rawRecoverySecret) {
    return NextResponse.json(
      { error: "Valid Case ID and Recovery Secret are required." },
      { status: 400 }
    );
  }

  if (!(file instanceof File) || file.size === 0) {
    return NextResponse.json(
      { error: "Please attach a non-empty evidence file." },
      { status: 400 }
    );
  }

  if (file.size > MAX_EVIDENCE_BYTES) {
    return NextResponse.json(
      { error: "Evidence file exceeds the 5 MB limit." },
      { status: 400 }
    );
  }

  if (!ALLOWED_EVIDENCE_MIME_TYPES.has(file.type)) {
    return NextResponse.json(
      {
        error: `Unsupported file type (${file.type || "unknown"}). Allowed: PNG, JPEG, WEBP, PDF, TXT.`,
      },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const caseCodeHash = sha256Hex((rawCaseCode as string).trim().toUpperCase());

  const { data: complaint, error: complaintError } = await admin
    .from("complaints")
    .select("id, recovery_secret_hash")
    .eq("case_code_hash", caseCodeHash)
    .maybeSingle();

  if (complaintError || !complaint) {
    return NextResponse.json(
      { error: "Invalid Case ID or Recovery Secret." },
      { status: 403 }
    );
  }

  const recoveryHash = sha256Hex(rawRecoverySecret.toUpperCase());
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

  const recipients: CommitteeRecipientKey[] = (committeeRows ?? [])
    .filter(
      (row): row is { user_id: string; public_key: string } =>
        typeof row.user_id === "string" &&
        typeof row.public_key === "string" &&
        isValidRsaPublicKeyPem(row.public_key)
    )
    .map((row) => ({ memberId: row.user_id, publicKeyPem: row.public_key }));

  if (recipients.length < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json(
      {
        error: `Encrypted evidence requires at least ${REQUIRED_UNLOCK_APPROVALS} committee members with public keys.`,
      },
      { status: 503 }
    );
  }

  const fileId = crypto.randomUUID();
  const rawBuffer = Buffer.from(await file.arrayBuffer());
  const { encryptedBlob, ciphertextHash } = encryptEvidenceBuffer(
    rawBuffer,
    complaint.id,
    fileId,
    recipients
  );
  const storagePath = `complaints/${complaint.id}/${fileId}.enc`;
  const nowIso = new Date().toISOString();

  const { error: uploadError } = await admin.storage
    .from(EVIDENCE_BUCKET_NAME)
    .upload(storagePath, encryptedBlob, {
      contentType: "application/octet-stream",
      upsert: false,
    });

  if (uploadError) {
    return NextResponse.json(
      { error: `Storage upload failed: ${uploadError.message}` },
      { status: 500 }
    );
  }

  const { error: insertError } = await admin.from("evidence_files").insert({
    id: fileId,
    complaint_id: complaint.id,
    storage_path: storagePath,
    mime_type: file.type,
    file_size: encryptedBlob.length,
    file_hash: ciphertextHash,
    created_at: nowIso,
  });

  if (insertError) {
    return NextResponse.json(
      { error: `Metadata insert failed: ${insertError.message}` },
      { status: 500 }
    );
  }

  await appendAuditLog(admin, {
    complaintId: complaint.id,
    actorMemberId: null,
    eventType: "EVIDENCE_UPLOADED",
    eventDetails: {
      evidenceFileId: fileId,
      mimeType: file.type,
      encryptedSize: encryptedBlob.length,
    },
  });

  return NextResponse.json(
    {
      evidenceId: fileId,
      complaintId: complaint.id,
      fileHash: ciphertextHash,
    },
    { status: 201 }
  );
}
