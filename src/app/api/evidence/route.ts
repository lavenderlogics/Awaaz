import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import {
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
  safeEqualHex,
  sha256Hex,
  validateEncryptedEvidenceBlob,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  isUuid,
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

/**
 * Follow-up browser-encrypted AWZ1 evidence upload authorized by Case ID + Recovery Secret.
 * Never receives or encrypts raw unencrypted evidence bytes on the server.
 */
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
  const rawFileId = formData.get("fileId");
  const rawMimeType = formData.get("mimeType");
  const file = formData.get("file");

  if (!isValidCaseIdFormat(rawCaseCode) || !rawRecoverySecret) {
    return NextResponse.json(
      { error: "Valid Case ID and Recovery Secret are required." },
      { status: 400 }
    );
  }

  if (
    !isUuid(rawFileId) ||
    typeof rawMimeType !== "string" ||
    !ALLOWED_EVIDENCE_MIME_TYPES.has(rawMimeType)
  ) {
    return NextResponse.json(
      { error: "Valid fileId UUID and allowed mimeType are required." },
      { status: 400 }
    );
  }

  if (!(file instanceof File) || file.size === 0) {
    return NextResponse.json(
      { error: "Please attach a non-empty encrypted evidence blob." },
      { status: 400 }
    );
  }

  if (file.size > MAX_EVIDENCE_BYTES + 65536) {
    return NextResponse.json(
      { error: "Encrypted evidence blob exceeds the 5 MB limit." },
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
        error: `Encrypted evidence requires at least ${REQUIRED_UNLOCK_APPROVALS} committee members with public keys.`,
      },
      { status: 503 }
    );
  }

  const fileId = (rawFileId as string).trim();
  const encryptedBytes = Buffer.from(await file.arrayBuffer());
  const blobCheck = validateEncryptedEvidenceBlob(
    encryptedBytes,
    complaint.id,
    fileId,
    activeMemberIds
  );

  if (!blobCheck.ok) {
    return NextResponse.json({ error: blobCheck.error }, { status: 400 });
  }

  const storagePath = `complaints/${complaint.id}/${fileId}.enc`;
  const nowIso = new Date().toISOString();

  const { error: uploadError } = await admin.storage
    .from(EVIDENCE_BUCKET_NAME)
    .upload(storagePath, encryptedBytes, {
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
    mime_type: rawMimeType,
    file_size: encryptedBytes.length,
    file_hash: blobCheck.ciphertextHash,
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
      mimeType: rawMimeType,
      encryptedSize: encryptedBytes.length,
      clientEncrypted: true,
    },
  });

  return NextResponse.json(
    {
      evidenceId: fileId,
      complaintId: complaint.id,
      fileHash: blobCheck.ciphertextHash,
    },
    { status: 201 }
  );
}
