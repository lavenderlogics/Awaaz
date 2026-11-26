import { NextResponse } from "next/server";
import { mapUiCategoryToDbCategory } from "@/lib/constants";
import {
  enqueueBackgroundJob,
  invalidateDashboardCache,
  scheduleAutoShredJob,
} from "@/lib/redis/client";
import { appendAuditLog } from "@/lib/security/audit";
import {
  ENCRYPTION_ALGORITHM,
  generateTrackingCredentials,
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
  validateEncryptedComplaintEnvelope,
  validateEncryptedEvidenceBlob,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  isUuid,
  isValidCategory,
  MAX_EVIDENCE_BYTES,
  MAX_EVIDENCE_FILES,
  parseRetentionDays,
} from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { EVIDENCE_BUCKET_NAME } from "@/lib/supabase/health";

const FORBIDDEN_PLAINTEXT_FIELDS = [
  "description",
  "location",
  "additionalContext",
  "incidentDate",
  "urgency",
  "aesKey",
  "rawKey",
  "privateKey",
] as const;

interface EvidenceMetadataInput {
  fileId: string;
  mimeType: string;
}

interface ParsedEncryptedSubmission {
  complaintId: unknown;
  category: unknown;
  retentionDays: unknown;
  encryptedPayload: unknown;
  evidenceBlobs: File[];
  evidenceMeta: unknown;
  forbiddenFieldsPresent: string[];
}

async function parseSubmission(
  request: Request
): Promise<ParsedEncryptedSubmission> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const forbiddenFieldsPresent = FORBIDDEN_PLAINTEXT_FIELDS.filter((field) =>
      formData.has(field)
    );
    const rawPayload = formData.get("encryptedPayload");
    const rawMeta = formData.get("evidenceMeta");
    const evidenceBlobs = formData
      .getAll("evidence")
      .filter((entry): entry is File => entry instanceof File && entry.size > 0);

    let parsedPayload: unknown = rawPayload;
    if (typeof rawPayload === "string") {
      try {
        parsedPayload = JSON.parse(rawPayload);
      } catch {
        parsedPayload = null;
      }
    }

    let parsedMeta: unknown = [];
    if (typeof rawMeta === "string" && rawMeta.trim()) {
      try {
        parsedMeta = JSON.parse(rawMeta);
      } catch {
        parsedMeta = null;
      }
    }

    return {
      complaintId: formData.get("complaintId"),
      category: formData.get("category"),
      retentionDays: formData.get("retentionDays"),
      encryptedPayload: parsedPayload,
      evidenceBlobs,
      evidenceMeta: parsedMeta,
      forbiddenFieldsPresent,
    };
  }

  const body = (await request.json()) as Record<string, unknown>;
  const forbiddenFieldsPresent = FORBIDDEN_PLAINTEXT_FIELDS.filter(
    (field) => body[field] !== undefined
  );

  return {
    complaintId: body.complaintId,
    category: body.category,
    retentionDays: body.retentionDays,
    encryptedPayload: body.encryptedPayload,
    evidenceBlobs: [],
    evidenceMeta: [],
    forbiddenFieldsPresent,
  };
}

/**
 * Anonymous encrypted complaint intake (C1).
 * Accepts ONLY browser-encrypted AES-256-GCM envelopes and encrypted AWZ1 evidence blobs.
 * Never receives plaintext descriptions, raw evidence files, or AES keys.
 */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "submit-complaint"),
    { limit: 5, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      {
        error:
          "Too many submissions from this network. Please wait before trying again.",
      },
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

  let parsed: ParsedEncryptedSubmission;
  try {
    parsed = await parseSubmission(request);
  } catch {
    return NextResponse.json(
      { error: "Invalid request payload." },
      { status: 400 }
    );
  }

  if (parsed.forbiddenFieldsPresent.length > 0) {
    return NextResponse.json(
      {
        error:
          "Plaintext complaint fields and encryption keys are rejected. Encrypt everything in the browser before submitting.",
      },
      { status: 400 }
    );
  }

  if (!isUuid(parsed.complaintId)) {
    return NextResponse.json(
      { error: "Valid complaintId UUID is required for AAD verification." },
      { status: 400 }
    );
  }
  const complaintId = (parsed.complaintId as string).trim();

  const rawCategory =
    typeof parsed.category === "string" ? parsed.category.trim() : "";
  const isDbCategory =
    rawCategory === "ragging" || rawCategory === "harassment";
  if (!isDbCategory && !isValidCategory(rawCategory)) {
    return NextResponse.json(
      { error: "Please select a valid incident category." },
      { status: 400 }
    );
  }
  const dbCategory = isDbCategory
    ? (rawCategory as "ragging" | "harassment")
    : mapUiCategoryToDbCategory(rawCategory);

  if (parsed.evidenceBlobs.length > MAX_EVIDENCE_FILES) {
    return NextResponse.json(
      {
        error: `Maximum ${MAX_EVIDENCE_FILES} encrypted evidence files allowed per submission.`,
      },
      { status: 400 }
    );
  }

  if (
    !Array.isArray(parsed.evidenceMeta) ||
    parsed.evidenceMeta.length !== parsed.evidenceBlobs.length
  ) {
    return NextResponse.json(
      { error: "Encrypted evidence metadata count does not match uploaded blobs." },
      { status: 400 }
    );
  }

  const evidenceMetaList: EvidenceMetadataInput[] = [];
  for (const item of parsed.evidenceMeta) {
    const record = item as Record<string, unknown>;
    if (
      !record ||
      !isUuid(record.fileId) ||
      typeof record.mimeType !== "string" ||
      !ALLOWED_EVIDENCE_MIME_TYPES.has(record.mimeType)
    ) {
      return NextResponse.json(
        {
          error:
            "Invalid evidence metadata. Allowed MIME types: PNG, JPEG, WEBP, PDF, TXT.",
        },
        { status: 400 }
      );
    }
    evidenceMetaList.push({
      fileId: (record.fileId as string).trim(),
      mimeType: record.mimeType,
    });
  }

  const admin = createAdminClient();
  const { data: committeeRows, error: committeeError } = await admin
    .from("committee_members")
    .select("user_id, public_key")
    .eq("is_active", true)
    .not("public_key", "is", null);

  if (committeeError) {
    return NextResponse.json(
      { error: "Failed to load active committee members." },
      { status: 500 }
    );
  }

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
        error: `Encrypted intake requires at least ${REQUIRED_UNLOCK_APPROVALS} active committee members with registered RSA public keys.`,
      },
      { status: 503 }
    );
  }

  const envelopeCheck = validateEncryptedComplaintEnvelope(
    parsed.encryptedPayload,
    activeMemberIds
  );
  if (!envelopeCheck.ok) {
    return NextResponse.json({ error: envelopeCheck.error }, { status: 400 });
  }

  const preparedEvidence: Array<{
    fileId: string;
    mimeType: string;
    encryptedBytes: Buffer;
    ciphertextHash: string;
  }> = [];

  for (let i = 0; i < parsed.evidenceBlobs.length; i++) {
    const blobFile = parsed.evidenceBlobs[i];
    const meta = evidenceMetaList[i];
    if (blobFile.size > MAX_EVIDENCE_BYTES + 65536) {
      return NextResponse.json(
        { error: "Encrypted evidence blob exceeds maximum allowed size." },
        { status: 400 }
      );
    }

    const encryptedBytes = Buffer.from(await blobFile.arrayBuffer());
    const blobCheck = validateEncryptedEvidenceBlob(
      encryptedBytes,
      complaintId,
      meta.fileId,
      activeMemberIds
    );
    if (!blobCheck.ok) {
      return NextResponse.json({ error: blobCheck.error }, { status: 400 });
    }

    preparedEvidence.push({
      fileId: meta.fileId,
      mimeType: meta.mimeType,
      encryptedBytes,
      ciphertextHash: blobCheck.ciphertextHash,
    });
  }

  const tracking = generateTrackingCredentials();
  const retentionDays = parseRetentionDays(parsed.retentionDays, 90);
  const nowIso = new Date().toISOString();
  const retentionUntil = new Date(
    Date.now() + retentionDays * 24 * 60 * 60 * 1000
  ).toISOString();

  const { error: insertError } = await admin.from("complaints").insert({
    id: complaintId,
    case_code_hash: tracking.caseCodeHash,
    recovery_secret_hash: tracking.recoverySecretHash,
    category: dbCategory,
    encrypted_payload: JSON.stringify(envelopeCheck.envelope),
    encryption_algorithm: ENCRYPTION_ALGORITHM,
    status: "submitted",
    retention_until: retentionUntil,
    created_at: nowIso,
    updated_at: nowIso,
  });

  if (insertError) {
    const status = insertError.code === "23505" ? 409 : 500;
    return NextResponse.json(
      { error: `Failed to store encrypted complaint: ${insertError.message}` },
      { status }
    );
  }

  let uploadedCount = 0;
  for (const item of preparedEvidence) {
    const storagePath = `complaints/${complaintId}/${item.fileId}.enc`;
    const { error: uploadError } = await admin.storage
      .from(EVIDENCE_BUCKET_NAME)
      .upload(storagePath, item.encryptedBytes, {
        contentType: "application/octet-stream",
        upsert: false,
      });

    if (uploadError) {
      return NextResponse.json(
        {
          error: `Complaint recorded, but encrypted evidence upload failed: ${uploadError.message}`,
          caseCode: tracking.caseCode,
          recoverySecret: tracking.recoverySecret,
        },
        { status: 500 }
      );
    }

    const { error: evidenceError } = await admin.from("evidence_files").insert({
      id: item.fileId,
      complaint_id: complaintId,
      storage_path: storagePath,
      mime_type: item.mimeType,
      file_size: item.encryptedBytes.length,
      file_hash: item.ciphertextHash,
      created_at: nowIso,
    });

    if (evidenceError) {
      return NextResponse.json(
        { error: `Failed to record evidence metadata: ${evidenceError.message}` },
        { status: 500 }
      );
    }
    uploadedCount += 1;
  }

  await Promise.all([
    appendAuditLog(admin, {
      complaintId,
      actorMemberId: null,
      eventType: "COMPLAINT_SUBMITTED",
      eventDetails: {
        category: dbCategory,
        encryptionAlgorithm: ENCRYPTION_ALGORITHM,
        clientEncrypted: true,
        evidenceCount: uploadedCount,
        retentionDays,
        retentionUntil,
        threshold: `${REQUIRED_UNLOCK_APPROVALS}-of-${Object.keys(envelopeCheck.envelope.shares).length}`,
      },
    }),
    scheduleAutoShredJob(complaintId, retentionUntil),
    enqueueBackgroundJob({
      type: "AUTO_SHRED_SCHEDULED",
      complaintId,
      payload: { retentionUntil, evidenceCount: uploadedCount },
    }),
    invalidateDashboardCache(),
  ]);

  return NextResponse.json(
    {
      complaintId,
      caseCode: tracking.caseCode,
      recoverySecret: tracking.recoverySecret,
      status: "submitted",
      evidenceCount: uploadedCount,
      retentionUntil,
    },
    { status: 201 }
  );
}
