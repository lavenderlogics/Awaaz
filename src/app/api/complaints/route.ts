import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import {
  type CommitteeRecipientKey,
  ENCRYPTION_ALGORITHM,
  encryptComplaintPayload,
  encryptEvidenceBuffer,
  generateTrackingCredentials,
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  isIsoDateString,
  isValidCategory,
  isValidUrgency,
  MAX_EVIDENCE_BYTES,
  MAX_EVIDENCE_FILES,
  readNonEmptyString,
} from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { EVIDENCE_BUCKET_NAME } from "@/lib/supabase/health";

interface ParsedSubmission {
  category: unknown;
  urgency: unknown;
  incidentDate: unknown;
  location: unknown;
  description: unknown;
  additionalContext: unknown;
  files: File[];
}

async function parseRequestBody(request: Request): Promise<ParsedSubmission> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const rawFiles = formData
      .getAll("evidence")
      .filter((entry): entry is File => entry instanceof File && entry.size > 0);
    return {
      category: formData.get("category"),
      urgency: formData.get("urgency"),
      incidentDate: formData.get("incidentDate"),
      location: formData.get("location"),
      description: formData.get("description"),
      additionalContext: formData.get("additionalContext"),
      files: rawFiles,
    };
  }

  const body = (await request.json()) as Record<string, unknown>;
  return {
    category: body.category,
    urgency: body.urgency,
    incidentDate: body.incidentDate,
    location: body.location,
    description: body.description,
    additionalContext: body.additionalContext,
    files: [],
  };
}

/** Anonymous encrypted complaint intake (never stores plaintext complaint fields). */
export async function POST(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "submit-complaint"),
    { limit: 5, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many submissions from this network. Please wait before trying again." },
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

  let parsed: ParsedSubmission;
  try {
    parsed = await parseRequestBody(request);
  } catch {
    return NextResponse.json(
      { error: "Invalid request payload." },
      { status: 400 }
    );
  }

  if (!isValidCategory(parsed.category)) {
    return NextResponse.json(
      { error: "Please select a valid incident category." },
      { status: 400 }
    );
  }
  const urgency = isValidUrgency(parsed.urgency) ? parsed.urgency : "standard";
  if (!isIsoDateString(parsed.incidentDate)) {
    return NextResponse.json(
      { error: "Please provide a valid incident date (YYYY-MM-DD)." },
      { status: 400 }
    );
  }

  const location = readNonEmptyString(parsed.location, 2, 200);
  const description = readNonEmptyString(parsed.description, 20, 5000);
  const additionalContext =
    typeof parsed.additionalContext === "string"
      ? parsed.additionalContext.trim().slice(0, 3000)
      : "";

  if (!location || !description) {
    return NextResponse.json(
      {
        error:
          "Location (2-200 chars) and incident description (20-5000 chars) are required.",
      },
      { status: 400 }
    );
  }

  if (parsed.files.length > MAX_EVIDENCE_FILES) {
    return NextResponse.json(
      { error: `Maximum ${MAX_EVIDENCE_FILES} evidence files allowed per submission.` },
      { status: 400 }
    );
  }

  for (const file of parsed.files) {
    if (file.size > MAX_EVIDENCE_BYTES) {
      return NextResponse.json(
        { error: `File "${file.name}" exceeds the 5 MB limit.` },
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
  }

  const admin = createAdminClient();
  const { data: committeeRows, error: committeeError } = await admin
    .from("committee_members")
    .select("user_id, public_key")
    .eq("is_active", true)
    .not("public_key", "is", null);

  if (committeeError) {
    return NextResponse.json(
      { error: "Failed to load committee encryption keys." },
      { status: 500 }
    );
  }

  const recipients: CommitteeRecipientKey[] = (committeeRows ?? [])
    .filter(
      (row): row is { user_id: string; public_key: string } =>
        typeof row.user_id === "string" &&
        typeof row.public_key === "string" &&
        isValidRsaPublicKeyPem(row.public_key)
    )
    .map((row) => ({
      memberId: row.user_id,
      publicKeyPem: row.public_key,
    }));

  if (recipients.length < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json(
      {
        error: `Encrypted intake requires at least ${REQUIRED_UNLOCK_APPROVALS} active committee members with registered RSA public keys.`,
      },
      { status: 503 }
    );
  }

  const complaintId = crypto.randomUUID();
  const tracking = generateTrackingCredentials();
  const nowIso = new Date().toISOString();
  const retentionUntil = new Date(
    Date.now() + 365 * 24 * 60 * 60 * 1000
  ).toISOString();

  const sensitivePayload = {
    urgency,
    incidentDate: parsed.incidentDate.trim(),
    location,
    description,
    additionalContext,
    evidenceFileNames: parsed.files.map((f) => f.name),
  };

  const envelope = encryptComplaintPayload(
    sensitivePayload,
    complaintId,
    recipients
  );

  const { error: insertError } = await admin.from("complaints").insert({
    id: complaintId,
    case_code_hash: tracking.caseCodeHash,
    recovery_secret_hash: tracking.recoverySecretHash,
    category: parsed.category.trim(),
    encrypted_payload: JSON.stringify(envelope),
    encryption_algorithm: ENCRYPTION_ALGORITHM,
    status: "submitted",
    retention_until: retentionUntil,
    created_at: nowIso,
    updated_at: nowIso,
  });

  if (insertError) {
    return NextResponse.json(
      { error: `Failed to store encrypted complaint: ${insertError.message}` },
      { status: 500 }
    );
  }

  let uploadedCount = 0;
  for (const file of parsed.files) {
    const fileId = crypto.randomUUID();
    const rawBuffer = Buffer.from(await file.arrayBuffer());
    const { encryptedBlob, ciphertextHash } = encryptEvidenceBuffer(
      rawBuffer,
      complaintId,
      fileId,
      recipients
    );
    const storagePath = `complaints/${complaintId}/${fileId}.enc`;

    const { error: uploadError } = await admin.storage
      .from(EVIDENCE_BUCKET_NAME)
      .upload(storagePath, encryptedBlob, {
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
      id: fileId,
      complaint_id: complaintId,
      storage_path: storagePath,
      mime_type: file.type,
      file_size: encryptedBlob.length,
      file_hash: ciphertextHash,
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

  await appendAuditLog(admin, {
    complaintId,
    actorMemberId: null,
    eventType: "COMPLAINT_SUBMITTED",
    eventDetails: {
      category: parsed.category.trim(),
      encryptionAlgorithm: ENCRYPTION_ALGORITHM,
      evidenceCount: uploadedCount,
      threshold: `${REQUIRED_UNLOCK_APPROVALS}-of-${recipients.length}`,
    },
  });

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
