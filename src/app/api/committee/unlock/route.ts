import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import {
  type EncryptedComplaintEnvelope,
  isStrictRsa2048CiphertextBase64,
  isValidRsaPublicKeyPem,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";

interface ForwardedShareEnvelope {
  version: 2;
  scheme: "C2-FORWARDED-RSA-OAEP-256";
  complaintId: string;
  senderMemberId: string;
  recipients: Record<string, string>;
}

const FORBIDDEN_SECRET_FIELDS = [
  "privateKeyPem",
  "privateKey",
  "plaintextShare",
  "rawShare",
  "aesKey",
  "rawDek",
  "decryptedPayload",
] as const;

function parseForwardedShareEnvelope(
  raw: string
): ForwardedShareEnvelope | null {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (
      parsed &&
      parsed.version === 2 &&
      parsed.scheme === "C2-FORWARDED-RSA-OAEP-256" &&
      parsed.recipients &&
      typeof parsed.recipients === "object" &&
      !Array.isArray(parsed.recipients)
    ) {
      return parsed as unknown as ForwardedShareEnvelope;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * C2 Step A & Step D retrieval endpoint:
 * Returns ONLY the encrypted complaint ciphertext, the authenticated member's own
 * wrapped share, and forwarded encrypted shares specifically addressed to this member.
 * Never returns private keys, plaintext shares, AES keys, or other members' shares.
 */
export async function GET(request: Request) {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  const url = new URL(request.url);
  const complaintId = url.searchParams.get("complaintId")?.trim() ?? "";
  if (!isUuid(complaintId)) {
    return NextResponse.json(
      { error: "Valid complaintId UUID query parameter is required." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const [complaintRes, approvalsRes, evidenceRes] = await Promise.all([
    admin
      .from("complaints")
      .select(
        "id, category, status, encrypted_payload, encryption_algorithm, created_at, updated_at"
      )
      .eq("id", complaintId)
      .maybeSingle(),
    admin
      .from("unlock_approvals")
      .select("member_id, encrypted_key_share, approved_at")
      .eq("complaint_id", complaintId),
    admin
      .from("evidence_files")
      .select("id, mime_type, file_size, file_hash, created_at")
      .eq("complaint_id", complaintId),
  ]);

  if (complaintRes.error || !complaintRes.data) {
    return NextResponse.json(
      { error: "Complaint not found." },
      { status: 404 }
    );
  }

  let envelope: EncryptedComplaintEnvelope;
  try {
    envelope = JSON.parse(
      complaintRes.data.encrypted_payload
    ) as EncryptedComplaintEnvelope;
  } catch {
    return NextResponse.json(
      { error: "Stored complaint envelope is malformed." },
      { status: 500 }
    );
  }

  const myEncryptedShare = envelope.shares?.[auth.member.user_id] ?? null;
  const forwardedSharesToMe: Array<{
    senderMemberId: string;
    ciphertextShare: string;
    approvedAt: string | null;
  }> = [];
  const approvalSummaries: Array<{
    memberId: string;
    approvedAt: string | null;
    forwardedToIds: string[];
  }> = [];

  for (const row of approvalsRes.data ?? []) {
    const parsed = parseForwardedShareEnvelope(row.encrypted_key_share);
    if (!parsed) {
      approvalSummaries.push({
        memberId: row.member_id,
        approvedAt: row.approved_at,
        forwardedToIds: [],
      });
      continue;
    }

    const recipientIds = Object.keys(parsed.recipients);
    approvalSummaries.push({
      memberId: row.member_id,
      approvedAt: row.approved_at,
      forwardedToIds: recipientIds,
    });

    // Strictly return only forwarded shares addressed to the authenticated member
    const shareForMe = parsed.recipients[auth.member.user_id];
    if (
      row.member_id !== auth.member.user_id &&
      isStrictRsa2048CiphertextBase64(shareForMe)
    ) {
      forwardedSharesToMe.push({
        senderMemberId: row.member_id,
        ciphertextShare: shareForMe,
        approvedAt: row.approved_at,
      });
    }
  }

  return NextResponse.json(
    {
      complaintId: complaintRes.data.id,
      category: complaintRes.data.category,
      status: complaintRes.data.status ?? "submitted",
      encryptionAlgorithm:
        complaintRes.data.encryption_algorithm ?? "AES-256-GCM",
      createdAt: complaintRes.data.created_at,
      updatedAt: complaintRes.data.updated_at,
      envelope: {
        version: envelope.version,
        algorithm: envelope.algorithm,
        keyScheme: envelope.keyScheme,
        iv: envelope.iv,
        authTag: envelope.authTag,
        ciphertext: envelope.ciphertext,
      },
      myEncryptedShare,
      forwardedSharesToMe,
      approvalSummaries,
      evidenceFiles: evidenceRes.data ?? [],
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}

/**
 * C2 Step C share-forwarding endpoint:
 * Accepts ONLY a browser-encrypted forwarded share wrapped with the intended
 * recipient committee member's RSA-OAEP public key. Never accepts private keys
 * or plaintext shares, and never decrypts anything on the server.
 */
export async function POST(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-share-forward"),
    { limit: 30, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many share forwarding requests. Please try again later." },
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

  const forbidden = FORBIDDEN_SECRET_FIELDS.filter(
    (field) => body[field] !== undefined
  );
  if (forbidden.length > 0) {
    return NextResponse.json(
      {
        error:
          "Private keys, plaintext shares, and AES keys must never be sent to the server.",
      },
      { status: 400 }
    );
  }

  if (!isUuid(body.complaintId) || !isUuid(body.recipientMemberId)) {
    return NextResponse.json(
      { error: "Valid complaintId and recipientMemberId UUIDs are required." },
      { status: 400 }
    );
  }

  const complaintId = (body.complaintId as string).trim();
  const recipientMemberId = (body.recipientMemberId as string).trim();

  if (recipientMemberId === auth.member.user_id) {
    return NextResponse.json(
      { error: "You cannot forward your own share to yourself." },
      { status: 400 }
    );
  }

  if (!isStrictRsa2048CiphertextBase64(body.encryptedForwardedShare)) {
    return NextResponse.json(
      {
        error:
          "encryptedForwardedShare must be valid RSA-OAEP-2048 ciphertext (base64).",
      },
      { status: 400 }
    );
  }
  const encryptedForwardedShare = body.encryptedForwardedShare.trim();

  const admin = createAdminClient();
  const [complaintRes, recipientRes, existingApprovalRes] = await Promise.all([
    admin
      .from("complaints")
      .select("id, encrypted_payload")
      .eq("id", complaintId)
      .maybeSingle(),
    admin
      .from("committee_members")
      .select("user_id, public_key, is_active")
      .eq("user_id", recipientMemberId)
      .maybeSingle(),
    admin
      .from("unlock_approvals")
      .select("id, encrypted_key_share")
      .eq("complaint_id", complaintId)
      .eq("member_id", auth.member.user_id)
      .maybeSingle(),
  ]);

  if (complaintRes.error || !complaintRes.data) {
    return NextResponse.json(
      { error: "Complaint not found." },
      { status: 404 }
    );
  }

  if (
    recipientRes.error ||
    !recipientRes.data ||
    recipientRes.data.is_active === false ||
    !recipientRes.data.public_key ||
    !isValidRsaPublicKeyPem(recipientRes.data.public_key)
  ) {
    return NextResponse.json(
      {
        error:
          "Recipient must be an active committee member with a valid RSA public key.",
      },
      { status: 403 }
    );
  }

  let envelope: EncryptedComplaintEnvelope;
  try {
    envelope = JSON.parse(
      complaintRes.data.encrypted_payload
    ) as EncryptedComplaintEnvelope;
  } catch {
    return NextResponse.json(
      { error: "Stored complaint envelope is malformed." },
      { status: 500 }
    );
  }

  if (!envelope.shares?.[auth.member.user_id]) {
    return NextResponse.json(
      {
        error:
          "This complaint does not contain an encrypted share for your committee account.",
      },
      { status: 403 }
    );
  }

  const existingParsed = existingApprovalRes.data
    ? parseForwardedShareEnvelope(existingApprovalRes.data.encrypted_key_share)
    : null;

  const updatedEnvelope: ForwardedShareEnvelope = {
    version: 2,
    scheme: "C2-FORWARDED-RSA-OAEP-256",
    complaintId,
    senderMemberId: auth.member.user_id,
    recipients: {
      ...(existingParsed?.recipients ?? {}),
      [recipientMemberId]: encryptedForwardedShare,
    },
  };

  const nowIso = new Date().toISOString();
  const { error: upsertError } = await admin.from("unlock_approvals").upsert(
    {
      id: existingApprovalRes.data?.id ?? crypto.randomUUID(),
      complaint_id: complaintId,
      member_id: auth.member.user_id,
      encrypted_key_share: JSON.stringify(updatedEnvelope),
      approved_at: nowIso,
    },
    { onConflict: "complaint_id,member_id" }
  );

  if (upsertError) {
    return NextResponse.json(
      { error: `Failed to store forwarded share: ${upsertError.message}` },
      { status: 500 }
    );
  }

  await appendAuditLog(admin, {
    complaintId,
    actorMemberId: auth.member.user_id,
    eventType: "UNLOCK_APPROVED",
    eventDetails: {
      mode: "C2-client-forwarded",
      recipientMemberId,
      memberRole: auth.member.role,
    },
  });

  return NextResponse.json({
    ok: true,
    complaintId,
    senderMemberId: auth.member.user_id,
    recipientMemberId,
    approvedAt: nowIso,
  });
}
