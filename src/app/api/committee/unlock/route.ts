import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { appendAuditLog } from "@/lib/security/audit";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import {
  decryptComplaintEnvelope,
  type EncryptedComplaintEnvelope,
  protectStoredShare,
  REQUIRED_UNLOCK_APPROVALS,
  unprotectStoredShare,
  unwrapMemberShareWithPrivateKey,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isUuid } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import { getShareWrappingSecret } from "@/lib/supabase/config";

/**
 * Dual-key complaint unlock endpoint:
 * Each active committee member submits their own private key in memory to unwrap
 * their RSA-encrypted Shamir share and record an approval in `unlock_approvals`.
 * Once >= 2 distinct active members approve, the AES-256-GCM payload is decrypted.
 */
export async function POST(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-unlock"),
    { limit: 20, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many unlock requests. Please try again later." },
      { status: 429 }
    );
  }

  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  let body: { complaintId?: unknown; privateKeyPem?: unknown };
  try {
    body = (await request.json()) as {
      complaintId?: unknown;
      privateKeyPem?: unknown;
    };
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (!isUuid(body.complaintId)) {
    return NextResponse.json(
      { error: "Valid complaintId UUID is required." },
      { status: 400 }
    );
  }

  const complaintId = (body.complaintId as string).trim();
  const privateKeyPem =
    typeof body.privateKeyPem === "string" ? body.privateKeyPem.trim() : "";

  const admin = createAdminClient();
  const { data: complaint, error: complaintError } = await admin
    .from("complaints")
    .select("id, category, status, encrypted_payload, created_at, updated_at")
    .eq("id", complaintId)
    .maybeSingle();

  if (complaintError || !complaint) {
    return NextResponse.json(
      { error: "Complaint not found." },
      { status: 404 }
    );
  }

  let envelope: EncryptedComplaintEnvelope;
  try {
    envelope = JSON.parse(
      complaint.encrypted_payload
    ) as EncryptedComplaintEnvelope;
  } catch {
    return NextResponse.json(
      { error: "Stored complaint envelope is malformed." },
      { status: 500 }
    );
  }

  const shareWrappingSecret = getShareWrappingSecret();

  if (privateKeyPem) {
    const memberEncryptedShare = envelope.shares?.[auth.member.user_id];
    if (!memberEncryptedShare) {
      return NextResponse.json(
        {
          error:
            "This complaint does not contain a key share for your committee account.",
        },
        { status: 403 }
      );
    }

    let rawShare: Buffer;
    try {
      rawShare = unwrapMemberShareWithPrivateKey(
        memberEncryptedShare,
        privateKeyPem
      );
    } catch {
      return NextResponse.json(
        { error: "Invalid private key for this committee account." },
        { status: 400 }
      );
    }

    const protectedShare = protectStoredShare(
      rawShare,
      complaintId,
      auth.member.user_id,
      shareWrappingSecret
    );
    rawShare.fill(0);

    const { data: existingApproval } = await admin
      .from("unlock_approvals")
      .select("id")
      .eq("complaint_id", complaintId)
      .eq("member_id", auth.member.user_id)
      .maybeSingle();

    if (!existingApproval) {
      const { error: insertApprovalError } = await admin
        .from("unlock_approvals")
        .insert({
          id: crypto.randomUUID(),
          complaint_id: complaintId,
          member_id: auth.member.user_id,
          encrypted_key_share: protectedShare,
          approved_at: new Date().toISOString(),
        });

      if (insertApprovalError) {
        return NextResponse.json(
          { error: `Failed to record unlock approval: ${insertApprovalError.message}` },
          { status: 500 }
        );
      }

      await appendAuditLog(admin, {
        complaintId,
        actorMemberId: auth.member.user_id,
        eventType: "UNLOCK_APPROVED",
        eventDetails: {
          memberRole: auth.member.role,
        },
      });
    }
  }

  const { data: approvals, error: approvalsError } = await admin
    .from("unlock_approvals")
    .select("member_id, encrypted_key_share, approved_at")
    .eq("complaint_id", complaintId);

  if (approvalsError) {
    return NextResponse.json(
      { error: approvalsError.message },
      { status: 500 }
    );
  }

  const uniqueApprovals = new Map<string, string>();
  for (const row of approvals ?? []) {
    if (!uniqueApprovals.has(row.member_id)) {
      uniqueApprovals.set(row.member_id, row.encrypted_key_share);
    }
  }

  if (uniqueApprovals.size < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json({
      unlocked: false,
      approvalsCount: uniqueApprovals.size,
      requiredApprovals: REQUIRED_UNLOCK_APPROVALS,
    });
  }

  const unwrappedShares: Buffer[] = [];
  for (const [memberId, protectedJson] of uniqueApprovals.entries()) {
    try {
      unwrappedShares.push(
        unprotectStoredShare(
          protectedJson,
          complaintId,
          memberId,
          shareWrappingSecret
        )
      );
    } catch {
      continue;
    }
    if (unwrappedShares.length === REQUIRED_UNLOCK_APPROVALS) {
      break;
    }
  }

  if (unwrappedShares.length < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json(
      { error: "Unable to unwrap enough valid key shares to decrypt complaint." },
      { status: 500 }
    );
  }

  let decryptedPayload: Record<string, unknown>;
  try {
    decryptedPayload = decryptComplaintEnvelope(
      envelope,
      complaintId,
      unwrappedShares
    );
  } catch {
    return NextResponse.json(
      { error: "AES-256-GCM authentication or decryption failed." },
      { status: 500 }
    );
  } finally {
    unwrappedShares.forEach((b) => b.fill(0));
  }

  const { data: evidenceRows } = await admin
    .from("evidence_files")
    .select("id, mime_type, file_size, file_hash, created_at")
    .eq("complaint_id", complaintId);

  await appendAuditLog(admin, {
    complaintId,
    actorMemberId: auth.member.user_id,
    eventType: "COMPLAINT_DECRYPTED",
    eventDetails: {
      approvalsCount: uniqueApprovals.size,
    },
  });

  return NextResponse.json({
    unlocked: true,
    approvalsCount: uniqueApprovals.size,
    requiredApprovals: REQUIRED_UNLOCK_APPROVALS,
    payload: decryptedPayload,
    evidenceFiles: evidenceRows ?? [],
  });
}
