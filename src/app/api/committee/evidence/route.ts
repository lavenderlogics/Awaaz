import { NextResponse } from "next/server";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { isStrictRsa2048CiphertextBase64 } from "@/lib/security/crypto";
import { isUuid } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import { EVIDENCE_BUCKET_NAME } from "@/lib/supabase/health";

interface ForwardedEnvelopeWithEvidence {
  version: number;
  scheme: string;
  recipients?: Record<string, string>;
  evidenceRecipients?: Record<string, Record<string, string>>;
}

function parseAwz1Blob(blob: Buffer) {
  if (blob.length < 16 || blob.subarray(0, 4).toString("ascii") !== "AWZ1") {
    return null;
  }
  const headerLen = blob.readUInt32BE(4);
  if (headerLen < 20 || headerLen > 65536 || 8 + headerLen >= blob.length) {
    return null;
  }
  try {
    const header = JSON.parse(
      blob.subarray(8, 8 + headerLen).toString("utf8")
    ) as {
      iv: string;
      authTag: string;
      shares?: Record<string, string>;
    };
    return {
      iv: header.iv,
      authTag: header.authTag,
      shares: header.shares ?? {},
      ciphertextBase64: blob.subarray(8 + headerLen).toString("base64"),
    };
  } catch {
    return null;
  }
}

/**
 * Returns encrypted AWZ1 components and ONLY the authenticated officer's own share
 * plus forwarded evidence shares specifically addressed to this officer.
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
  const [filesRes, approvalsRes] = await Promise.all([
    admin
      .from("evidence_files")
      .select("id, storage_path, mime_type, file_size, file_hash, created_at")
      .eq("complaint_id", complaintId),
    admin
      .from("unlock_approvals")
      .select("member_id, encrypted_key_share")
      .eq("complaint_id", complaintId),
  ]);

  if (filesRes.error) {
    return NextResponse.json(
      { error: "Failed to load encrypted evidence metadata." },
      { status: 500 }
    );
  }

  const forwardedEvidenceByFile: Record<
    string,
    Array<{ senderMemberId: string; ciphertextShare: string }>
  > = {};

  for (const row of approvalsRes.data ?? []) {
    if (row.member_id === auth.member.user_id) continue;
    try {
      const parsed = JSON.parse(
        row.encrypted_key_share
      ) as ForwardedEnvelopeWithEvidence;
      const fileMap = parsed.evidenceRecipients?.[auth.member.user_id];
      if (!fileMap || typeof fileMap !== "object") continue;
      for (const [fileId, share] of Object.entries(fileMap)) {
        if (isStrictRsa2048CiphertextBase64(share)) {
          forwardedEvidenceByFile[fileId] ??= [];
          forwardedEvidenceByFile[fileId].push({
            senderMemberId: row.member_id,
            ciphertextShare: share,
          });
        }
      }
    } catch {
      continue;
    }
  }

  const items: Array<{
    fileId: string;
    mimeType: string;
    fileSize: number;
    fileHash: string | null;
    iv: string;
    authTag: string;
    ciphertextBase64: string;
    myEncryptedShare: string | null;
    forwardedSharesToMe: Array<{ senderMemberId: string; ciphertextShare: string }>;
  }> = [];

  for (const row of filesRes.data ?? []) {
    const { data: blobData, error: dlError } = await admin.storage
      .from(EVIDENCE_BUCKET_NAME)
      .download(row.storage_path);
    if (dlError || !blobData) {
      continue;
    }
    const parsed = parseAwz1Blob(Buffer.from(await blobData.arrayBuffer()));
    if (!parsed) continue;

    items.push({
      fileId: row.id,
      mimeType: row.mime_type,
      fileSize: row.file_size,
      fileHash: row.file_hash,
      iv: parsed.iv,
      authTag: parsed.authTag,
      ciphertextBase64: parsed.ciphertextBase64,
      myEncryptedShare: parsed.shares[auth.member.user_id] ?? null,
      forwardedSharesToMe: forwardedEvidenceByFile[row.id] ?? [],
    });
  }

  return NextResponse.json(
    { complaintId, files: items },
    { headers: { "Cache-Control": "no-store" } }
  );
}
