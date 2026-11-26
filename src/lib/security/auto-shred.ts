import "server-only";
import crypto from "node:crypto";
import {
  enqueueBackgroundJob,
  getDueAutoShredIds,
  invalidateDashboardCache,
  removeAutoShredSchedule,
} from "@/lib/redis/client";
import { appendAuditLog } from "@/lib/security/audit";
import { sha256Hex } from "@/lib/security/crypto";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { EVIDENCE_BUCKET_NAME } from "@/lib/supabase/health";

export interface DeletionReceipt {
  receiptId: string;
  complaintId: string;
  shreddedAt: string;
  retentionUntil: string | null;
  deletedFileCount: number;
  deletedFiles: Array<{
    fileId: string;
    fileHash: string | null;
    mimeType: string;
    fileSize: number;
  }>;
  receiptDigest: string;
}

export interface AutoShredRunResult {
  checkedAt: string;
  expiredComplaintsScanned: number;
  shreddedComplaintCount: number;
  shreddedFileCount: number;
  receipts: DeletionReceipt[];
  errors: string[];
}

/**
 * Executes an Auto-Shred sweep for all complaints past `retention_until`,
 * permanently deleting encrypted blobs from Supabase Storage and recording
 * immutable SHA-256 deletion receipts in `audit_logs`.
 */
export async function runAutoShredCycle(options?: {
  actorMemberId?: string | null;
  limit?: number;
}): Promise<AutoShredRunResult> {
  const checkedAt = new Date().toISOString();
  const limit = Math.min(Math.max(options?.limit ?? 50, 1), 100);

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return {
      checkedAt,
      expiredComplaintsScanned: 0,
      shreddedComplaintCount: 0,
      shreddedFileCount: 0,
      receipts: [],
      errors: ["Supabase service credentials are not configured."],
    };
  }

  const admin = createAdminClient();
  const [redisDueIds, dbDueRes] = await Promise.all([
    getDueAutoShredIds(Date.now(), limit),
    admin
      .from("complaints")
      .select("id, retention_until")
      .not("retention_until", "is", null)
      .lte("retention_until", checkedAt)
      .order("retention_until", { ascending: true })
      .limit(limit),
  ]);

  if (dbDueRes.error) {
    return {
      checkedAt,
      expiredComplaintsScanned: 0,
      shreddedComplaintCount: 0,
      shreddedFileCount: 0,
      receipts: [],
      errors: [dbDueRes.error.message],
    };
  }

  const retentionByComplaint = new Map<string, string | null>();
  for (const row of dbDueRes.data ?? []) {
    retentionByComplaint.set(row.id, row.retention_until);
  }

  // Double-check any extra IDs from Redis directly against complaints.retention_until
  const missingIds = redisDueIds.filter((id) => !retentionByComplaint.has(id));
  if (missingIds.length > 0) {
    const { data: extraRows } = await admin
      .from("complaints")
      .select("id, retention_until")
      .in("id", missingIds)
      .lte("retention_until", checkedAt);
    for (const row of extraRows ?? []) {
      retentionByComplaint.set(row.id, row.retention_until);
    }
  }

  const expiredIds = Array.from(retentionByComplaint.keys());
  if (expiredIds.length === 0) {
    return {
      checkedAt,
      expiredComplaintsScanned: 0,
      shreddedComplaintCount: 0,
      shreddedFileCount: 0,
      receipts: [],
      errors: [],
    };
  }

  const { data: expiredFiles, error: filesError } = await admin
    .from("evidence_files")
    .select("id, complaint_id, storage_path, mime_type, file_size, file_hash")
    .in("complaint_id", expiredIds);

  if (filesError) {
    return {
      checkedAt,
      expiredComplaintsScanned: expiredIds.length,
      shreddedComplaintCount: 0,
      shreddedFileCount: 0,
      receipts: [],
      errors: [filesError.message],
    };
  }

  const filesByComplaint = new Map<
    string,
    NonNullable<typeof expiredFiles>
  >();
  for (const file of expiredFiles ?? []) {
    const list = filesByComplaint.get(file.complaint_id) ?? [];
    list.push(file);
    filesByComplaint.set(file.complaint_id, list);
  }

  const receipts: DeletionReceipt[] = [];
  const errors: string[] = [];
  const clearedRedisIds: string[] = [];
  let shreddedFileCount = 0;

  for (const complaintId of expiredIds) {
    const files = filesByComplaint.get(complaintId) ?? [];
    if (files.length === 0) {
      clearedRedisIds.push(complaintId);
      continue;
    }

    const storagePaths = files.map((f) => f.storage_path).filter(Boolean);
    if (storagePaths.length > 0) {
      const { error: removeStorageErr } = await admin.storage
        .from(EVIDENCE_BUCKET_NAME)
        .remove(storagePaths);
      if (removeStorageErr) {
        errors.push(
          `Storage shred failed for ${complaintId}: ${removeStorageErr.message}`
        );
        continue;
      }
    }

    const fileIds = files.map((f) => f.id);
    const { error: deleteRowsErr } = await admin
      .from("evidence_files")
      .delete()
      .in("id", fileIds);
    if (deleteRowsErr) {
      errors.push(
        `Evidence row cleanup failed for ${complaintId}: ${deleteRowsErr.message}`
      );
      continue;
    }

    const shreddedAt = new Date().toISOString();
    const receiptId = crypto.randomUUID();
    const deletedFiles = files.map((f) => ({
      fileId: f.id,
      fileHash: f.file_hash ?? null,
      mimeType: f.mime_type,
      fileSize: f.file_size,
    }));

    const receiptDigest = sha256Hex(
      JSON.stringify({
        receiptId,
        complaintId,
        shreddedAt,
        retentionUntil: retentionByComplaint.get(complaintId) ?? null,
        deletedFiles,
      })
    );

    const receipt: DeletionReceipt = {
      receiptId,
      complaintId,
      shreddedAt,
      retentionUntil: retentionByComplaint.get(complaintId) ?? null,
      deletedFileCount: deletedFiles.length,
      deletedFiles,
      receiptDigest,
    };

    await appendAuditLog(admin, {
      complaintId,
      actorMemberId: options?.actorMemberId ?? null,
      eventType: "EVIDENCE_AUTO_SHREDDED",
      eventDetails: {
        receiptId: receipt.receiptId,
        shreddedAt: receipt.shreddedAt,
        retentionUntil: receipt.retentionUntil,
        deletedFileCount: receipt.deletedFileCount,
        deletedFiles: receipt.deletedFiles,
        receiptDigest: receipt.receiptDigest,
      },
    });

    receipts.push(receipt);
    clearedRedisIds.push(complaintId);
    shreddedFileCount += deletedFiles.length;
  }

  if (clearedRedisIds.length > 0) {
    await removeAutoShredSchedule(clearedRedisIds);
  }
  if (receipts.length > 0) {
    await Promise.all([
      invalidateDashboardCache(),
      enqueueBackgroundJob({
        type: "CACHE_INVALIDATED",
        payload: {
          reason: "auto_shred",
          shreddedComplaintCount: receipts.length,
          shreddedFileCount,
        },
      }),
    ]);
  }

  return {
    checkedAt,
    expiredComplaintsScanned: expiredIds.length,
    shreddedComplaintCount: receipts.length,
    shreddedFileCount,
    receipts,
    errors,
  };
}
