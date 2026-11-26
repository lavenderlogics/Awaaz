import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { sha256Hex } from "@/lib/security/crypto";

export interface AuditLogInsert {
  complaintId: string;
  actorMemberId: string | null;
  eventType: string;
  eventDetails: Record<string, unknown>;
}

export interface AuditLogRow {
  id: number;
  complaint_id: string;
  actor_member_id: string | null;
  event_type: string;
  event_details: Record<string, unknown> | null;
  previous_hash: string | null;
  entry_hash: string;
  created_at: string;
}

/** Produces deterministic JSON regardless of PostgreSQL jsonb key reordering. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) {
        sorted[key] = canonicalize(v);
      }
    }
    return sorted;
  }
  return value;
}

/** Computes a deterministic SHA-256 hash linking an audit record to the prior entry. */
export function computeAuditEntryHash(input: {
  previousHash: string;
  complaintId: string;
  actorMemberId: string | null;
  eventType: string;
  eventDetails: Record<string, unknown> | null;
  createdAt: string;
}): string {
  return sha256Hex(
    JSON.stringify([
      input.previousHash,
      input.complaintId,
      input.actorMemberId ?? null,
      input.eventType,
      canonicalize(input.eventDetails ?? {}),
      new Date(input.createdAt).toISOString(),
    ])
  );
}

let auditAppendQueue: Promise<unknown> = Promise.resolve();

async function appendAuditLogAttempt(
  admin: SupabaseClient,
  entry: AuditLogInsert
): Promise<{ ok: true } | { ok: false; error: string }> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data: latestRow, error: latestError } = await admin
      .from("audit_logs")
      .select("id, entry_hash")
      .order("id", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (latestError) {
      return { ok: false, error: latestError.message };
    }

    const previousHash = latestRow?.entry_hash ?? "GENESIS";
    const createdAt = new Date().toISOString();
    const entryHash = computeAuditEntryHash({
      previousHash,
      complaintId: entry.complaintId,
      actorMemberId: entry.actorMemberId,
      eventType: entry.eventType,
      eventDetails: entry.eventDetails,
      createdAt,
    });

    const { data: inserted, error: insertError } = await admin
      .from("audit_logs")
      .insert({
        complaint_id: entry.complaintId,
        actor_member_id: entry.actorMemberId,
        event_type: entry.eventType,
        event_details: entry.eventDetails,
        previous_hash: previousHash,
        entry_hash: entryHash,
        created_at: createdAt,
      })
      .select("id, previous_hash")
      .single();

    if (insertError) {
      return { ok: false, error: insertError.message };
    }

    // Detect cross-instance race condition: confirm the row immediately before ours matches previousHash.
    const { data: priorRow } = await admin
      .from("audit_logs")
      .select("entry_hash")
      .lt("id", inserted.id)
      .order("id", { ascending: false })
      .limit(1)
      .maybeSingle();

    const expectedPriorHash = priorRow?.entry_hash ?? "GENESIS";
    if (expectedPriorHash === inserted.previous_hash) {
      return { ok: true };
    }

    // Remove forked row and retry against the updated chain tip.
    await admin.from("audit_logs").delete().eq("id", inserted.id);
  }

  return {
    ok: false,
    error: "Audit log append conflicted with concurrent updates.",
  };
}

/** Appends a serialized hash-chained audit log record to `audit_logs` using the server-only admin client. */
export async function appendAuditLog(
  admin: SupabaseClient,
  entry: AuditLogInsert
): Promise<{ ok: true } | { ok: false; error: string }> {
  const run = auditAppendQueue.then(
    () => appendAuditLogAttempt(admin, entry),
    () => appendAuditLogAttempt(admin, entry)
  );
  auditAppendQueue = run.catch(() => undefined);
  return run;
}

/** Verifies linkage (`previous_hash`) and `entry_hash` across ascending audit log rows. */
export function verifyAuditChain(rowsAscending: AuditLogRow[]): boolean {
  for (let i = 0; i < rowsAscending.length; i++) {
    const row = rowsAscending[i];
    const previousHash = row.previous_hash ?? "GENESIS";
    if (i > 0 && row.previous_hash !== rowsAscending[i - 1].entry_hash) {
      return false;
    }
    const expected = computeAuditEntryHash({
      previousHash,
      complaintId: row.complaint_id,
      actorMemberId: row.actor_member_id,
      eventType: row.event_type,
      eventDetails: row.event_details,
      createdAt: row.created_at,
    });
    if (expected !== row.entry_hash) {
      return false;
    }
  }
  return true;
}
