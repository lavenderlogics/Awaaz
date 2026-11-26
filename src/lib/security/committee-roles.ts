import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

const LEAST_PRIVILEGE_ROLE_CANDIDATES = [
  "member",
  "investigator",
  "reviewer",
  "officer",
  "admin",
] as const;

function isRoleCheckConstraintError(
  error: { code?: string; message?: string } | null | undefined
): boolean {
  if (!error) return false;
  return (
    error.code === "23514" ||
    (error.message ?? "").includes("committee_members_role_check")
  );
}

function getCandidateRoles(preferredRole: string): string[] {
  if (preferredRole === "admin") {
    return ["admin"];
  }
  const rest = LEAST_PRIVILEGE_ROLE_CANDIDATES.filter(
    (r) => r !== preferredRole
  );
  return [preferredRole, ...rest];
}

/**
 * Inserts a new `committee_members` row using least-privilege role preference,
 * stepping through DB-compatible role values if `committee_members_role_check` rejects a role.
 */
export async function insertCommitteeMemberResilient(
  admin: SupabaseClient,
  params: {
    userId: string;
    fullName: string;
    preferredRole: string;
    isActive: boolean;
  }
): Promise<{
  role: string;
  error: { code?: string; message: string } | null;
}> {
  const candidates = getCandidateRoles(params.preferredRole);
  let lastError: { code?: string; message: string } | null = null;

  for (const role of candidates) {
    const { error } = await admin.from("committee_members").insert({
      user_id: params.userId,
      full_name: params.fullName,
      role,
      is_active: params.isActive,
    });
    if (!error) {
      return { role, error: null };
    }
    lastError = error;
    if (!isRoleCheckConstraintError(error)) {
      return { role, error };
    }
  }

  return { role: params.preferredRole, error: lastError };
}

/**
 * Upserts an approved `committee_members` row cleanly even if the Postgres
 * `committee_members_role_check` constraint only permits a subset of roles.
 */
export async function upsertApprovedCommitteeMemberResilient(
  admin: SupabaseClient,
  params: {
    userId: string;
    fullName: string;
    preferredRole: string;
  }
): Promise<{
  role: string;
  error: { code?: string; message: string } | null;
}> {
  const candidates = getCandidateRoles(params.preferredRole);
  let lastError: { code?: string; message: string } | null = null;

  for (const role of candidates) {
    const { error } = await admin.from("committee_members").upsert(
      {
        user_id: params.userId,
        full_name: params.fullName,
        role,
        is_active: true,
      },
      { onConflict: "user_id" }
    );
    if (!error) {
      return { role, error: null };
    }
    lastError = error;
    if (!isRoleCheckConstraintError(error)) {
      return { role, error };
    }
  }

  return { role: params.preferredRole, error: lastError };
}

/**
 * Updates an existing `committee_members` row, stepping through compatible roles
 * only when activating/assigning a non-admin member against a constrained DB schema.
 */
export async function updateCommitteeMemberResilient(
  admin: SupabaseClient,
  params: {
    memberId: string;
    updates: { role?: string; is_active?: boolean };
    allowRoleFallback: boolean;
  }
): Promise<{
  appliedUpdates: { role?: string; is_active?: boolean };
  error: { code?: string; message: string } | null;
}> {
  if (!params.updates.role || !params.allowRoleFallback) {
    const { error } = await admin
      .from("committee_members")
      .update(params.updates)
      .eq("user_id", params.memberId);
    return { appliedUpdates: params.updates, error };
  }

  const candidates = getCandidateRoles(params.updates.role);
  let lastError: { code?: string; message: string } | null = null;

  for (const role of candidates) {
    const candidateUpdates = { ...params.updates, role };
    const { error } = await admin
      .from("committee_members")
      .update(candidateUpdates)
      .eq("user_id", params.memberId);
    if (!error) {
      return { appliedUpdates: candidateUpdates, error: null };
    }
    lastError = error;
    if (!isRoleCheckConstraintError(error)) {
      return { appliedUpdates: candidateUpdates, error };
    }
  }

  return { appliedUpdates: params.updates, error: lastError };
}
