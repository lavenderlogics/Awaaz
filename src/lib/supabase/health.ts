import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const AWAAZ_TABLES = [
  "committee_members",
  "complaints",
  "evidence_files",
  "unlock_approvals",
  "audit_logs",
] as const;

export const EVIDENCE_BUCKET_NAME = "awaaz-evidence";

export interface SupabaseHealthReport {
  publicConfigured: boolean;
  serviceRoleConfigured: boolean;
  authReachable: boolean;
  storageBucketVerified: boolean | null;
  tablesVerified: Record<string, boolean> | null;
  error: string | null;
}

/**
 * Verifies Supabase connectivity using the SSR client and, when configured,
 * checks the expected Awaaz tables and private storage bucket via the admin client.
 */
export async function verifySupabaseConnection(): Promise<SupabaseHealthReport> {
  const publicConfigured = isSupabaseConfigured();
  const serviceRoleConfigured = isServiceRoleConfigured();

  if (!publicConfigured) {
    return {
      publicConfigured: false,
      serviceRoleConfigured,
      authReachable: false,
      storageBucketVerified: null,
      tablesVerified: null,
      error: "Public Supabase environment variables are not configured.",
    };
  }

  let authReachable = false;
  let errorMessage: string | null = null;

  try {
    const supabase = await createClient();
    const { error } = await supabase.auth.getSession();
    if (error) {
      errorMessage = error.message;
    } else {
      authReachable = true;
    }
  } catch (err) {
    errorMessage =
      err instanceof Error ? err.message : "Failed to reach Supabase Auth.";
  }

  if (!serviceRoleConfigured) {
    return {
      publicConfigured,
      serviceRoleConfigured: false,
      authReachable,
      storageBucketVerified: null,
      tablesVerified: null,
      error: errorMessage,
    };
  }

  const tablesVerified: Record<string, boolean> = {};
  let storageBucketVerified = false;

  try {
    const admin = createAdminClient();

    const tableChecks = await Promise.all(
      AWAAZ_TABLES.map(async (tableName) => {
        const { error } = await admin
          .from(tableName)
          .select("*", { head: true, count: "exact" });
        return [tableName, !error] as const;
      })
    );

    for (const [tableName, ok] of tableChecks) {
      tablesVerified[tableName] = ok;
    }

    const { data: bucket, error: bucketError } =
      await admin.storage.getBucket(EVIDENCE_BUCKET_NAME);
    storageBucketVerified = !bucketError && Boolean(bucket);
  } catch (err) {
    errorMessage =
      err instanceof Error
        ? err.message
        : "Admin client verification failed.";
  }

  return {
    publicConfigured,
    serviceRoleConfigured,
    authReachable,
    storageBucketVerified,
    tablesVerified,
    error: errorMessage,
  };
}
