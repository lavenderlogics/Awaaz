import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  getServiceRoleKeyType,
  isServiceRoleConfigured,
  isSupabaseConfigured,
  type ServiceRoleKeyType,
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
  serviceRoleKeyType: ServiceRoleKeyType | null;
  authReachable: boolean;
  storageBucketVerified: boolean | null;
  tablesVerified: Record<string, boolean> | null;
  adminError: string | null;
  error: string | null;
}

/**
 * Verifies Supabase connectivity using the SSR client and, when configured,
 * checks the expected Awaaz tables and private storage bucket via the admin client.
 */
export async function verifySupabaseConnection(): Promise<SupabaseHealthReport> {
  const publicConfigured = isSupabaseConfigured();
  const serviceRoleConfigured = isServiceRoleConfigured();
  const serviceRoleKeyType = getServiceRoleKeyType();

  if (!publicConfigured) {
    return {
      publicConfigured: false,
      serviceRoleConfigured,
      serviceRoleKeyType,
      authReachable: false,
      storageBucketVerified: null,
      tablesVerified: null,
      adminError: null,
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
      serviceRoleKeyType: null,
      authReachable,
      storageBucketVerified: null,
      tablesVerified: null,
      adminError: null,
      error: errorMessage,
    };
  }

  const tablesVerified: Record<string, boolean> = {};
  let storageBucketVerified = false;
  let adminError: string | null = null;

  try {
    const admin = createAdminClient();

    const tableChecks = await Promise.all(
      AWAAZ_TABLES.map(async (tableName) => {
        const { error, status } = await admin
          .from(tableName)
          .select("*", { count: "exact" })
          .limit(0);
        return {
          tableName,
          ok: !error,
          errorMessage: error
            ? `${error.code || status || "ERR"}: ${error.message || error.hint || "Denied"}`
            : null,
        };
      })
    );

    for (const check of tableChecks) {
      tablesVerified[check.tableName] = check.ok;
      if (!check.ok && !adminError && check.errorMessage) {
        adminError = `${check.tableName}: ${check.errorMessage}`;
      }
    }

    const { data: bucket, error: bucketError } =
      await admin.storage.getBucket(EVIDENCE_BUCKET_NAME);
    storageBucketVerified = !bucketError && Boolean(bucket);
    if (bucketError && !adminError) {
      adminError = `storage(${EVIDENCE_BUCKET_NAME}): ${bucketError.message}`;
    }
  } catch (err) {
    adminError =
      err instanceof Error
        ? err.message
        : "Admin client verification failed.";
  }

  return {
    publicConfigured,
    serviceRoleConfigured,
    serviceRoleKeyType,
    authReachable,
    storageBucketVerified,
    tablesVerified,
    adminError,
    error: errorMessage,
  };
}
