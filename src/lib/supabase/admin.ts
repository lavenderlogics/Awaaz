import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { getSupabaseServiceRoleConfig } from "@/lib/supabase/config";

let cachedAdminClient: SupabaseClient | null = null;

/**
 * Creates (or reuses) a server-only Supabase admin client using the service-role key.
 * Never import this module in Client Components or expose it to the browser.
 */
export function createAdminClient(): SupabaseClient {
  if (typeof window !== "undefined") {
    throw new Error("createAdminClient() is strictly server-only.");
  }

  if (cachedAdminClient) {
    return cachedAdminClient;
  }

  const { url, serviceRoleKey } = getSupabaseServiceRoleConfig();

  cachedAdminClient = createClient(url, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  return cachedAdminClient;
}
