import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { getSupabaseServiceRoleConfig } from "@/lib/supabase/config";

let cachedAdminClient: SupabaseClient | null = null;
let cachedKeySignature = "";

/**
 * Creates (or reuses) a server-only Supabase admin client using the service-role/secret key.
 * Strips invalid `Bearer sb_secret_...` Authorization headers so Supabase `sb_secret_` keys
 * work reliably across PostgREST and Storage endpoints.
 */
export function createAdminClient(): SupabaseClient {
  if (typeof window !== "undefined") {
    throw new Error("createAdminClient() is strictly server-only.");
  }

  const { url, serviceRoleKey } = getSupabaseServiceRoleConfig();
  const signature = `${url}:${serviceRoleKey.slice(0, 16)}:${serviceRoleKey.length}`;

  if (cachedAdminClient && cachedKeySignature === signature) {
    return cachedAdminClient;
  }

  const isNewSecretKey = serviceRoleKey.startsWith("sb_secret_");

  const customFetch: typeof fetch | undefined = isNewSecretKey
    ? async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set("apikey", serviceRoleKey);
        const auth = headers.get("Authorization");
        if (auth && auth.includes(serviceRoleKey)) {
          headers.delete("Authorization");
        }
        return fetch(input, { ...init, headers });
      }
    : undefined;

  cachedAdminClient = createClient(url, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
    ...(customFetch ? { global: { fetch: customFetch } } : {}),
  });
  cachedKeySignature = signature;

  return cachedAdminClient;
}
