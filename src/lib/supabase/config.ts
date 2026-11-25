export interface SupabaseConfig {
  url: string;
  anonKey: string;
}

export interface SupabaseAdminConfig {
  url: string;
  serviceRoleKey: string;
}

/** Reads public Supabase project URL and publishable/anon key from env. */
export function getSupabaseConfig(): SupabaseConfig {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey =
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!url || !anonKey) {
    throw new Error(
      "Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY in environment."
    );
  }

  return { url, anonKey };
}

/** Returns true when public Supabase environment variables are configured. */
export function isSupabaseConfigured(): boolean {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey =
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  return Boolean(url && anonKey);
}

/** Reads server-only Supabase service-role/secret key from env. */
export function getSupabaseServiceRoleConfig(): SupabaseAdminConfig {
  if (typeof window !== "undefined") {
    throw new Error(
      "getSupabaseServiceRoleConfig() must never be called in browser code."
    );
  }

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY;

  if (!url || !serviceRoleKey) {
    throw new Error(
      "Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in server environment."
    );
  }

  return { url, serviceRoleKey };
}

/** Returns true when server-only service-role credentials are available. */
export function isServiceRoleConfigured(): boolean {
  if (typeof window !== "undefined") {
    return false;
  }

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY;

  return Boolean(url && serviceRoleKey);
}

/** Returns a server-only secret for wrapping intermediate unlock shares. */
export function getShareWrappingSecret(): string {
  if (typeof window !== "undefined") {
    throw new Error("getShareWrappingSecret() is strictly server-only.");
  }

  const secret =
    process.env.AWAAZ_KEY_SECRET ??
    process.env.SUPABASE_SERVICE_ROLE_KEY ??
    process.env.SUPABASE_SECRET_KEY;

  if (!secret) {
    throw new Error(
      "Missing AWAAZ_KEY_SECRET or SUPABASE_SERVICE_ROLE_KEY in server environment."
    );
  }

  return secret;
}
