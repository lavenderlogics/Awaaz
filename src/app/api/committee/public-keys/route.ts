import { NextResponse } from "next/server";
import {
  isValidRsaPublicKeyPem,
  REQUIRED_UNLOCK_APPROVALS,
} from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";

/**
 * Returns active committee member IDs and validated RSA-OAEP public keys
 * for browser-side 2-of-N encryption. Never returns private keys or member PII.
 */
export async function GET(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-public-keys"),
    { limit: 60, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many key requests. Please try again shortly." },
      { status: 429 }
    );
  }

  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return NextResponse.json(
      {
        error:
          "Server Supabase credentials are incomplete. Configure SUPABASE_SERVICE_ROLE_KEY on the server.",
      },
      { status: 503 }
    );
  }

  const admin = createAdminClient();
  const { data: rows, error } = await admin
    .from("committee_members")
    .select("user_id, public_key")
    .eq("is_active", true)
    .not("public_key", "is", null)
    .order("created_at", { ascending: true });

  if (error) {
    return NextResponse.json(
      { error: "Failed to load committee encryption keys." },
      { status: 500 }
    );
  }

  const members = (rows ?? [])
    .filter(
      (row): row is { user_id: string; public_key: string } =>
        typeof row.user_id === "string" &&
        typeof row.public_key === "string" &&
        isValidRsaPublicKeyPem(row.public_key)
    )
    .map((row) => ({
      memberId: row.user_id,
      publicKey: row.public_key,
    }));

  if (members.length < REQUIRED_UNLOCK_APPROVALS) {
    return NextResponse.json(
      {
        error: `Client-side encryption requires at least ${REQUIRED_UNLOCK_APPROVALS} active committee members with valid RSA-OAEP public keys.`,
      },
      { status: 503 }
    );
  }

  return NextResponse.json(
    { members },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    }
  );
}
