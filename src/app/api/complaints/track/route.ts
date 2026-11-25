import { NextResponse } from "next/server";
import { safeEqualHex, sha256Hex } from "@/lib/security/crypto";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { isValidCaseIdFormat, readNonEmptyString } from "@/lib/security/validation";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";

/** Anonymous Case ID status lookup returning only non-sensitive status metadata. */
export async function POST(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "track-complaint"),
    { limit: 20, windowMs: 10 * 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many tracking requests. Please try again later." },
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

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (!isValidCaseIdFormat(body.caseCode)) {
    return NextResponse.json(
      { error: "Please enter a valid Case ID (e.g. AWZ-XXXX-XXXX-XXXX)." },
      { status: 400 }
    );
  }

  const normalizedCaseCode = (body.caseCode as string).trim().toUpperCase();
  const caseCodeHash = sha256Hex(normalizedCaseCode);
  const recoverySecret = readNonEmptyString(body.recoverySecret, 4, 64);

  const admin = createAdminClient();
  const { data: complaint, error } = await admin
    .from("complaints")
    .select(
      "id, category, status, encryption_algorithm, recovery_secret_hash, retention_until, created_at, updated_at"
    )
    .eq("case_code_hash", caseCodeHash)
    .maybeSingle();

  if (error) {
    return NextResponse.json(
      { error: "Unable to look up complaint status." },
      { status: 500 }
    );
  }

  if (!complaint) {
    return NextResponse.json(
      { found: false, error: "No complaint matches that Case ID." },
      { status: 404 }
    );
  }

  const { count: evidenceCount } = await admin
    .from("evidence_files")
    .select("id", { head: true, count: "exact" })
    .eq("complaint_id", complaint.id);

  let recoveryVerified: boolean | null = null;
  if (recoverySecret) {
    const submittedRecoveryHash = sha256Hex(recoverySecret.toUpperCase());
    recoveryVerified = safeEqualHex(
      submittedRecoveryHash,
      complaint.recovery_secret_hash
    );
  }

  return NextResponse.json({
    found: true,
    caseCode: normalizedCaseCode,
    category: complaint.category,
    status: complaint.status ?? "submitted",
    encryptionAlgorithm: complaint.encryption_algorithm,
    createdAt: complaint.created_at,
    updatedAt: complaint.updated_at,
    retentionUntil: complaint.retention_until,
    evidenceCount: evidenceCount ?? 0,
    recoveryVerified,
  });
}
