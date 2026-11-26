import { NextResponse } from "next/server";
import { runAutoShredCycle } from "@/lib/security/auto-shred";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { createAdminClient } from "@/lib/supabase/admin";

/** Lists recent tamper-evident Auto-Shred deletion receipts for committee officers. */
export async function GET() {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  const admin = createAdminClient();
  const { data, error } = await admin
    .from("audit_logs")
    .select("id, complaint_id, event_details, entry_hash, created_at")
    .eq("event_type", "EVIDENCE_AUTO_SHREDDED")
    .order("id", { ascending: false })
    .limit(50);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json(
    { receipts: data ?? [] },
    { headers: { "Cache-Control": "no-store" } }
  );
}

/** Admin-only manual Auto-Shred trigger for enforcing expired retention windows immediately. */
export async function POST(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "committee-auto-shred"),
    { limit: 10, windowMs: 10 * 60_000 }
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many Auto-Shred runs requested." },
      { status: 429 }
    );
  }

  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }
  if (auth.member.role !== "admin") {
    return NextResponse.json(
      { error: "Only committee admins may manually trigger Auto-Shred sweeps." },
      { status: 403 }
    );
  }

  const result = await runAutoShredCycle({ actorMemberId: auth.member.user_id });
  return NextResponse.json(result, {
    status: result.errors.length > 0 ? 207 : 200,
  });
}
