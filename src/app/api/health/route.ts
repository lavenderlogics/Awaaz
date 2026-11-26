import { NextResponse } from "next/server";
import { verifyRedisConnection } from "@/lib/redis/client";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { verifySupabaseConnection } from "@/lib/supabase/health";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store",
} as const;

/**
 * Health check endpoint.
 * - Unauthenticated or non-admin callers receive ONLY `{ status: "ok" | "degraded" }`.
 * - Authenticated committee admins receive sanitized boolean subsystem checks
 *   without table names, queue counts, key formats, or raw errors.
 */
export async function GET(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "health"),
    { limit: 30, windowMs: 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many health check requests. Please try again shortly." },
      { status: 429, headers: NO_STORE_HEADERS }
    );
  }

  const [report, auth] = await Promise.all([
    verifySupabaseConnection(),
    requireCommitteeMember(),
  ]);

  const healthy = report.authReachable;
  const httpStatus = healthy ? 200 : 503;

  if (!auth.ok || auth.member.role !== "admin") {
    return NextResponse.json(
      { status: healthy ? "ok" : "degraded" },
      { status: httpStatus, headers: NO_STORE_HEADERS }
    );
  }

  const redis = await verifyRedisConnection();
  const databaseReady =
    report.tablesVerified !== null &&
    Object.values(report.tablesVerified).every(Boolean);

  return NextResponse.json(
    {
      status: healthy ? "ok" : "degraded",
      scope: "committee-admin",
      checks: {
        auth: report.authReachable,
        database: databaseReady,
        storage: report.storageBucketVerified === true,
        redis: redis.reachable,
      },
      redisLatencyMs: redis.latencyMs,
    },
    { status: httpStatus, headers: NO_STORE_HEADERS }
  );
}
