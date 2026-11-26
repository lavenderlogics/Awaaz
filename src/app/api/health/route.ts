import { NextResponse } from "next/server";
import { verifyRedisConnection } from "@/lib/redis/client";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { verifySupabaseConnection } from "@/lib/supabase/health";

export async function GET(request: Request) {
  const rate = await checkRateLimit(
    getRateLimitClientKey(request.headers, "health"),
    { limit: 30, windowMs: 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many health check requests. Please try again shortly." },
      { status: 429 }
    );
  }

  const [report, redis] = await Promise.all([
    verifySupabaseConnection(),
    verifyRedisConnection(),
  ]);
  const status = report.authReachable ? 200 : 503;

  return NextResponse.json(
    {
      status: report.authReachable ? "ok" : "degraded",
      rateLimitBackend: rate.backend,
      supabase: report,
      redis,
    },
    { status }
  );
}
