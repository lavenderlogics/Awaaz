import { NextResponse } from "next/server";
import { checkRateLimit, getRateLimitClientKey } from "@/lib/security/rate-limit";
import { verifySupabaseConnection } from "@/lib/supabase/health";

export async function GET(request: Request) {
  const rate = checkRateLimit(
    getRateLimitClientKey(request.headers, "health"),
    { limit: 30, windowMs: 60_000 }
  );

  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Too many health check requests. Please try again shortly." },
      { status: 429 }
    );
  }

  const report = await verifySupabaseConnection();
  const status = report.authReachable ? 200 : 503;

  return NextResponse.json(
    {
      status: report.authReachable ? "ok" : "degraded",
      supabase: report,
    },
    { status }
  );
}
