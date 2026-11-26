import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { runAutoShredCycle } from "@/lib/security/auto-shred";

function isAuthorizedCronRequest(request: Request): boolean {
  const secret = process.env.CRON_SECRET?.trim();
  if (!secret) {
    return false;
  }
  const authHeader = request.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";
  if (!token || token.length !== secret.length) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(token, "utf8"),
    Buffer.from(secret, "utf8")
  );
}

/**
 * Scheduled Auto-Shred cron endpoint (Vercel Cron / Upstash QStash).
 * Authenticated strictly via bearer CRON_SECRET.
 */
export async function GET(request: Request) {
  if (!isAuthorizedCronRequest(request)) {
    return NextResponse.json({ error: "Unauthorized cron trigger." }, { status: 401 });
  }

  const result = await runAutoShredCycle({ actorMemberId: null });
  return NextResponse.json(result, {
    status: result.errors.length > 0 ? 207 : 200,
  });
}

export async function POST(request: Request) {
  return GET(request);
}
