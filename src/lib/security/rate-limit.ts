import "server-only";
import { getRedisClient } from "@/lib/redis/client";

export interface RateLimitOptions {
  /** Maximum requests allowed within the time window. */
  limit: number;
  /** Time window duration in milliseconds. */
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  backend: "redis" | "memory";
}

interface BucketEntry {
  count: number;
  resetAt: number;
}

const memoryStore = new Map<string, BucketEntry>();

function checkMemoryRateLimit(
  key: string,
  options: RateLimitOptions
): RateLimitResult {
  const now = Date.now();
  const existing = memoryStore.get(key);

  if (!existing || existing.resetAt <= now) {
    const resetAt = now + options.windowMs;
    memoryStore.set(key, { count: 1, resetAt });
    return {
      allowed: true,
      remaining: Math.max(0, options.limit - 1),
      resetAt,
      backend: "memory",
    };
  }

  if (existing.count >= options.limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: existing.resetAt,
      backend: "memory",
    };
  }

  existing.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, options.limit - existing.count),
    resetAt: existing.resetAt,
    backend: "memory",
  };
}

/**
 * Distributed Upstash Redis rate limiter backed by atomic INCR + PEXPIRE,
 * falling back cleanly to in-memory limiting when Redis is not configured.
 */
export async function checkRateLimit(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const redis = getRedisClient();
  if (!redis) {
    return checkMemoryRateLimit(key, options);
  }

  const redisKey = `awaaz:rl:${key}`;
  try {
    const count = await redis.incr(redisKey);
    let ttlMs = await redis.pttl(redisKey);

    if (count === 1 || ttlMs < 0) {
      await redis.pexpire(redisKey, options.windowMs);
      ttlMs = options.windowMs;
    }

    const resetAt = Date.now() + Math.max(ttlMs, 0);
    return {
      allowed: count <= options.limit,
      remaining: Math.max(0, options.limit - count),
      resetAt,
      backend: "redis",
    };
  } catch {
    return checkMemoryRateLimit(key, options);
  }
}

/** Extracts a best-effort client IP key without storing raw IPs in databases. */
export function getRateLimitClientKey(
  headers: Headers,
  scope: string
): string {
  const forwarded = headers.get("x-forwarded-for");
  const ip =
    forwarded?.split(",")[0]?.trim() || headers.get("x-real-ip") || "unknown";
  return `${scope}:${ip}`;
}
