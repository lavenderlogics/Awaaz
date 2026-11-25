import "server-only";

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
}

interface BucketEntry {
  count: number;
  resetAt: number;
}

const memoryStore = new Map<string, BucketEntry>();

/**
 * Lightweight in-memory sliding-window rate limiter.
 * Structured behind an explicit interface so Redis can replace memoryStore later.
 */
export function checkRateLimit(
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
    };
  }

  if (existing.count >= options.limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: existing.resetAt,
    };
  }

  existing.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, options.limit - existing.count),
    resetAt: existing.resetAt,
  };
}

/** Extracts a best-effort client IP key without storing raw IPs in databases. */
export function getRateLimitClientKey(
  headers: Headers,
  scope: string
): string {
  const forwarded = headers.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0]?.trim() || headers.get("x-real-ip") || "unknown";
  return `${scope}:${ip}`;
}
