import "server-only";
import { Redis } from "@upstash/redis";

export const DASHBOARD_CACHE_KEY = "awaaz:cache:committee:dashboard:v1";
export const AUTOSHRED_SCHEDULE_KEY = "awaaz:autoshred:schedule";
export const BACKGROUND_JOB_QUEUE_KEY = "awaaz:jobs:queue";

export interface BackgroundJob {
  id: string;
  type: "AUTO_SHRED_SCHEDULED" | "CACHE_INVALIDATED" | "AUDIT_VERIFICATION";
  complaintId?: string;
  createdAt: string;
  payload?: Record<string, unknown>;
}

let cachedRedis: Redis | null | undefined;

export function isRedisConfigured(): boolean {
  return Boolean(
    process.env.UPSTASH_REDIS_REST_URL?.trim() &&
      process.env.UPSTASH_REDIS_REST_TOKEN?.trim()
  );
}

/** Returns a singleton server-only Upstash Redis client when configured. */
export function getRedisClient(): Redis | null {
  if (cachedRedis !== undefined) {
    return cachedRedis;
  }

  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!url || !token) {
    cachedRedis = null;
    return null;
  }

  cachedRedis = new Redis({ url, token });
  return cachedRedis;
}

export async function verifyRedisConnection(): Promise<{
  configured: boolean;
  reachable: boolean;
  latencyMs: number | null;
  scheduledShredJobs: number;
  queuedBackgroundJobs: number;
  error: string | null;
}> {
  if (!isRedisConfigured()) {
    return {
      configured: false,
      reachable: false,
      latencyMs: null,
      scheduledShredJobs: 0,
      queuedBackgroundJobs: 0,
      error: "UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN is missing.",
    };
  }

  const redis = getRedisClient();
  if (!redis) {
    return {
      configured: false,
      reachable: false,
      latencyMs: null,
      scheduledShredJobs: 0,
      queuedBackgroundJobs: 0,
      error: "Unable to initialize Upstash Redis client.",
    };
  }

  const start = Date.now();
  try {
    await redis.ping();
    const [scheduledShredJobs, queuedBackgroundJobs] = await Promise.all([
      redis.zcard(AUTOSHRED_SCHEDULE_KEY),
      redis.llen(BACKGROUND_JOB_QUEUE_KEY),
    ]);
    return {
      configured: true,
      reachable: true,
      latencyMs: Date.now() - start,
      scheduledShredJobs,
      queuedBackgroundJobs,
      error: null,
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      latencyMs: Date.now() - start,
      scheduledShredJobs: 0,
      queuedBackgroundJobs: 0,
      error: err instanceof Error ? err.message : "Redis health check failed.",
    };
  }
}

export async function getCachedJson<T>(key: string): Promise<T | null> {
  const redis = getRedisClient();
  if (!redis) return null;
  try {
    const value = await redis.get<T>(key);
    return value ?? null;
  } catch {
    return null;
  }
}

export async function setCachedJson<T>(
  key: string,
  value: T,
  ttlSeconds: number
): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  try {
    await redis.set(key, value, { ex: ttlSeconds });
  } catch {
    // Non-fatal cache write failure.
  }
}

export async function invalidateDashboardCache(): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  try {
    await redis.del(DASHBOARD_CACHE_KEY);
  } catch {
    // Non-fatal cache invalidation failure.
  }
}

/** Schedules a complaint's expiration timestamp in the Redis Auto-Shred sorted set. */
export async function scheduleAutoShredJob(
  complaintId: string,
  retentionUntilIso: string
): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  const score = Date.parse(retentionUntilIso);
  if (!Number.isFinite(score)) return;
  try {
    await redis.zadd(AUTOSHRED_SCHEDULE_KEY, {
      score,
      member: complaintId,
    });
  } catch {
    // Worker also falls back to PostgreSQL retention_until <= now().
  }
}

export async function getDueAutoShredIds(
  nowMs = Date.now(),
  limit = 25
): Promise<string[]> {
  const redis = getRedisClient();
  if (!redis) return [];
  try {
    const members = await redis.zrange<string[]>(
      AUTOSHRED_SCHEDULE_KEY,
      0,
      nowMs,
      { byScore: true, offset: 0, count: limit }
    );
    return Array.isArray(members) ? members : [];
  } catch {
    return [];
  }
}

export async function removeAutoShredSchedule(
  complaintIds: string[]
): Promise<void> {
  const redis = getRedisClient();
  if (!redis || complaintIds.length === 0) return;
  try {
    await redis.zrem(AUTOSHRED_SCHEDULE_KEY, ...complaintIds);
  } catch {
    // Ignore transient schedule cleanup error.
  }
}

export async function enqueueBackgroundJob(
  job: Omit<BackgroundJob, "id" | "createdAt">
): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  const entry: BackgroundJob = {
    ...job,
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
  };
  try {
    await redis.lpush(BACKGROUND_JOB_QUEUE_KEY, JSON.stringify(entry));
    await redis.ltrim(BACKGROUND_JOB_QUEUE_KEY, 0, 199);
  } catch {
    // Non-fatal queue push error.
  }
}
