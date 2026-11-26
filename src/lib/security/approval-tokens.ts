import "server-only";
import crypto from "node:crypto";
import { getRedisClient } from "@/lib/redis/client";

export type ApprovalAction = "approve_member" | "approve_admin" | "reject";

export interface ApprovalTokenPayload {
  jti: string;
  applicantUserId: string;
  applicantEmail: string;
  applicantName: string;
  action: ApprovalAction;
  adminMemberId: string;
  exp: number;
}

const APPROVAL_TTL_SECONDS = 48 * 60 * 60; // 48 hours

function getSigningSecret(): string {
  const secret = (
    process.env.ADMIN_APPROVAL_SECRET ?? process.env.CRON_SECRET
  )?.trim();
  if (!secret || secret.length < 16) {
    throw new Error(
      "Missing ADMIN_APPROVAL_SECRET or CRON_SECRET for signing approval links."
    );
  }
  return secret;
}

function signHmac(encodedPayload: string, secret: string): string {
  return crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");
}

function jtiRedisKey(jti: string): string {
  return `awaaz:approval:jti:${jti}`;
}

/**
 * Generates an HMAC-SHA256 signed, 48h, single-use admin approval token
 * backed by Upstash Redis `jti` replay protection when configured.
 */
export async function createAdminApprovalToken(input: {
  applicantUserId: string;
  applicantEmail: string;
  applicantName: string;
  action: ApprovalAction;
  adminMemberId: string;
}): Promise<string> {
  const secret = getSigningSecret();
  const payload: ApprovalTokenPayload = {
    jti: crypto.randomUUID(),
    applicantUserId: input.applicantUserId,
    applicantEmail: input.applicantEmail,
    applicantName: input.applicantName,
    action: input.action,
    adminMemberId: input.adminMemberId,
    exp: Math.floor(Date.now() / 1000) + APPROVAL_TTL_SECONDS,
  };

  const redis = getRedisClient();
  if (redis) {
    await redis.set(jtiRedisKey(payload.jti), "pending", {
      ex: APPROVAL_TTL_SECONDS,
    });
  }

  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  const sig = signHmac(encoded, secret);
  return `${encoded}.${sig}`;
}

function verifySignatureAndParse(token: string): ApprovalTokenPayload | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  if (!encoded || !sig) return null;

  let expectedSig: string;
  try {
    expectedSig = signHmac(encoded, getSigningSecret());
  } catch {
    return null;
  }

  const sigBuf = Buffer.from(sig, "utf8");
  const expectedBuf = Buffer.from(expectedSig, "utf8");
  if (
    sigBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(sigBuf, expectedBuf)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    ) as ApprovalTokenPayload;
    if (
      !parsed ||
      typeof parsed.jti !== "string" ||
      typeof parsed.applicantUserId !== "string" ||
      typeof parsed.applicantEmail !== "string" ||
      typeof parsed.adminMemberId !== "string" ||
      typeof parsed.exp !== "number"
    ) {
      return null;
    }
    if (parsed.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    if (
      parsed.action !== "approve_member" &&
      parsed.action !== "approve_admin" &&
      parsed.action !== "reject"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/** Validates an approval token without consuming it (safe against email link pre-fetchers). */
export async function inspectAdminApprovalToken(
  token: string
): Promise<ApprovalTokenPayload | null> {
  const parsed = verifySignatureAndParse(token);
  if (!parsed) return null;

  const redis = getRedisClient();
  if (redis) {
    const status = await redis.get<string>(jtiRedisKey(parsed.jti));
    if (status !== "pending") {
      return null;
    }
  }

  return parsed;
}

/** Validates and atomically consumes a single-use approval token on POST confirmation. */
export async function consumeAdminApprovalToken(
  token: string
): Promise<ApprovalTokenPayload | null> {
  const parsed = verifySignatureAndParse(token);
  if (!parsed) return null;

  const redis = getRedisClient();
  if (redis) {
    const deletedCount = await redis.del(jtiRedisKey(parsed.jti));
    if (deletedCount !== 1) {
      return null;
    }
  }

  return parsed;
}
