import crypto from "node:crypto";
import {
  combineShares2OfNBytes,
  decodeShamirShare,
  encodeShamirShare,
  splitSecret2OfNBytes,
} from "./shamir.ts";

export const ENCRYPTION_ALGORITHM = "AES-256-GCM";
export const REQUIRED_UNLOCK_APPROVALS = 2;

export interface CommitteeRecipientKey {
  memberId: string;
  publicKeyPem: string;
}

export interface EncryptedComplaintEnvelope {
  version: 1;
  algorithm: "AES-256-GCM";
  keyScheme: "SSS-2-OF-N+RSA-OAEP-256";
  iv: string;
  authTag: string;
  ciphertext: string;
  shares: Record<string, string>;
}

export interface EncryptedFileHeader {
  version: 1;
  algorithm: "AES-256-GCM";
  complaintId: string;
  fileId: string;
  iv: string;
  authTag: string;
  shares: Record<string, string>;
}

const FILE_MAGIC = Buffer.from("AWZ1", "ascii");

/**
 * Splits a secret buffer into N shares where any 2 distinct shares reconstruct
 * the secret and any single share reveals zero information.
 */
export function splitSecret2OfN(
  secret: Buffer,
  shareCount: number
): Array<{ x: number; y: Buffer }> {
  return splitSecret2OfNBytes(secret, shareCount).map((share) => ({
    x: share.x,
    y: Buffer.from(share.y),
  }));
}

/** Reconstructs the secret from at least 2 distinct Shamir shares over GF(256). */
export function combineShares2OfN(
  shares: Array<{ x: number; y: Buffer }>
): Buffer {
  return Buffer.from(combineShares2OfNBytes(shares));
}

function wrapDekForRecipients(
  dek: Buffer,
  recipients: CommitteeRecipientKey[]
): Record<string, string> {
  if (recipients.length < REQUIRED_UNLOCK_APPROVALS) {
    throw new Error(
      `At least ${REQUIRED_UNLOCK_APPROVALS} committee members with public keys are required.`
    );
  }

  const rawShares = splitSecret2OfN(dek, recipients.length);
  const wrapped: Record<string, string> = {};

  recipients.forEach((recipient, index) => {
    const sharePayload = Buffer.from(encodeShamirShare(rawShares[index]));
    const encryptedShare = crypto.publicEncrypt(
      {
        key: recipient.publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      sharePayload
    );
    wrapped[recipient.memberId] = encryptedShare.toString("base64");
  });

  return wrapped;
}

/** Server-side helper retained for unit/regression test compatibility. */
export function encryptComplaintPayload(
  payload: unknown,
  complaintId: string,
  recipients: CommitteeRecipientKey[]
): EncryptedComplaintEnvelope {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(Buffer.from(complaintId, "utf8"));

  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const shares = wrapDekForRecipients(dek, recipients);

  dek.fill(0);

  return {
    version: 1,
    algorithm: "AES-256-GCM",
    keyScheme: "SSS-2-OF-N+RSA-OAEP-256",
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    shares,
  };
}

function isStrictBase64WithByteLength(
  value: unknown,
  expectedLength: number | null
): boolean {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  const normalized = value.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+=*$/.test(normalized)) {
    return false;
  }
  const decoded = Buffer.from(normalized, "base64");
  if (decoded.length === 0) {
    return false;
  }
  if (expectedLength !== null && decoded.length !== expectedLength) {
    return false;
  }
  return true;
}

/** Validates a client-encrypted complaint envelope before storing it in `complaints`. */
export function validateEncryptedComplaintEnvelope(
  candidate: unknown,
  activeMemberIds: Set<string>
): { ok: true; envelope: EncryptedComplaintEnvelope } | { ok: false; error: string } {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return { ok: false, error: "Encrypted payload must be an object." };
  }

  const env = candidate as Record<string, unknown>;
  if (env.version !== 1) {
    return { ok: false, error: "Unsupported encrypted envelope version." };
  }
  if (env.algorithm !== "AES-256-GCM") {
    return { ok: false, error: "Encrypted envelope must use AES-256-GCM." };
  }
  if (env.keyScheme !== "SSS-2-OF-N+RSA-OAEP-256") {
    return {
      ok: false,
      error: "Encrypted envelope must use SSS-2-OF-N+RSA-OAEP-256.",
    };
  }
  if (!isStrictBase64WithByteLength(env.iv, 12)) {
    return { ok: false, error: "AES-GCM IV must be 12 random bytes (base64)." };
  }
  if (!isStrictBase64WithByteLength(env.authTag, 16)) {
    return {
      ok: false,
      error: "AES-GCM authTag must be 16 bytes (base64).",
    };
  }
  if (!isStrictBase64WithByteLength(env.ciphertext, null)) {
    return { ok: false, error: "Encrypted ciphertext must be non-empty base64." };
  }

  if (!env.shares || typeof env.shares !== "object" || Array.isArray(env.shares)) {
    return { ok: false, error: "Encrypted Shamir key shares are required." };
  }

  const sharesObj = env.shares as Record<string, unknown>;
  let validMemberShares = 0;
  const sanitizedShares: Record<string, string> = {};

  for (const [memberId, wrappedShare] of Object.entries(sharesObj)) {
    if (!activeMemberIds.has(memberId)) {
      continue;
    }
    if (!isStrictBase64WithByteLength(wrappedShare, 256)) {
      return {
        ok: false,
        error: `Wrapped RSA-OAEP share for member ${memberId} is invalid.`,
      };
    }
    sanitizedShares[memberId] = wrappedShare as string;
    validMemberShares += 1;
  }

  if (validMemberShares < REQUIRED_UNLOCK_APPROVALS) {
    return {
      ok: false,
      error: `At least ${REQUIRED_UNLOCK_APPROVALS} valid committee key shares are required.`,
    };
  }

  return {
    ok: true,
    envelope: {
      version: 1,
      algorithm: "AES-256-GCM",
      keyScheme: "SSS-2-OF-N+RSA-OAEP-256",
      iv: env.iv as string,
      authTag: env.authTag as string,
      ciphertext: env.ciphertext as string,
      shares: sanitizedShares,
    },
  };
}

/** Validates a client-encrypted `AWZ1` evidence blob without seeing raw bytes. */
export function validateEncryptedEvidenceBlob(
  blob: Buffer,
  expectedComplaintId: string,
  expectedFileId: string,
  activeMemberIds: Set<string>
): { ok: true; ciphertextHash: string } | { ok: false; error: string } {
  if (blob.length < 16) {
    return { ok: false, error: "Encrypted evidence blob is too short." };
  }
  if (!blob.subarray(0, 4).equals(FILE_MAGIC)) {
    return { ok: false, error: "Evidence blob missing AWZ1 encrypted header." };
  }

  const headerLen = blob.readUInt32BE(4);
  if (headerLen < 20 || headerLen > 65536 || 8 + headerLen >= blob.length) {
    return { ok: false, error: "Encrypted evidence header length is invalid." };
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(
      blob.subarray(8, 8 + headerLen).toString("utf8")
    ) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "Encrypted evidence header is malformed JSON." };
  }

  if (
    header.version !== 1 ||
    header.algorithm !== "AES-256-GCM" ||
    header.complaintId !== expectedComplaintId ||
    header.fileId !== expectedFileId
  ) {
    return {
      ok: false,
      error: "Encrypted evidence header metadata mismatch.",
    };
  }
  if (
    !isStrictBase64WithByteLength(header.iv, 12) ||
    !isStrictBase64WithByteLength(header.authTag, 16)
  ) {
    return { ok: false, error: "Encrypted evidence IV or authTag is invalid." };
  }

  if (
    !header.shares ||
    typeof header.shares !== "object" ||
    Array.isArray(header.shares)
  ) {
    return { ok: false, error: "Encrypted evidence shares are missing." };
  }

  let validShares = 0;
  for (const [memberId, shareVal] of Object.entries(
    header.shares as Record<string, unknown>
  )) {
    if (
      activeMemberIds.has(memberId) &&
      isStrictBase64WithByteLength(shareVal, 256)
    ) {
      validShares += 1;
    }
  }

  if (validShares < REQUIRED_UNLOCK_APPROVALS) {
    return {
      ok: false,
      error: `Encrypted evidence requires at least ${REQUIRED_UNLOCK_APPROVALS} committee shares.`,
    };
  }

  return { ok: true, ciphertextHash: sha256Hex(blob) };
}

/** Uses a committee member's RSA private key to unwrap their share from an envelope. */
export function unwrapMemberShareWithPrivateKey(
  encryptedShareBase64: string,
  privateKeyPem: string
): Buffer {
  const shareCipher = Buffer.from(encryptedShareBase64, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    shareCipher
  );

  if (decrypted.length !== 33) {
    throw new Error("Decrypted share format is invalid.");
  }
  return decrypted;
}

/** Wraps/unwraps an approved member's share for storage in unlock_approvals using AES-256-GCM. */
export function protectStoredShare(
  shareBytes: Buffer,
  complaintId: string,
  memberId: string,
  serverSecret: string
): string {
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(serverSecret, "utf8"),
      Buffer.from("awaaz-unlock-approval-v1", "utf8"),
      Buffer.from(`${complaintId}:${memberId}`, "utf8"),
      32
    )
  );
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`${complaintId}:${memberId}`, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(shareBytes), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return JSON.stringify({
    v: 1,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  });
}

export function unprotectStoredShare(
  storedJson: string,
  complaintId: string,
  memberId: string,
  serverSecret: string
): Buffer {
  const parsed = JSON.parse(storedJson) as {
    v: number;
    iv: string;
    authTag: string;
    ciphertext: string;
  };
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(serverSecret, "utf8"),
      Buffer.from("awaaz-unlock-approval-v1", "utf8"),
      Buffer.from(`${complaintId}:${memberId}`, "utf8"),
      32
    )
  );
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parsed.iv, "base64")
  );
  decipher.setAAD(Buffer.from(`${complaintId}:${memberId}`, "utf8"));
  decipher.setAuthTag(Buffer.from(parsed.authTag, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(parsed.ciphertext, "base64")),
    decipher.final(),
  ]);
}

/** Reconstructs the complaint DEK from >=2 unwrapped shares and decrypts the payload. */
export function decryptComplaintEnvelope<T = Record<string, unknown>>(
  envelope: EncryptedComplaintEnvelope,
  complaintId: string,
  rawShareBuffers: Buffer[]
): T {
  const shares = rawShareBuffers.map((buf) => {
    const decoded = decodeShamirShare(buf);
    return { x: decoded.x, y: Buffer.from(decoded.y) };
  });
  const dek = combineShares2OfN(shares);

  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      dek,
      Buffer.from(envelope.iv, "base64")
    );
    decipher.setAAD(Buffer.from(complaintId, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));

    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);

    return JSON.parse(plaintext.toString("utf8")) as T;
  } finally {
    dek.fill(0);
  }
}

/** Server-side evidence helper retained for unit/regression test compatibility. */
export function encryptEvidenceBuffer(
  fileBytes: Buffer,
  complaintId: string,
  fileId: string,
  recipients: CommitteeRecipientKey[]
): { encryptedBlob: Buffer; ciphertextHash: string } {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(`${complaintId}:${fileId}`, "utf8");

  const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(fileBytes), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const shares = wrapDekForRecipients(dek, recipients);

  dek.fill(0);

  const header: EncryptedFileHeader = {
    version: 1,
    algorithm: "AES-256-GCM",
    complaintId,
    fileId,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    shares,
  };

  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  const headerLen = Buffer.alloc(4);
  headerLen.writeUInt32BE(headerBytes.length, 0);

  const encryptedBlob = Buffer.concat([
    FILE_MAGIC,
    headerLen,
    headerBytes,
    ciphertext,
  ]);
  const ciphertextHash = sha256Hex(encryptedBlob);

  return { encryptedBlob, ciphertextHash };
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/** Generates a non-sequential case code and separate recovery secret for anonymous tracking. */
export function generateTrackingCredentials(): {
  caseCode: string;
  recoverySecret: string;
  caseCodeHash: string;
  recoverySecretHash: string;
} {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const randomChars = (len: number) => {
    const bytes = crypto.randomBytes(len);
    let out = "";
    for (let i = 0; i < len; i++) {
      out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
  };

  const caseCode = `AWZ-${randomChars(4)}-${randomChars(4)}-${randomChars(4)}`;
  const recoverySecret = `${randomChars(6)}-${randomChars(6)}`;

  return {
    caseCode,
    recoverySecret,
    caseCodeHash: sha256Hex(caseCode),
    recoverySecretHash: sha256Hex(recoverySecret),
  };
}

export function isStrictRsa2048CiphertextBase64(value: unknown): value is string {
  return isStrictBase64WithByteLength(value, 256);
}

/** Validates that a PEM string is an RSA public key suitable for RSA-OAEP (>= 2048 bits). */
export function isValidRsaPublicKeyPem(pem: string): boolean {
  try {
    const keyObj = crypto.createPublicKey(pem);
    if (keyObj.asymmetricKeyType !== "rsa") {
      return false;
    }
    const modulusLength = keyObj.asymmetricKeyDetails?.modulusLength ?? 0;
    return modulusLength >= 2048;
  } catch {
    return false;
  }
}
