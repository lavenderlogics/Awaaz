import crypto from "node:crypto";

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

// GF(256) arithmetic with AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
function gfMul(a: number, b: number): number {
  let res = 0;
  let aa = a;
  let bb = b;
  for (let i = 0; i < 8; i++) {
    if ((bb & 1) !== 0) {
      res ^= aa;
    }
    const carry = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (carry !== 0) {
      aa ^= 0x1b;
    }
    bb >>= 1;
  }
  return res;
}

function gfPow(base: number, exp: number): number {
  let result = 1;
  let b = base;
  let e = exp;
  while (e > 0) {
    if ((e & 1) !== 0) {
      result = gfMul(result, b);
    }
    b = gfMul(b, b);
    e >>= 1;
  }
  return result;
}

function gfInv(a: number): number {
  if (a === 0) {
    throw new Error("Cannot invert zero in GF(256).");
  }
  return gfPow(a, 254);
}

/**
 * Splits a secret buffer into N shares where any 2 distinct shares reconstruct
 * the secret and any single share reveals zero information.
 */
export function splitSecret2OfN(
  secret: Buffer,
  shareCount: number
): Array<{ x: number; y: Buffer }> {
  if (shareCount < 2 || shareCount > 250) {
    throw new Error("Shamir 2-of-N requires between 2 and 250 recipients.");
  }

  const slope = crypto.randomBytes(secret.length);
  const shares: Array<{ x: number; y: Buffer }> = [];

  for (let i = 1; i <= shareCount; i++) {
    const y = Buffer.alloc(secret.length);
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      y[byteIdx] = secret[byteIdx] ^ gfMul(slope[byteIdx], i);
    }
    shares.push({ x: i, y });
  }

  return shares;
}

/** Reconstructs the secret from at least 2 distinct Shamir shares over GF(256). */
export function combineShares2OfN(
  shares: Array<{ x: number; y: Buffer }>
): Buffer {
  if (shares.length < 2) {
    throw new Error("At least 2 distinct shares are required to reconstruct DEK.");
  }

  const [s1, s2] = shares;
  if (s1.x === s2.x) {
    throw new Error("Shares must belong to distinct participants.");
  }
  if (s1.y.length !== s2.y.length) {
    throw new Error("Share lengths do not match.");
  }

  // Evaluate f(0) via Lagrange interpolation over GF(256)
  // f(0) = y1 * (x2 / (x1 ^ x2)) ^ y2 * (x1 / (x1 ^ x2))
  const denomInv = gfInv(s1.x ^ s2.x);
  const l1 = gfMul(s2.x, denomInv);
  const l2 = gfMul(s1.x, denomInv);

  const secret = Buffer.alloc(s1.y.length);
  for (let i = 0; i < secret.length; i++) {
    secret[i] = gfMul(s1.y[i], l1) ^ gfMul(s2.y[i], l2);
  }
  return secret;
}

function encodeShare(share: { x: number; y: Buffer }): Buffer {
  return Buffer.concat([Buffer.from([share.x]), share.y]);
}

function decodeShare(buf: Buffer): { x: number; y: Buffer } {
  if (buf.length !== 33) {
    throw new Error("Invalid key share length.");
  }
  return { x: buf[0], y: buf.subarray(1) };
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
    const sharePayload = encodeShare(rawShares[index]);
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

/** Encrypts a JSON-serializable complaint payload using AES-256-GCM + 2-of-N RSA-OAEP. */
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
  const shares = rawShareBuffers.map(decodeShare);
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

/** Encrypts an evidence file buffer into a self-describing AES-256-GCM envelope. */
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

export function isValidRsaPublicKeyPem(pem: string): boolean {
  try {
    const keyObj = crypto.createPublicKey(pem);
    return keyObj.asymmetricKeyType === "rsa";
  } catch {
    return false;
  }
}
