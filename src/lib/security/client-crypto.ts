/**
 * Browser-side Web Crypto API encryption module for Awaaz (C1).
 * Uses `globalThis.crypto.subtle` and `Uint8Array` Shamir Secret Sharing so
 * plaintext complaints, raw evidence files, and AES keys never leave the browser.
 */

import { encodeShamirShare, splitSecret2OfNBytes } from "./shamir.ts";

export interface PublicCommitteeRecipient {
  memberId: string;
  publicKey: string;
}

export interface BrowserEncryptedComplaintEnvelope {
  version: 1;
  algorithm: "AES-256-GCM";
  keyScheme: "SSS-2-OF-N+RSA-OAEP-256";
  iv: string;
  authTag: string;
  ciphertext: string;
  shares: Record<string, string>;
}

export interface BrowserEncryptedEvidenceResult {
  fileId: string;
  mimeType: string;
  encryptedBytes: Uint8Array;
  ciphertextHash: string;
}

const FILE_MAGIC_BYTES = new Uint8Array([0x41, 0x57, 0x5a, 0x31]); // "AWZ1"

function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    throw new Error(
      "Web Crypto API (SubtleCrypto) is unavailable in this browser context."
    );
  }
  return globalThis.crypto;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function pemSpkiToDerBytes(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  if (!stripped) {
    throw new Error("Invalid RSA SPKI public key PEM.");
  }
  return base64ToBytes(stripped);
}

/** Imports a PEM-encoded SPKI RSA public key for RSA-OAEP (SHA-256) wrapping. */
export async function importRsaOaepPublicKey(pem: string): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const der = pemSpkiToDerBytes(pem);
  return webCrypto.subtle.importKey(
    "spki",
    toArrayBuffer(der),
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    false,
    ["encrypt"]
  );
}

async function wrapDekSharesInBrowser(
  rawDek: Uint8Array,
  recipients: PublicCommitteeRecipient[]
): Promise<Record<string, string>> {
  if (recipients.length < 2) {
    throw new Error(
      "At least 2 active committee members with valid public keys are required."
    );
  }

  const webCrypto = getWebCrypto();
  const rawShares = splitSecret2OfNBytes(rawDek, recipients.length);
  const wrappedShares: Record<string, string> = {};

  for (let i = 0; i < recipients.length; i++) {
    const recipient = recipients[i];
    const encodedShare = encodeShamirShare(rawShares[i]);
    try {
      const rsaKey = await importRsaOaepPublicKey(recipient.publicKey);
      const encryptedShareBuf = await webCrypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKey,
        toArrayBuffer(encodedShare)
      );
      wrappedShares[recipient.memberId] = bytesToBase64(
        new Uint8Array(encryptedShareBuf)
      );
    } finally {
      encodedShare.fill(0);
      rawShares[i].y.fill(0);
    }
  }

  return wrappedShares;
}

async function encryptAes256GcmInBrowser(
  plaintext: Uint8Array,
  aadText: string
): Promise<{
  rawDek: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  authTag: Uint8Array;
}> {
  const webCrypto = getWebCrypto();
  const rawDek = new Uint8Array(32);
  const iv = new Uint8Array(12);
  webCrypto.getRandomValues(rawDek);
  webCrypto.getRandomValues(iv);

  const aesKey = await webCrypto.subtle.importKey(
    "raw",
    toArrayBuffer(rawDek),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const aadBytes = new TextEncoder().encode(aadText);
  const encryptedBuf = await webCrypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aadBytes),
      tagLength: 128,
    },
    aesKey,
    toArrayBuffer(plaintext)
  );

  const combined = new Uint8Array(encryptedBuf);
  if (combined.length < 16) {
    rawDek.fill(0);
    throw new Error("AES-GCM produced invalid output.");
  }

  const splitIdx = combined.length - 16;
  return {
    rawDek,
    iv,
    ciphertext: combined.subarray(0, splitIdx),
    authTag: combined.subarray(splitIdx),
  };
}

/**
 * Encrypts complaint payload in the browser using AES-256-GCM (AAD = complaintId)
 * and splits the DEK with 2-of-N Shamir + RSA-OAEP-256 public-key wrapping.
 */
export async function encryptComplaintInBrowser(params: {
  complaintId: string;
  payload: unknown;
  recipients: PublicCommitteeRecipient[];
}): Promise<BrowserEncryptedComplaintEnvelope> {
  const plaintext = new TextEncoder().encode(JSON.stringify(params.payload));
  const { rawDek, iv, ciphertext, authTag } = await encryptAes256GcmInBrowser(
    plaintext,
    params.complaintId
  );

  try {
    const shares = await wrapDekSharesInBrowser(rawDek, params.recipients);
    return {
      version: 1,
      algorithm: "AES-256-GCM",
      keyScheme: "SSS-2-OF-N+RSA-OAEP-256",
      iv: bytesToBase64(iv),
      authTag: bytesToBase64(authTag),
      ciphertext: bytesToBase64(ciphertext),
      shares,
    };
  } finally {
    rawDek.fill(0);
  }
}

/**
 * Encrypts an evidence file in the browser into the self-describing `AWZ1`
 * AES-256-GCM envelope (AAD = `${complaintId}:${fileId}`) with a unique IV & DEK.
 */
export async function encryptEvidenceBytesInBrowser(params: {
  fileBytes: Uint8Array;
  mimeType: string;
  complaintId: string;
  fileId: string;
  recipients: PublicCommitteeRecipient[];
}): Promise<BrowserEncryptedEvidenceResult> {
  const webCrypto = getWebCrypto();
  const aadText = `${params.complaintId}:${params.fileId}`;
  const { rawDek, iv, ciphertext, authTag } = await encryptAes256GcmInBrowser(
    params.fileBytes,
    aadText
  );

  let shares: Record<string, string>;
  try {
    shares = await wrapDekSharesInBrowser(rawDek, params.recipients);
  } finally {
    rawDek.fill(0);
  }

  const headerJson = JSON.stringify({
    version: 1,
    algorithm: "AES-256-GCM",
    complaintId: params.complaintId,
    fileId: params.fileId,
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(authTag),
    shares,
  });

  const headerBytes = new TextEncoder().encode(headerJson);
  const headerLenBytes = new Uint8Array(4);
  new DataView(headerLenBytes.buffer).setUint32(0, headerBytes.length, false);

  const encryptedBytes = new Uint8Array(
    FILE_MAGIC_BYTES.length +
      headerLenBytes.length +
      headerBytes.length +
      ciphertext.length
  );

  let offset = 0;
  encryptedBytes.set(FILE_MAGIC_BYTES, offset);
  offset += FILE_MAGIC_BYTES.length;
  encryptedBytes.set(headerLenBytes, offset);
  offset += headerLenBytes.length;
  encryptedBytes.set(headerBytes, offset);
  offset += headerBytes.length;
  encryptedBytes.set(ciphertext, offset);

  const digestBuf = await webCrypto.subtle.digest(
    "SHA-256",
    toArrayBuffer(encryptedBytes)
  );
  const ciphertextHash = Array.from(new Uint8Array(digestBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    fileId: params.fileId,
    mimeType: params.mimeType,
    encryptedBytes,
    ciphertextHash,
  };
}
