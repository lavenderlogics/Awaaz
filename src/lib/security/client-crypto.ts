/**
 * Browser-side Web Crypto API encryption & committee decryption module for Awaaz (C1 + C2).
 * Uses `globalThis.crypto.subtle` and `Uint8Array` Shamir Secret Sharing so
 * plaintext complaints, raw evidence files, private keys, plaintext shares, and AES keys
 * never leave the browser.
 */

import {
  combineShares2OfNBytes,
  decodeShamirShare,
  encodeShamirShare,
  splitSecret2OfNBytes,
} from "./shamir.ts";

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

export interface BrowserDecryptableEnvelope {
  version: 1;
  algorithm: "AES-256-GCM";
  keyScheme: "SSS-2-OF-N+RSA-OAEP-256";
  iv: string;
  authTag: string;
  ciphertext: string;
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

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
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

function pemToDerBytes(pem: string, label: string): Uint8Array {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const stripped = pem.replace(begin, "").replace(end, "").replace(/\s+/g, "");
  if (!stripped || !pem.includes(begin) || !pem.includes(end)) {
    throw new Error(`Invalid ${label} PEM format.`);
  }
  return base64ToBytes(stripped);
}

/** Formats raw DER bytes as a PEM string. */
export function derToPem(buffer: ArrayBuffer, label: string): string {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

/** Imports a PEM-encoded SPKI RSA public key for RSA-OAEP (SHA-256) encryption. */
export async function importRsaOaepPublicKey(pem: string): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const der = pemToDerBytes(pem, "PUBLIC KEY");
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

/**
 * Imports a PKCS#8 RSA private key PEM as a non-extractable RSA-OAEP (SHA-256)
 * CryptoKey inside the browser and wipes temporary DER bytes from memory.
 */
export async function importRsaOaepPrivateKeyNonExtractable(
  pkcs8Pem: string
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const der = pemToDerBytes(pkcs8Pem, "PRIVATE KEY");
  try {
    return await webCrypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(der),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false,
      ["decrypt"]
    );
  } finally {
    der.fill(0);
  }
}

/**
 * Verifies locally inside the browser that a private CryptoKey matches a
 * registered SPKI public key PEM using a challenge-response RSA-OAEP test.
 */
export async function verifyPrivateKeyMatchesPublicKeyInBrowser(
  privateKey: CryptoKey,
  expectedPublicKeyPem: string
): Promise<boolean> {
  const webCrypto = getWebCrypto();
  const challenge = new Uint8Array(16);
  webCrypto.getRandomValues(challenge);

  try {
    const publicKey = await importRsaOaepPublicKey(expectedPublicKeyPem);
    const encrypted = await webCrypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      toArrayBuffer(challenge)
    );
    const decrypted = new Uint8Array(
      await webCrypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encrypted
      )
    );
    if (decrypted.length !== challenge.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < challenge.length; i++) {
      diff |= decrypted[i] ^ challenge[i];
    }
    return diff === 0;
  } catch {
    return false;
  }
}

/** Decrypts a 33-byte wrapped Shamir share inside the browser using a local private CryptoKey. */
export async function unwrapShareInBrowser(
  encryptedShareBase64: string,
  privateKey: CryptoKey
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const cipherBytes = base64ToBytes(encryptedShareBase64);
  const plainBuf = await webCrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    toArrayBuffer(cipherBytes)
  );
  const shareBytes = new Uint8Array(plainBuf);
  if (shareBytes.length !== 33) {
    shareBytes.fill(0);
    throw new Error("Decrypted share format is invalid.");
  }
  return shareBytes;
}

/** Re-encrypts a 33-byte Shamir share for an intended committee recipient's RSA-OAEP public key. */
export async function wrapShareForRecipientInBrowser(
  rawShareBytes: Uint8Array,
  recipientPublicKeyPem: string
): Promise<string> {
  if (rawShareBytes.length !== 33) {
    throw new Error("Shamir share must be 33 bytes.");
  }
  const webCrypto = getWebCrypto();
  const recipientKey = await importRsaOaepPublicKey(recipientPublicKeyPem);
  const encryptedBuf = await webCrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientKey,
    toArrayBuffer(rawShareBytes)
  );
  return bytesToBase64(new Uint8Array(encryptedBuf));
}

/**
 * Member A workflow (C2 Steps B & C):
 * Decrypts Member A's own complaint share locally with A's private CryptoKey,
 * re-encrypts it with Member B's RSA-OAEP public key, and zeroes plaintext share bytes.
 */
export async function forwardShareInBrowser(params: {
  myEncryptedShareBase64: string;
  myPrivateKey: CryptoKey;
  recipientPublicKeyPem: string;
}): Promise<string> {
  const rawShare = await unwrapShareInBrowser(
    params.myEncryptedShareBase64,
    params.myPrivateKey
  );
  try {
    return await wrapShareForRecipientInBrowser(
      rawShare,
      params.recipientPublicKeyPem
    );
  } finally {
    rawShare.fill(0);
  }
}

/**
 * Member B workflow (C2 Step D):
 * Decrypts Member B's own wrapped share and >=1 forwarded share locally using B's
 * private CryptoKey, reconstructs the 32-byte AES-256 key via GF(256) Shamir,
 * and decrypts the AES-256-GCM complaint envelope entirely in browser memory.
 */
export async function reconstructAndDecryptComplaintInBrowser<
  T = Record<string, unknown>,
>(params: {
  complaintId: string;
  envelope: BrowserDecryptableEnvelope;
  myEncryptedShareBase64: string;
  forwardedEncryptedSharesBase64: string[];
  myPrivateKey: CryptoKey;
}): Promise<{ payload: T; reconstructedKeyHexLength: number }> {
  if (params.forwardedEncryptedSharesBase64.length < 1) {
    throw new Error(
      "At least 1 forwarded share from another committee member is required."
    );
  }

  const webCrypto = getWebCrypto();
  const decryptedShareBuffers: Uint8Array[] = [];

  try {
    const myShareBytes = await unwrapShareInBrowser(
      params.myEncryptedShareBase64,
      params.myPrivateKey
    );
    decryptedShareBuffers.push(myShareBytes);

    let paired = false;
    for (const fwdShareB64 of params.forwardedEncryptedSharesBase64) {
      try {
        const fwdShareBytes = await unwrapShareInBrowser(
          fwdShareB64,
          params.myPrivateKey
        );
        const sMe = decodeShamirShare(myShareBytes);
        const sFwd = decodeShamirShare(fwdShareBytes);
        if (sMe.x !== sFwd.x) {
          decryptedShareBuffers.push(fwdShareBytes);
          paired = true;
          break;
        }
        fwdShareBytes.fill(0);
      } catch {
        continue;
      }
    }

    if (!paired || decryptedShareBuffers.length < 2) {
      throw new Error(
        "No valid forwarded share from a distinct committee member could be decrypted with your private key."
      );
    }

    const decodedShares = decryptedShareBuffers.map(decodeShamirShare);
    const rawDek = combineShares2OfNBytes(decodedShares);

    try {
      const aesKey = await webCrypto.subtle.importKey(
        "raw",
        toArrayBuffer(rawDek),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      const ivBytes = base64ToBytes(params.envelope.iv);
      const cipherBytes = base64ToBytes(params.envelope.ciphertext);
      const authTagBytes = base64ToBytes(params.envelope.authTag);
      const combinedCipher = new Uint8Array(
        cipherBytes.length + authTagBytes.length
      );
      combinedCipher.set(cipherBytes, 0);
      combinedCipher.set(authTagBytes, cipherBytes.length);

      const aadBytes = new TextEncoder().encode(params.complaintId);
      const plainBuf = await webCrypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(ivBytes),
          additionalData: toArrayBuffer(aadBytes),
          tagLength: 128,
        },
        aesKey,
        toArrayBuffer(combinedCipher)
      );

      const payload = JSON.parse(new TextDecoder().decode(plainBuf)) as T;
      return {
        payload,
        reconstructedKeyHexLength: rawDek.length * 2,
      };
    } finally {
      rawDek.fill(0);
    }
  } finally {
    for (const buf of decryptedShareBuffers) {
      buf.fill(0);
    }
  }
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
