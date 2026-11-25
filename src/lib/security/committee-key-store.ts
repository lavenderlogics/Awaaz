/**
 * Browser-only IndexedDB store for non-extractable committee RSA-OAEP CryptoKeys.
 * Private keys are never placed in localStorage, sessionStorage, or sent to the server.
 */

const DB_NAME = "awaaz-committee-keystore";
const DB_VERSION = 1;
const STORE_NAME = "privateKeys";

export interface StoredCommitteeKeyEntry {
  memberId: string;
  privateKey: CryptoKey;
  publicKeyFingerprint: string;
  createdAt: string;
}

function openKeyStoreDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined" || !window.indexedDB) {
      reject(new Error("IndexedDB is unavailable in this browser."));
      return;
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "memberId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("Failed to open IndexedDB key store."));
  });
}

/** Computes a SHA-256 hex fingerprint of a normalized SPKI public key PEM. */
export async function computePublicKeyFingerprint(
  publicKeyPem: string
): Promise<string> {
  const normalized = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const bytes = new TextEncoder().encode(normalized);
  const digest = await window.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Saves a non-extractable RSA-OAEP CryptoKey into IndexedDB for a member. */
export async function savePrivateKeyToIndexedDb(params: {
  memberId: string;
  privateKey: CryptoKey;
  publicKeyFingerprint: string;
}): Promise<void> {
  if (params.privateKey.extractable) {
    throw new Error(
      "Refusing to persist an extractable private CryptoKey in IndexedDB."
    );
  }

  const db = await openKeyStoreDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const entry: StoredCommitteeKeyEntry = {
        memberId: params.memberId,
        privateKey: params.privateKey,
        publicKeyFingerprint: params.publicKeyFingerprint,
        createdAt: new Date().toISOString(),
      };
      const req = store.put(entry);
      req.onsuccess = () => resolve();
      req.onerror = () =>
        reject(req.error ?? new Error("Failed to store private key."));
    });
  } finally {
    db.close();
  }
}

/** Loads a stored non-extractable private CryptoKey from IndexedDB. */
export async function loadPrivateKeyFromIndexedDb(
  memberId: string
): Promise<StoredCommitteeKeyEntry | null> {
  const db = await openKeyStoreDb();
  try {
    return await new Promise<StoredCommitteeKeyEntry | null>(
      (resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(memberId);
        req.onsuccess = () =>
          resolve((req.result as StoredCommitteeKeyEntry | undefined) ?? null);
        req.onerror = () =>
          reject(req.error ?? new Error("Failed to read private key."));
      }
    );
  } finally {
    db.close();
  }
}

/** Removes a member's locally persisted private CryptoKey from IndexedDB. */
export async function deletePrivateKeyFromIndexedDb(
  memberId: string
): Promise<void> {
  const db = await openKeyStoreDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(memberId);
      req.onsuccess = () => resolve();
      req.onerror = () =>
        reject(req.error ?? new Error("Failed to delete private key."));
    });
  } finally {
    db.close();
  }
}
