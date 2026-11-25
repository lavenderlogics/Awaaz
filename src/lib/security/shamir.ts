/**
 * Browser- and Node-compatible 2-of-N Shamir Secret Sharing over GF(256)
 * using AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 */

export interface ShamirShareBytes {
  x: number;
  y: Uint8Array;
}

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
 * Splits a secret byte array into N shares where any 2 distinct shares reconstruct
 * the secret and any single share reveals zero information.
 */
export function splitSecret2OfNBytes(
  secret: Uint8Array,
  shareCount: number
): ShamirShareBytes[] {
  if (shareCount < 2 || shareCount > 250) {
    throw new Error("Shamir 2-of-N requires between 2 and 250 recipients.");
  }

  const slope = new Uint8Array(secret.length);
  globalThis.crypto.getRandomValues(slope);
  const shares: ShamirShareBytes[] = [];

  for (let i = 1; i <= shareCount; i++) {
    const y = new Uint8Array(secret.length);
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      y[byteIdx] = secret[byteIdx] ^ gfMul(slope[byteIdx], i);
    }
    shares.push({ x: i, y });
  }

  slope.fill(0);
  return shares;
}

/** Reconstructs the secret from at least 2 distinct Shamir shares over GF(256). */
export function combineShares2OfNBytes(shares: ShamirShareBytes[]): Uint8Array {
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

  const denomInv = gfInv(s1.x ^ s2.x);
  const l1 = gfMul(s2.x, denomInv);
  const l2 = gfMul(s1.x, denomInv);

  const secret = new Uint8Array(s1.y.length);
  for (let i = 0; i < secret.length; i++) {
    secret[i] = gfMul(s1.y[i], l1) ^ gfMul(s2.y[i], l2);
  }
  return secret;
}

/** Encodes a 32-byte key share into the canonical 33-byte `[x, ...y]` format. */
export function encodeShamirShare(share: ShamirShareBytes): Uint8Array {
  const out = new Uint8Array(1 + share.y.length);
  out[0] = share.x;
  out.set(share.y, 1);
  return out;
}

/** Decodes a canonical 33-byte `[x, ...y]` key share. */
export function decodeShamirShare(bytes: Uint8Array): ShamirShareBytes {
  if (bytes.length !== 33) {
    throw new Error("Invalid key share length.");
  }
  return { x: bytes[0], y: bytes.subarray(1) };
}
