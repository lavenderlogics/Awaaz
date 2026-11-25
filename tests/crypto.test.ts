import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  encryptComplaintInBrowser,
  encryptEvidenceBytesInBrowser,
  forwardShareInBrowser,
  importRsaOaepPrivateKeyNonExtractable,
  reconstructAndDecryptComplaintInBrowser,
  verifyPrivateKeyMatchesPublicKeyInBrowser,
} from "../src/lib/security/client-crypto.ts";
import {
  combineShares2OfN,
  decryptComplaintEnvelope,
  encryptComplaintPayload,
  encryptEvidenceBuffer,
  generateTrackingCredentials,
  protectStoredShare,
  splitSecret2OfN,
  unprotectStoredShare,
  unwrapMemberShareWithPrivateKey,
  validateEncryptedComplaintEnvelope,
  validateEncryptedEvidenceBlob,
} from "../src/lib/security/crypto.ts";
import {
  combineShares2OfNBytes,
  decodeShamirShare,
  encodeShamirShare,
  splitSecret2OfNBytes,
} from "../src/lib/security/shamir.ts";

function makeMember(id: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { id, publicKey, privateKey };
}

test("Browser Uint8Array Shamir 2-of-3 reconstructs exact 32-byte key from any pair", () => {
  const dek = new Uint8Array(32);
  globalThis.crypto.getRandomValues(dek);
  const shares = splitSecret2OfNBytes(dek, 3);
  assert.equal(shares.length, 3);

  const encoded = shares.map((s) => decodeShamirShare(encodeShamirShare(s)));
  assert.deepEqual(combineShares2OfNBytes([encoded[0], encoded[1]]), dek);
  assert.deepEqual(combineShares2OfNBytes([encoded[0], encoded[2]]), dek);
  assert.deepEqual(combineShares2OfNBytes([encoded[1], encoded[2]]), dek);
  assert.throws(() => combineShares2OfNBytes([encoded[0]]));
  assert.throws(() => combineShares2OfNBytes([encoded[0], encoded[0]]));
});

test("Shamir 2-of-3 secret sharing reconstructs exact 32-byte DEK from any pair", () => {
  const dek = crypto.randomBytes(32);
  const shares = splitSecret2OfN(dek, 3);
  assert.equal(shares.length, 3);

  assert.deepEqual(combineShares2OfN([shares[0], shares[1]]), dek);
  assert.deepEqual(combineShares2OfN([shares[0], shares[2]]), dek);
  assert.deepEqual(combineShares2OfN([shares[1], shares[2]]), dek);

  assert.throws(() => combineShares2OfN([shares[0]]));
  assert.throws(() => combineShares2OfN([shares[0], shares[0]]));
});

test("C2: Browser-side share forwarding and Member B local reconstruction & decryption", async () => {
  const mA = makeMember("11111111-1111-1111-1111-111111111111");
  const mB = makeMember("22222222-2222-2222-2222-222222222222");
  const mC = makeMember("33333333-3333-3333-3333-333333333333");
  const complaintId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

  const payload = {
    detailedCategory: "Ragging / Hazing",
    urgency: "immediate",
    incidentDate: "2026-11-25",
    location: "Block C Common Room",
    description: "C2 zero-knowledge browser forwarding and local decryption test.",
    additionalContext: "No plaintext or private keys leave browser",
    evidenceFileNames: [],
  };

  const envelope = await encryptComplaintInBrowser({
    complaintId,
    payload,
    recipients: [
      { memberId: mA.id, publicKey: mA.publicKey },
      { memberId: mB.id, publicKey: mB.publicKey },
      { memberId: mC.id, publicKey: mC.publicKey },
    ],
  });

  // Import non-extractable private keys in browser runtime
  const keyA = await importRsaOaepPrivateKeyNonExtractable(mA.privateKey);
  const keyB = await importRsaOaepPrivateKeyNonExtractable(mB.privateKey);
  const keyC = await importRsaOaepPrivateKeyNonExtractable(mC.privateKey);

  assert.equal(keyA.extractable, false);
  assert.equal(
    await verifyPrivateKeyMatchesPublicKeyInBrowser(keyA, mA.publicKey),
    true
  );
  assert.equal(
    await verifyPrivateKeyMatchesPublicKeyInBrowser(keyA, mB.publicKey),
    false
  );

  // Member A unwraps A's share locally and re-encrypts it for Member B
  const forwardedToB = await forwardShareInBrowser({
    myEncryptedShareBase64: envelope.shares[mA.id],
    myPrivateKey: keyA,
    recipientPublicKeyPem: mB.publicKey,
  });

  // Member C (unintended recipient) CANNOT decrypt the share forwarded to Member B
  await assert.rejects(() =>
    reconstructAndDecryptComplaintInBrowser({
      complaintId,
      envelope,
      myEncryptedShareBase64: envelope.shares[mC.id],
      forwardedEncryptedSharesBase64: [forwardedToB],
      myPrivateKey: keyC,
    })
  );

  // Wrong private key (Member C's key against Member B's share) must fail safely
  await assert.rejects(() =>
    reconstructAndDecryptComplaintInBrowser({
      complaintId,
      envelope,
      myEncryptedShareBase64: envelope.shares[mB.id],
      forwardedEncryptedSharesBase64: [forwardedToB],
      myPrivateKey: keyC,
    })
  );

  // Member B decrypts forwarded share + B's own share locally, reconstructs AES-256 key, and decrypts
  const result = await reconstructAndDecryptComplaintInBrowser<typeof payload>({
    complaintId,
    envelope,
    myEncryptedShareBase64: envelope.shares[mB.id],
    forwardedEncryptedSharesBase64: [forwardedToB],
    myPrivateKey: keyB,
  });

  assert.equal(result.reconstructedKeyHexLength, 64); // 256-bit key
  assert.deepEqual(result.payload, payload);
});

test("Browser WebCrypto complaint encryption validates and decrypts cleanly with server unlock", async () => {
  const m1 = makeMember("11111111-1111-1111-1111-111111111111");
  const m2 = makeMember("22222222-2222-2222-2222-222222222222");
  const m3 = makeMember("33333333-3333-3333-3333-333333333333");
  const complaintId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const secret = "test-server-wrapping-secret";

  const payload = {
    detailedCategory: "Ragging / Hazing",
    urgency: "elevated",
    incidentDate: "2026-11-25",
    location: "North Hostel Corridor",
    description: "Browser-encrypted complaint narrative that server must never read.",
    additionalContext: "Witnesses present",
    evidenceFileNames: ["photo.png", "report.pdf"],
  };

  const envelope = await encryptComplaintInBrowser({
    complaintId,
    payload,
    recipients: [
      { memberId: m1.id, publicKey: m1.publicKey },
      { memberId: m2.id, publicKey: m2.publicKey },
      { memberId: m3.id, publicKey: m3.publicKey },
    ],
  });

  const serialized = JSON.stringify(envelope);
  assert.equal(serialized.includes("North Hostel Corridor"), false);
  assert.equal(serialized.includes("Browser-encrypted complaint"), false);

  const activeIds = new Set([m1.id, m2.id, m3.id]);
  const validation = validateEncryptedComplaintEnvelope(envelope, activeIds);
  assert.equal(validation.ok, true);

  const s1 = unwrapMemberShareWithPrivateKey(envelope.shares[m1.id], m1.privateKey);
  const s2 = unwrapMemberShareWithPrivateKey(envelope.shares[m2.id], m2.privateKey);
  const wrapped1 = protectStoredShare(s1, complaintId, m1.id, secret);
  const wrapped2 = protectStoredShare(s2, complaintId, m2.id, secret);

  const decrypted = decryptComplaintEnvelope<typeof payload>(
    envelope,
    complaintId,
    [
      unprotectStoredShare(wrapped1, complaintId, m1.id, secret),
      unprotectStoredShare(wrapped2, complaintId, m2.id, secret),
    ]
  );
  assert.deepEqual(decrypted, payload);

  assert.throws(() =>
    decryptComplaintEnvelope(envelope, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", [
      s1,
      s2,
    ])
  );
});

test("Browser WebCrypto evidence encryption produces valid AWZ1 blobs with unique IVs", async () => {
  const m1 = makeMember("11111111-1111-1111-1111-111111111111");
  const m2 = makeMember("22222222-2222-2222-2222-222222222222");
  const complaintId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const imgId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
  const pdfId = "dddddddd-dddd-dddd-dddd-dddddddddddd";

  const imgRaw = new TextEncoder().encode("PNG_BINARY_TEST_CONTENT");
  const pdfRaw = new TextEncoder().encode("%PDF-1.7 TEST CONTENT");

  const imgEnc = await encryptEvidenceBytesInBrowser({
    fileBytes: imgRaw,
    mimeType: "image/png",
    complaintId,
    fileId: imgId,
    recipients: [
      { memberId: m1.id, publicKey: m1.publicKey },
      { memberId: m2.id, publicKey: m2.publicKey },
    ],
  });
  const pdfEnc = await encryptEvidenceBytesInBrowser({
    fileBytes: pdfRaw,
    mimeType: "application/pdf",
    complaintId,
    fileId: pdfId,
    recipients: [
      { memberId: m1.id, publicKey: m1.publicKey },
      { memberId: m2.id, publicKey: m2.publicKey },
    ],
  });

  const imgBuf = Buffer.from(imgEnc.encryptedBytes);
  const pdfBuf = Buffer.from(pdfEnc.encryptedBytes);

  assert.equal(imgBuf.includes(Buffer.from(imgRaw)), false);
  assert.equal(pdfBuf.includes(Buffer.from(pdfRaw)), false);

  const activeIds = new Set([m1.id, m2.id]);
  const imgValid = validateEncryptedEvidenceBlob(imgBuf, complaintId, imgId, activeIds);
  const pdfValid = validateEncryptedEvidenceBlob(pdfBuf, complaintId, pdfId, activeIds);
  assert.equal(imgValid.ok, true);
  assert.equal(pdfValid.ok, true);

  const imgHeader = JSON.parse(imgBuf.subarray(8, 8 + imgBuf.readUInt32BE(4)).toString("utf8"));
  const pdfHeader = JSON.parse(pdfBuf.subarray(8, 8 + pdfBuf.readUInt32BE(4)).toString("utf8"));
  assert.notEqual(imgHeader.iv, pdfHeader.iv);
});

test("Browser encryption rejects insufficient committee keys without producing output", async () => {
  const m1 = makeMember("11111111-1111-1111-1111-111111111111");
  await assert.rejects(() =>
    encryptComplaintInBrowser({
      complaintId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      payload: { description: "Should fail before transmission" },
      recipients: [{ memberId: m1.id, publicKey: m1.publicKey }],
    })
  );
});

test("AES-256-GCM + RSA-OAEP 2-of-N envelope round-trip and tamper rejection", () => {
  const m1 = makeMember("11111111-1111-1111-1111-111111111111");
  const m2 = makeMember("22222222-2222-2222-2222-222222222222");
  const m3 = makeMember("33333333-3333-3333-3333-333333333333");
  const complaintId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const secret = "test-server-wrapping-secret";

  const payload = {
    urgency: "elevated",
    incidentDate: "2026-11-25",
    location: "Hostel Block B",
    description: "Sensitive incident narrative that must never be plaintext.",
  };

  const envelope = encryptComplaintPayload(payload, complaintId, [
    { memberId: m1.id, publicKeyPem: m1.publicKey },
    { memberId: m2.id, publicKeyPem: m2.publicKey },
    { memberId: m3.id, publicKeyPem: m3.publicKey },
  ]);

  const serialized = JSON.stringify(envelope);
  assert.equal(serialized.includes("Hostel Block B"), false);
  assert.equal(serialized.includes("Sensitive incident narrative"), false);

  const s1 = unwrapMemberShareWithPrivateKey(envelope.shares[m1.id], m1.privateKey);
  const s3 = unwrapMemberShareWithPrivateKey(envelope.shares[m3.id], m3.privateKey);

  const wrapped1 = protectStoredShare(s1, complaintId, m1.id, secret);
  const wrapped3 = protectStoredShare(s3, complaintId, m3.id, secret);

  const unwrapped1 = unprotectStoredShare(wrapped1, complaintId, m1.id, secret);
  const unwrapped3 = unprotectStoredShare(wrapped3, complaintId, m3.id, secret);

  const decrypted = decryptComplaintEnvelope<typeof payload>(
    envelope,
    complaintId,
    [unwrapped1, unwrapped3]
  );
  assert.deepEqual(decrypted, payload);

  assert.throws(() =>
    decryptComplaintEnvelope(envelope, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", [
      unwrapped1,
      unwrapped3,
    ])
  );

  const tampered = { ...envelope, ciphertext: Buffer.from("tampered").toString("base64") };
  assert.throws(() =>
    decryptComplaintEnvelope(tampered, complaintId, [unwrapped1, unwrapped3])
  );
});

test("Evidence encryption hides plaintext bytes and tracking credentials hash cleanly", () => {
  const m1 = makeMember("11111111-1111-1111-1111-111111111111");
  const m2 = makeMember("22222222-2222-2222-2222-222222222222");
  const raw = Buffer.from("Confidential evidence screenshot bytes", "utf8");

  const { encryptedBlob, ciphertextHash } = encryptEvidenceBuffer(
    raw,
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "cccccccc-cccc-cccc-cccc-cccccccccccc",
    [
      { memberId: m1.id, publicKeyPem: m1.publicKey },
      { memberId: m2.id, publicKeyPem: m2.publicKey },
    ]
  );

  assert.equal(encryptedBlob.subarray(0, 4).toString("ascii"), "AWZ1");
  assert.equal(encryptedBlob.includes(raw), false);
  assert.equal(ciphertextHash.length, 64);

  const creds = generateTrackingCredentials();
  assert.match(creds.caseCode, /^AWZ-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.equal(creds.caseCodeHash.length, 64);
  assert.equal(creds.recoverySecretHash.length, 64);
});
