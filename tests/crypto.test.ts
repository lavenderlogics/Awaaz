import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
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
} from "../src/lib/security/crypto.ts";

function makeMember(id: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { id, publicKey, privateKey };
}

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

  // Ensure plaintext does not appear anywhere in the encrypted envelope
  const serialized = JSON.stringify(envelope);
  assert.equal(serialized.includes("Hostel Block B"), false);
  assert.equal(serialized.includes("Sensitive incident narrative"), false);

  // Member 1 and Member 3 unwrap their shares with private keys and protect in unlock_approvals
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

  // Wrong AAD (different complaintId) must fail GCM authentication
  assert.throws(() =>
    decryptComplaintEnvelope(envelope, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", [
      unwrapped1,
      unwrapped3,
    ])
  );

  // Tampered ciphertext must fail GCM authentication
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
