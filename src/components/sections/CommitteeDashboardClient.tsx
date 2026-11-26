"use client";

import {
  CheckCircle2,
  ChevronDown,
  ClipboardList,
  Clock,
  Download,
  Inbox,
  KeyRound,
  LockOpen,
  LogOut,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type ChangeEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input, Select, Textarea } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { PLANNED_CASE_STAGES } from "@/lib/constants";
import {
  type BrowserDecryptableEnvelope,
  derToPem,
  forwardShareInBrowser,
  importRsaOaepPrivateKeyNonExtractable,
  type PublicCommitteeRecipient,
  reconstructAndDecryptComplaintInBrowser,
  verifyPrivateKeyMatchesPublicKeyInBrowser,
} from "@/lib/security/client-crypto";
import {
  computePublicKeyFingerprint,
  loadPrivateKeyFromIndexedDb,
  savePrivateKeyToIndexedDb,
} from "@/lib/security/committee-key-store";
import { createClient } from "@/lib/supabase/client";

interface DashboardComplaint {
  id: string;
  category: string;
  status: string;
  encryptionAlgorithm: string;
  createdAt: string | null;
  updatedAt: string | null;
  approvalCount: number;
  requiredApprovals: number;
  approvedByMe: boolean;
  forwardedToMeCount: number;
  evidenceCount: number;
}

interface CommitteeMemberSummary {
  userId: string;
  fullName: string;
  role: string;
  hasPublicKey: boolean;
  isActive: boolean;
}

interface CurrentCommitteeMember extends CommitteeMemberSummary {
  publicKeyPem: string | null;
}

interface AuditLogEntry {
  id: number;
  complaint_id: string;
  actor_member_id: string | null;
  event_type: string;
  event_details: Record<string, unknown> | null;
  created_at: string;
}

interface ForwardedShareItem {
  senderMemberId: string;
  ciphertextShare: string;
  approvedAt: string | null;
}

interface UnlockBundle {
  complaintId: string;
  category: string;
  status: string;
  envelope: BrowserDecryptableEnvelope;
  myEncryptedShare: string | null;
  forwardedSharesToMe: ForwardedShareItem[];
  approvalSummaries: Array<{
    memberId: string;
    approvedAt: string | null;
    forwardedToIds: string[];
  }>;
  evidenceFiles: Array<{
    id: string;
    mime_type: string | null;
    file_size: number | null;
    file_hash: string | null;
  }>;
}

interface DecryptedDetails {
  complaintId: string;
  payload: Record<string, unknown>;
  evidenceFiles: UnlockBundle["evidenceFiles"];
}

interface CommitteeDashboardClientProps {
  isConfigured: boolean;
  isServiceRoleReady: boolean;
  userEmail: string | null;
  userId: string | null;
}

type LocalKeyStatus = "checking" | "ready" | "missing" | "mismatch";

const SUMMARY_METRICS = [
  { key: "total", label: "Total Complaints", icon: ClipboardList },
  { key: "pending", label: "Pending Triage", icon: Clock },
  { key: "awaitingUnlock", label: "Ready for Me to Decrypt", icon: ShieldAlert },
  { key: "resolved", label: "Resolved Cases", icon: CheckCircle2 },
] as const;

/**
 * Protected committee dashboard implementing C2:
 * - Non-extractable RSA-OAEP private CryptoKeys persisted in IndexedDB only
 * - Local private-key PEM import with challenge-response verification
 * - Browser-side share decryption and re-encryption forwarding for recipients
 * - Browser-side Shamir reconstruction + AES-256-GCM complaint decryption
 */
export function CommitteeDashboardClient({
  isConfigured,
  isServiceRoleReady,
  userEmail,
  userId,
}: CommitteeDashboardClientProps) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState("all");
  const [isSigningOut, setIsSigningOut] = useState(false);

  const [loadingData, setLoadingData] = useState(
    Boolean(userEmail && isServiceRoleReady)
  );
  const [apiError, setApiError] = useState("");
  const [complaints, setComplaints] = useState<DashboardComplaint[]>([]);
  const [members, setMembers] = useState<CommitteeMemberSummary[]>([]);
  const [currentMember, setCurrentMember] =
    useState<CurrentCommitteeMember | null>(null);

  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditChainValid, setAuditChainValid] = useState<boolean | null>(null);

  // Browser-only non-extractable private CryptoKey state
  const [localPrivateKey, setLocalPrivateKey] = useState<CryptoKey | null>(null);
  const [localKeyStatus, setLocalKeyStatus] =
    useState<LocalKeyStatus>("checking");
  const [importPemText, setImportPemText] = useState("");
  const [importError, setImportError] = useState("");
  const [importSuccess, setImportSuccess] = useState("");
  const [isImportingKey, setIsImportingKey] = useState(false);

  // One-time backup download state (only populated right after key generation)
  const [generatedPrivatePem, setGeneratedPrivatePem] = useState<string | null>(
    null
  );
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [keyStatusMessage, setKeyStatusMessage] = useState("");

  // Selected complaint C2 unlock & share-forwarding state
  const [selectedComplaintId, setSelectedComplaintId] = useState<string | null>(
    null
  );
  const [unlockBundle, setUnlockBundle] = useState<UnlockBundle | null>(null);
  const [loadingBundle, setLoadingBundle] = useState(false);
  const [recipientMemberId, setRecipientMemberId] = useState("");
  const [unlockFeedback, setUnlockFeedback] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [decrypted, setDecrypted] = useState<DecryptedDetails | null>(null);
  const [updatingStatusId, setUpdatingStatusId] = useState<string | null>(null);
  const [statusUpdateFeedback, setStatusUpdateFeedback] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const syncLocalKeyFromIndexedDb = useCallback(
    async (member: CurrentCommitteeMember | null) => {
      if (!member) {
        setLocalPrivateKey(null);
        setLocalKeyStatus("missing");
        return;
      }
      if (!member.hasPublicKey || !member.publicKeyPem) {
        setLocalPrivateKey(null);
        setLocalKeyStatus("missing");
        return;
      }

      try {
        const entry = await loadPrivateKeyFromIndexedDb(member.userId);
        if (!entry) {
          setLocalPrivateKey(null);
          setLocalKeyStatus("missing");
          return;
        }

        const expectedFp = await computePublicKeyFingerprint(
          member.publicKeyPem
        );
        if (entry.publicKeyFingerprint !== expectedFp) {
          setLocalPrivateKey(null);
          setLocalKeyStatus("mismatch");
          return;
        }

        const cryptoMatches = await verifyPrivateKeyMatchesPublicKeyInBrowser(
          entry.privateKey,
          member.publicKeyPem
        );
        if (!cryptoMatches) {
          setLocalPrivateKey(null);
          setLocalKeyStatus("mismatch");
          return;
        }

        setLocalPrivateKey(entry.privateKey);
        setLocalKeyStatus("ready");
      } catch {
        setLocalPrivateKey(null);
        setLocalKeyStatus("missing");
      }
    },
    []
  );

  const loadDashboard = useCallback(async () => {
    if (!userEmail || !isServiceRoleReady) return;

    try {
      const [dashRes, auditRes] = await Promise.all([
        fetch("/api/committee/dashboard", { cache: "no-store" }),
        fetch("/api/committee/audit-logs", { cache: "no-store" }),
      ]);
      const dashJson = (await dashRes.json()) as Record<string, unknown>;

      if (!dashRes.ok) {
        setApiError(
          typeof dashJson.error === "string"
            ? dashJson.error
            : "Failed to load committee dashboard."
        );
        return;
      }

      setApiError("");
      setComplaints(
        Array.isArray(dashJson.complaints)
          ? (dashJson.complaints as DashboardComplaint[])
          : []
      );
      setMembers(
        Array.isArray(dashJson.members)
          ? (dashJson.members as CommitteeMemberSummary[])
          : []
      );
      const memberData =
        (dashJson.currentMember as CurrentCommitteeMember | null) ?? null;
      setCurrentMember(memberData);
      await syncLocalKeyFromIndexedDb(memberData);

      if (auditRes.ok) {
        const auditJson = (await auditRes.json()) as Record<string, unknown>;
        setAuditLogs(
          Array.isArray(auditJson.logs)
            ? (auditJson.logs as AuditLogEntry[])
            : []
        );
        setAuditChainValid(
          typeof auditJson.chainValid === "boolean"
            ? auditJson.chainValid
            : null
        );
      }
    } catch {
      setApiError("Network error while loading committee data.");
    } finally {
      setLoadingData(false);
    }
  }, [isServiceRoleReady, syncLocalKeyFromIndexedDb, userEmail]);

  useEffect(() => {
    if (!userEmail || !isServiceRoleReady) return;
    let active = true;
    const run = async () => {
      if (!active) return;
      await loadDashboard();
    };
    void run();
    return () => {
      active = false;
    };
  }, [isServiceRoleReady, loadDashboard, userEmail]);

  const otherActiveMembersWithKeys = useMemo(() => {
    if (!currentMember) return [];
    return members.filter(
      (m) =>
        m.isActive && m.hasPublicKey && m.userId !== currentMember.userId
    );
  }, [currentMember, members]);

  const effectiveRecipientId =
    recipientMemberId || otherActiveMembersWithKeys[0]?.userId || "";

  const filteredComplaints = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return complaints.filter((row) => {
      const matchesCategory =
        selectedCategory === "all" || row.category === selectedCategory;
      const matchesStatus =
        selectedStatus === "all" || row.status === selectedStatus;
      const matchesQuery =
        !query ||
        row.id.toLowerCase().includes(query) ||
        row.category.toLowerCase().includes(query);
      return matchesCategory && matchesStatus && matchesQuery;
    });
  }, [complaints, searchQuery, selectedCategory, selectedStatus]);

  const metricCounts = useMemo(() => {
    if (!userEmail || !currentMember) {
      return {
        total: null,
        pending: null,
        awaitingUnlock: null,
        resolved: null,
      };
    }
    return {
      total: complaints.length,
      pending: complaints.filter((c) =>
        ["submitted", "under_review"].includes(c.status)
      ).length,
      awaitingUnlock: complaints.filter((c) => c.forwardedToMeCount >= 1)
        .length,
      resolved: complaints.filter((c) =>
        ["resolved", "closed"].includes(c.status)
      ).length,
    };
  }, [complaints, currentMember, userEmail]);

  const handleGenerateAndRegisterKey = async () => {
    if (!currentMember) return;
    if (
      currentMember.hasPublicKey &&
      !window.confirm(
        "You already have a registered public key. Rotating generates a new keypair ONLY for future complaints—existing complaints cannot be decrypted unless you saved your previous .pem backup. Continue?"
      )
    ) {
      return;
    }
    setIsGeneratingKey(true);
    setKeyStatusMessage("");
    setApiError("");
    setImportError("");
    setImportSuccess("");

    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      const spki = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      const pkcs8 = await window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
      );

      const publicKeyPem = derToPem(spki, "PUBLIC KEY");
      const privateKeyBackupPem = derToPem(pkcs8, "PRIVATE KEY");

      // Re-import as non-extractable CryptoKey for IndexedDB persistence
      const nonExtractableKey = await importRsaOaepPrivateKeyNonExtractable(
        privateKeyBackupPem
      );
      new Uint8Array(pkcs8).fill(0);

      const res = await fetch("/api/committee/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ publicKeyPem }),
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setApiError(
          typeof json.error === "string"
            ? json.error
            : "Failed to register public key."
        );
        return;
      }

      const fingerprint = await computePublicKeyFingerprint(publicKeyPem);
      await savePrivateKeyToIndexedDb({
        memberId: currentMember.userId,
        privateKey: nonExtractableKey,
        publicKeyFingerprint: fingerprint,
      });

      setGeneratedPrivatePem(privateKeyBackupPem);
      setKeyStatusMessage(
        "RSA-2048 public key saved to committee_members, and your non-extractable private key is stored in IndexedDB. Download a PEM backup if you need to use another browser."
      );
      await loadDashboard();
    } catch {
      setApiError("Unable to generate RSA-OAEP keypair in this browser.");
    } finally {
      setIsGeneratingKey(false);
    }
  };

  const downloadPrivateKey = () => {
    if (!generatedPrivatePem) return;
    const blob = new Blob([generatedPrivatePem], {
      type: "application/x-pem-file",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "awaaz-committee-private-key.pem";
    link.click();
    URL.revokeObjectURL(url);
    // Clear one-time backup string from React state after download
    setGeneratedPrivatePem(null);
  };

  const handleImportPemFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setImportPemText(text);
    event.target.value = "";
  };

  const handleImportExistingPrivateKey = async () => {
    if (!currentMember || !currentMember.publicKeyPem) {
      setImportError(
        "No public key is registered on the server for your account yet."
      );
      return;
    }

    const trimmedPem = importPemText.trim();
    if (!trimmedPem) {
      setImportError("Paste or select your PKCS#8 private key PEM first.");
      return;
    }

    setIsImportingKey(true);
    setImportError("");
    setImportSuccess("");

    try {
      const nonExtractableKey =
        await importRsaOaepPrivateKeyNonExtractable(trimmedPem);
      const matches = await verifyPrivateKeyMatchesPublicKeyInBrowser(
        nonExtractableKey,
        currentMember.publicKeyPem
      );

      if (!matches) {
        setImportError(
          "This private key does not match your registered public key. Nothing was saved or transmitted."
        );
        return;
      }

      const fingerprint = await computePublicKeyFingerprint(
        currentMember.publicKeyPem
      );
      await savePrivateKeyToIndexedDb({
        memberId: currentMember.userId,
        privateKey: nonExtractableKey,
        publicKeyFingerprint: fingerprint,
      });

      setImportPemText("");
      setImportSuccess(
        "Private key verified locally and stored as a non-extractable CryptoKey in IndexedDB."
      );
      await syncLocalKeyFromIndexedDb(currentMember);
    } catch {
      setImportError(
        "Invalid PKCS#8 private key PEM. Ensure it starts with -----BEGIN PRIVATE KEY-----."
      );
    } finally {
      setIsImportingKey(false);
    }
  };

  const loadComplaintUnlockBundle = async (complaintId: string) => {
    setSelectedComplaintId(complaintId);
    setLoadingBundle(true);
    setUnlockError("");
    setUnlockFeedback("");
    setDecrypted(null);
    setUnlockBundle(null);

    try {
      const res = await fetch(
        `/api/committee/unlock?complaintId=${encodeURIComponent(complaintId)}`,
        { cache: "no-store" }
      );
      const json = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        setUnlockError(
          typeof json.error === "string"
            ? json.error
            : "Failed to load encrypted share data."
        );
        return;
      }

      setUnlockBundle(json as unknown as UnlockBundle);
    } catch {
      setUnlockError("Network error while loading encrypted share bundle.");
    } finally {
      setLoadingBundle(false);
    }
  };

  const handleForwardShare = async () => {
    if (!unlockBundle || !localPrivateKey || !effectiveRecipientId) return;
    if (!unlockBundle.myEncryptedShare) {
      setUnlockError(
        "This complaint does not include a wrapped share for your account."
      );
      return;
    }

    setIsUnlocking(true);
    setUnlockError("");
    setUnlockFeedback("");

    try {
      const keysRes = await fetch("/api/committee/public-keys", {
        cache: "no-store",
      });
      const keysJson = (await keysRes.json()) as {
        members?: PublicCommitteeRecipient[];
        error?: string;
      };

      if (!keysRes.ok || !Array.isArray(keysJson.members)) {
        setUnlockError(
          keysJson.error ?? "Unable to fetch recipient public key."
        );
        return;
      }

      const recipient = keysJson.members.find(
        (m) => m.memberId === effectiveRecipientId
      );
      if (!recipient) {
        setUnlockError(
          "Selected recipient does not have an active RSA-OAEP public key."
        );
        return;
      }

      const encryptedForwardedShare = await forwardShareInBrowser({
        myEncryptedShareBase64: unlockBundle.myEncryptedShare,
        myPrivateKey: localPrivateKey,
        recipientPublicKeyPem: recipient.publicKey,
      });

      const res = await fetch("/api/committee/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          complaintId: unlockBundle.complaintId,
          recipientMemberId: effectiveRecipientId,
          encryptedForwardedShare,
        }),
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setUnlockError(
          typeof json.error === "string"
            ? json.error
            : "Failed to submit encrypted forwarded share."
        );
        return;
      }

      const recipientName =
        members.find((m) => m.userId === effectiveRecipientId)?.fullName ??
        effectiveRecipientId;
      setUnlockFeedback(
        `Your share was decrypted locally and forwarded encrypted for ${recipientName}. No plaintext key or share left your browser.`
      );
      await Promise.all([
        loadDashboard(),
        loadComplaintUnlockBundle(unlockBundle.complaintId),
      ]);
    } catch {
      setUnlockError(
        "Local share decryption failed. Check that your IndexedDB key matches this complaint's encryption key."
      );
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleDecryptLocally = async () => {
    if (!unlockBundle || !localPrivateKey) return;
    if (!unlockBundle.myEncryptedShare) {
      setUnlockError(
        "This complaint does not include a wrapped share for your account."
      );
      return;
    }
    if (unlockBundle.forwardedSharesToMe.length === 0) {
      setUnlockError(
        "At least 1 other committee member must forward their encrypted share to you before you can decrypt."
      );
      return;
    }

    setIsUnlocking(true);
    setUnlockError("");
    setUnlockFeedback("");

    try {
      const { payload } = await reconstructAndDecryptComplaintInBrowser({
        complaintId: unlockBundle.complaintId,
        envelope: unlockBundle.envelope,
        myEncryptedShareBase64: unlockBundle.myEncryptedShare,
        forwardedEncryptedSharesBase64: unlockBundle.forwardedSharesToMe.map(
          (f) => f.ciphertextShare
        ),
        myPrivateKey: localPrivateKey,
      });

      setDecrypted({
        complaintId: unlockBundle.complaintId,
        payload,
        evidenceFiles: unlockBundle.evidenceFiles,
      });
      setUnlockFeedback(
        "AES-256 key reconstructed via Shamir GF(256) and complaint decrypted strictly inside your browser."
      );
    } catch (error) {
      setDecrypted(null);
      setUnlockError(
        error instanceof Error && error.message
          ? error.message
          : "Local decryption failed. Ensure your IndexedDB private key matches and the forwarded share came from a valid co-approver."
      );
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleStatusChange = async (complaintId: string, status: string) => {
    const previousComplaints = complaints;
    const stageLabel =
      PLANNED_CASE_STAGES.find((stage) => stage.id === status)?.label ?? status;

    setUpdatingStatusId(complaintId);
    setStatusUpdateFeedback(null);
    setComplaints((prev) =>
      prev.map((item) =>
        item.id === complaintId ? { ...item, status } : item
      )
    );

    try {
      const res = await fetch("/api/committee/status", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ complaintId, status }),
      });
      const json = (await res.json().catch(() => ({}))) as { error?: string };

      if (!res.ok) {
        setComplaints(previousComplaints);
        setStatusUpdateFeedback({
          type: "error",
          text:
            typeof json.error === "string"
              ? json.error
              : `Unable to update case status (HTTP ${res.status}).`,
        });
        return;
      }

      setStatusUpdateFeedback({
        type: "success",
        text: `Case ${complaintId.slice(0, 8)}... updated to "${stageLabel}".`,
      });
      await loadDashboard();
    } catch {
      setComplaints(previousComplaints);
      setStatusUpdateFeedback({
        type: "error",
        text: "Network error while updating case status. Please try again.",
      });
    } finally {
      setUpdatingStatusId(null);
    }
  };

  const handleSignOut = async () => {
    if (!isConfigured) return;
    setIsSigningOut(true);
    try {
      const supabase = createClient();
      await supabase.auth.signOut();
      router.push("/committee/login");
      router.refresh();
    } finally {
      setIsSigningOut(false);
    }
  };

  return (
    <div className="space-y-8">
      {!isConfigured ? (
        <StatusNotice
          title="Missing Public Supabase Environment Variables"
          variant="warning"
        >
          Add <code className="font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and{" "}
          <code className="font-mono">NEXT_PUBLIC_SUPABASE_ANON_KEY</code> in
          your environment settings and redeploy.
        </StatusNotice>
      ) : !userEmail ? (
        <StatusNotice
          title="Committee Sign-In Required for Live Records"
          variant="warning"
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <span>
              Row-Level Security blocks unauthenticated access. Sign in with an
              authorized committee account to inspect complaints and audit logs.
            </span>
            <LinkButton href="/committee/login" variant="primary" size="sm">
              Sign In
            </LinkButton>
          </div>
        </StatusNotice>
      ) : !isServiceRoleReady ? (
        <StatusNotice
          title="Server Service-Role Key Required"
          variant="warning"
        >
          Signed in as <strong>{userEmail}</strong>, but{" "}
          <code className="font-mono">SUPABASE_SERVICE_ROLE_KEY</code> is not
          configured on the server yet. Add it to{" "}
          <code className="font-mono">.env.local</code> / Vercel Environment
          Variables (without <code className="font-mono">NEXT_PUBLIC_</code>).
        </StatusNotice>
      ) : apiError ? (
        <StatusNotice title="Committee Access Notice" variant="warning">
          <div className="space-y-2">
            <p>{apiError}</p>
            {userId ? (
              <p className="text-xs">
                Signed-in Supabase Auth UID:{" "}
                <code className="rounded bg-amber-100 px-1.5 py-0.5 font-mono">
                  {userId}
                </code>
              </p>
            ) : null}
          </div>
        </StatusNotice>
      ) : (
        <StatusNotice title="Connected as Committee Officer" variant="navy">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <span>
              Signed in as <strong>{userEmail}</strong> (
              {currentMember?.role ?? "Committee"}). Zero-knowledge browser key
              mode active.
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={handleSignOut}
              disabled={isSigningOut}
            >
              <LogOut className="h-3.5 w-3.5" />
              {isSigningOut ? "Signing Out..." : "Sign Out"}
            </Button>
          </div>
        </StatusNotice>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {SUMMARY_METRICS.map((metric) => {
          const Icon = metric.icon;
          const value = metricCounts[metric.key];
          return (
            <Card key={metric.label}>
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">
                    {metric.label}
                  </span>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-navy-50 text-navy-800">
                    <Icon className="h-4 w-4" />
                  </span>
                </div>
                <p className="mt-3 font-display text-3xl font-bold text-slate-950">
                  {value === null ? "\u2014" : value}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {loadingData
                    ? "Loading..."
                    : currentMember
                      ? "Live Supabase count"
                      : "Committee authorization required"}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="border-b border-slate-100">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle>Encrypted Complaint Queue</CardTitle>
                <p className="mt-1 text-sm text-slate-600">
                  Private keys never leave your browser. Forward or combine
                  encrypted shares locally to decrypt.
                </p>
              </div>
              <Badge variant="slate">
                {filteredComplaints.length} Record
                {filteredComplaints.length === 1 ? "" : "s"}
              </Badge>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="relative">
                <Search className="pointer-events-none absolute top-3 left-3 h-4 w-4 text-slate-400" />
                <Input
                  type="text"
                  placeholder="Search ID or category..."
                  className="pl-9"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  aria-label="Search cases"
                />
              </div>
              <Select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                aria-label="Filter by category"
              >
                <option value="all">All Categories</option>
                <option value="ragging">Ragging</option>
                <option value="harassment">Harassment</option>
              </Select>
              <Select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                aria-label="Filter by status"
              >
                <option value="all">All Statuses</option>
                {PLANNED_CASE_STAGES.map((stage) => (
                  <option key={stage.id} value={stage.id}>
                    {stage.label}
                  </option>
                ))}
              </Select>
            </div>
            {statusUpdateFeedback ? (
              <div className="mt-4">
                <StatusNotice
                  title={
                    statusUpdateFeedback.type === "success"
                      ? "Case Status Updated"
                      : "Status Update Failed"
                  }
                  variant={
                    statusUpdateFeedback.type === "success"
                      ? "success"
                      : "warning"
                  }
                >
                  {statusUpdateFeedback.text}
                </StatusNotice>
              </div>
            ) : null}
          </CardHeader>

          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 bg-slate-50/80 text-xs font-semibold tracking-wider text-slate-600 uppercase">
                  <tr>
                    <th className="px-5 py-3.5">Complaint ID</th>
                    <th className="px-5 py-3.5">Category</th>
                    <th className="px-5 py-3.5">Key Shares</th>
                    <th className="px-5 py-3.5">Status</th>
                    <th className="px-5 py-3.5">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredComplaints.length > 0 ? (
                    filteredComplaints.map((row) => (
                      <tr key={row.id} className="hover:bg-slate-50/70">
                        <td className="px-5 py-4 font-mono text-xs font-semibold text-navy-900">
                          {row.id.slice(0, 8)}...
                        </td>
                        <td className="px-5 py-4 text-slate-800">
                          <div>{row.category}</div>
                          <div className="text-xs text-slate-500">
                            {row.evidenceCount} encrypted file
                            {row.evidenceCount === 1 ? "" : "s"}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <Badge
                            variant={
                              row.forwardedToMeCount >= 1
                                ? "emerald"
                                : "amber"
                            }
                          >
                            {row.forwardedToMeCount >= 1
                              ? `${row.forwardedToMeCount} Forwarded to You`
                              : `${row.approvalCount} Shared`}
                          </Badge>
                        </td>
                        <td className="px-5 py-4 align-middle">
                          <div className="relative inline-flex w-full min-w-[10.5rem] max-w-[13rem] items-center sm:w-48">
                            <Select
                              value={row.status}
                              disabled={updatingStatusId === row.id}
                              onChange={(e) =>
                                void handleStatusChange(row.id, e.target.value)
                              }
                              className="h-11 w-full appearance-none !py-2.5 !pr-11 !pl-4 text-sm font-medium"
                              aria-label={`Update status for ${row.id}`}
                            >
                              {PLANNED_CASE_STAGES.map((stage) => (
                                <option key={stage.id} value={stage.id}>
                                  {stage.label}
                                </option>
                              ))}
                            </Select>
                            <ChevronDown
                              className="pointer-events-none absolute top-1/2 right-3.5 h-5 w-5 -translate-y-1/2 text-slate-600"
                              aria-hidden="true"
                            />
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => void loadComplaintUnlockBundle(row.id)}
                          >
                            <LockOpen className="h-3.5 w-3.5" />
                            {row.forwardedToMeCount >= 1
                              ? "Unlock"
                              : "Forward Share"}
                          </Button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-14 text-center">
                        <div className="mx-auto flex max-w-sm flex-col items-center space-y-2.5">
                          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-navy-50 text-navy-800">
                            <Inbox className="h-6 w-6" />
                          </span>
                          <p className="text-sm font-semibold text-slate-900">
                            {currentMember
                              ? "No matching complaints found"
                              : "Committee authorization required"}
                          </p>
                          <p className="text-xs leading-relaxed text-slate-500">
                            Active filters:{" "}
                            <span className="font-mono text-slate-700">
                              {selectedCategory} / {selectedStatus}
                            </span>
                            {searchQuery ? ` / "${searchQuery}"` : ""}.
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <Card subtle>
          <CardHeader>
            <div className="flex items-center gap-2 text-navy-800">
              <KeyRound className="h-4 w-4" />
              <span className="text-xs font-semibold tracking-wider uppercase">
                Browser Keystore (IndexedDB)
              </span>
            </div>
            <CardTitle className="mt-2">Committee Key Readiness</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm text-slate-600">
            {currentMember ? (
              <div className="space-y-3">
                <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900">
                      Your Browser Key:
                    </span>
                    <Badge
                      variant={
                        localKeyStatus === "ready" ? "emerald" : "amber"
                      }
                    >
                      {localKeyStatus === "ready"
                        ? "Non-Extractable Ready"
                        : localKeyStatus === "mismatch"
                          ? "Key Mismatch"
                          : localKeyStatus === "checking"
                            ? "Checking..."
                            : "Not in Browser"}
                    </Badge>
                  </div>
                  {currentMember.hasPublicKey && localKeyStatus !== "ready" ? (
                    <p className="mt-2 leading-relaxed text-amber-800">
                      {localKeyStatus === "mismatch"
                        ? "Your IndexedDB key does not match the registered public key. Import your matching .pem backup below. Rotating generates a new key only for future complaints."
                        : "Your public key is registered, but this browser has no matching private key. Import your .pem backup locally below—do not rotate unless you want a new key for future complaints only."}
                    </p>
                  ) : null}
                </div>

                {!currentMember.hasPublicKey ? (
                  <Button
                    type="button"
                    variant="primary"
                    size="sm"
                    className="w-full"
                    disabled={isGeneratingKey}
                    onClick={handleGenerateAndRegisterKey}
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    {isGeneratingKey
                      ? "Generating RSA-2048 Key..."
                      : "Generate & Register My Key"}
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="w-full"
                    disabled={isGeneratingKey}
                    onClick={handleGenerateAndRegisterKey}
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    {isGeneratingKey
                      ? "Rotating Key..."
                      : "Rotate Key (Future Complaints Only)"}
                  </Button>
                )}

                {generatedPrivatePem ? (
                  <Button
                    type="button"
                    variant="primary"
                    size="sm"
                    className="w-full"
                    onClick={downloadPrivateKey}
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download Private Key Backup (.pem)
                  </Button>
                ) : null}

                {keyStatusMessage ? (
                  <StatusNotice title="Key Registered" variant="success">
                    {keyStatusMessage}
                  </StatusNotice>
                ) : null}

                {currentMember.hasPublicKey && localKeyStatus !== "ready" ? (
                  <div className="space-y-2.5 rounded-xl border border-slate-200 bg-white p-3">
                    <p className="text-xs font-semibold text-slate-900">
                      Import Existing Private Key Locally
                    </p>
                    <p className="text-[11px] leading-relaxed text-slate-500">
                      Imported directly into a non-extractable IndexedDB
                      CryptoKey. Never leaves your browser.
                    </p>
                    <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-navy-900 hover:bg-slate-100">
                      <Upload className="h-3.5 w-3.5" />
                      Load .pem File
                      <input
                        type="file"
                        accept=".pem,.key,.txt"
                        className="sr-only"
                        onChange={(e) => void handleImportPemFile(e)}
                      />
                    </label>
                    <Textarea
                      id="localImportPem"
                      className="min-h-20 font-mono text-[11px]"
                      placeholder="-----BEGIN PRIVATE KEY-----"
                      value={importPemText}
                      onChange={(e) => setImportPemText(e.target.value)}
                      disabled={isImportingKey}
                    />
                    <Button
                      type="button"
                      variant="primary"
                      size="sm"
                      className="w-full"
                      disabled={isImportingKey || !importPemText.trim()}
                      onClick={() => void handleImportExistingPrivateKey()}
                    >
                      {isImportingKey
                        ? "Verifying & Importing..."
                        : "Import into IndexedDB"}
                    </Button>
                    {importError ? (
                      <p className="text-xs font-medium text-red-700">
                        {importError}
                      </p>
                    ) : null}
                    {importSuccess ? (
                      <p className="text-xs font-medium text-emerald-700">
                        {importSuccess}
                      </p>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ) : null}

            <div className="space-y-2">
              {members.map((member) => (
                <div
                  key={member.userId}
                  className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-xs"
                >
                  <div>
                    <p className="font-semibold text-slate-900">
                      {member.fullName}
                    </p>
                    <p className="text-slate-500">{member.role}</p>
                  </div>
                  <Badge variant={member.hasPublicKey ? "emerald" : "amber"}>
                    {member.hasPublicKey ? "Key Ready" : "No Key"}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {selectedComplaintId ? (
        <Card className="border-navy-700/25">
          <CardHeader className="border-b border-slate-100">
            <div className="flex items-center justify-between gap-3">
              <div>
                <CardTitle>
                  Browser-Side Unlock &amp; Share Forwarding (
                  {selectedComplaintId})
                </CardTitle>
                <p className="mt-1 text-sm text-slate-600">
                  Private keys, Shamir shares, and decrypted complaints never
                  leave your browser.
                </p>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelectedComplaintId(null);
                  setUnlockBundle(null);
                  setDecrypted(null);
                }}
              >
                Close
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-5 pt-6">
            {loadingBundle ? (
              <p className="text-sm text-slate-600">
                Loading encrypted share bundle...
              </p>
            ) : unlockBundle ? (
              <div className="grid gap-6 md:grid-cols-2">
                {/* Step B & C: Forward my share to another committee member */}
                <div className="space-y-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-semibold text-navy-950">
                      1. Approve &amp; Forward Your Encrypted Share
                    </h4>
                    <Badge
                      variant={
                        unlockBundle.myEncryptedShare ? "navy" : "amber"
                      }
                    >
                      {unlockBundle.myEncryptedShare
                        ? "Share Available"
                        : "No Share"}
                    </Badge>
                  </div>
                  <p className="text-xs leading-relaxed text-slate-600">
                    Decrypts your share locally with your IndexedDB key,
                    re-encrypts it for the selected co-approver&apos;s public
                    key, and forwards only ciphertext.
                  </p>

                  <FormField
                    id="recipientMemberId"
                    label="Forward To Committee Officer"
                  >
                    <Select
                      id="recipientMemberId"
                      value={effectiveRecipientId}
                      onChange={(e) => setRecipientMemberId(e.target.value)}
                      disabled={
                        isUnlocking || otherActiveMembersWithKeys.length === 0
                      }
                    >
                      {otherActiveMembersWithKeys.length === 0 ? (
                        <option value="">No other active members with keys</option>
                      ) : (
                        otherActiveMembersWithKeys.map((m) => (
                          <option key={m.userId} value={m.userId}>
                            {m.fullName} ({m.role})
                          </option>
                        ))
                      )}
                    </Select>
                  </FormField>

                  <Button
                    type="button"
                    variant="outline"
                    disabled={
                      isUnlocking ||
                      localKeyStatus !== "ready" ||
                      !unlockBundle.myEncryptedShare ||
                      !effectiveRecipientId
                    }
                    onClick={() => void handleForwardShare()}
                    className="w-full"
                  >
                    <Send className="h-4 w-4" />
                    {isUnlocking
                      ? "Encrypting Share Locally..."
                      : "Decrypt Locally & Forward Share"}
                  </Button>
                </div>

                {/* Step D: Reconstruct AES key and decrypt locally */}
                <div className="space-y-3 rounded-xl border border-navy-700/20 bg-navy-50/40 p-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-semibold text-navy-950">
                      2. Reconstruct &amp; Decrypt Locally
                    </h4>
                    <Badge
                      variant={
                        unlockBundle.forwardedSharesToMe.length >= 1
                          ? "emerald"
                          : "amber"
                      }
                    >
                      {unlockBundle.forwardedSharesToMe.length} Forwarded to You
                    </Badge>
                  </div>
                  <p className="text-xs leading-relaxed text-slate-600">
                    Combines a forwarded share encrypted for you with your own
                    share locally in browser memory using Shamir GF(256), then
                    decrypts AES-256-GCM locally.
                  </p>

                  {unlockBundle.forwardedSharesToMe.length > 0 ? (
                    <ul className="space-y-1 text-xs text-slate-700">
                      {unlockBundle.forwardedSharesToMe.map((item) => {
                        const senderName =
                          members.find((m) => m.userId === item.senderMemberId)
                            ?.fullName ?? item.senderMemberId;
                        return (
                          <li key={item.senderMemberId}>
                            &bull; Encrypted share from{" "}
                            <strong>{senderName}</strong>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500">
                      Waiting for another committee officer to forward an
                      encrypted share to you.
                    </p>
                  )}

                  <Button
                    type="button"
                    variant="primary"
                    disabled={
                      isUnlocking ||
                      localKeyStatus !== "ready" ||
                      !unlockBundle.myEncryptedShare ||
                      unlockBundle.forwardedSharesToMe.length === 0
                    }
                    onClick={() => void handleDecryptLocally()}
                    className="w-full"
                  >
                    <LockOpen className="h-4 w-4" />
                    {isUnlocking
                      ? "Decrypting Locally..."
                      : "Decrypt Complaint in Browser"}
                  </Button>
                </div>
              </div>
            ) : null}

            {unlockError ? (
              <StatusNotice title="Local Unlock Notice" variant="warning">
                {unlockError}
              </StatusNotice>
            ) : null}

            {unlockFeedback ? (
              <StatusNotice title="C2 Zero-Knowledge Status" variant="success">
                {unlockFeedback}
              </StatusNotice>
            ) : null}

            {decrypted && decrypted.complaintId === selectedComplaintId ? (
              <div className="space-y-3 rounded-xl border border-emerald-200 bg-emerald-50/40 p-4 text-sm text-slate-800">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <p className="font-semibold text-emerald-950">
                    Decrypted Complaint Payload (Browser Memory Only)
                  </p>
                  <div className="flex items-center gap-2">
                    <Select
                      value={
                        complaints.find((c) => c.id === decrypted.complaintId)
                          ?.status ??
                        unlockBundle?.status ??
                        "submitted"
                      }
                      disabled={updatingStatusId === decrypted.complaintId}
                      onChange={(e) =>
                        void handleStatusChange(
                          decrypted.complaintId,
                          e.target.value
                        )
                      }
                      className="h-8 w-40 bg-white py-1 text-xs"
                      aria-label="Update selected case status"
                    >
                      {PLANNED_CASE_STAGES.map((stage) => (
                        <option key={stage.id} value={stage.id}>
                          {stage.label}
                        </option>
                      ))}
                    </Select>
                    <Button
                      type="button"
                      size="sm"
                      variant="primary"
                      disabled={
                        updatingStatusId === decrypted.complaintId ||
                        (complaints.find((c) => c.id === decrypted.complaintId)
                          ?.status ?? unlockBundle?.status) === "resolved"
                      }
                      onClick={() =>
                        void handleStatusChange(decrypted.complaintId, "resolved")
                      }
                    >
                      {updatingStatusId === decrypted.complaintId
                        ? "Saving..."
                        : "Mark Resolved"}
                    </Button>
                  </div>
                </div>
                <pre className="overflow-x-auto rounded-lg bg-white p-3 font-mono text-xs text-slate-800">
                  {JSON.stringify(decrypted.payload, null, 2)}
                </pre>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {currentMember ? (
        <Card subtle>
          <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-navy-800" />
              <CardTitle>Hash-Chained Audit Logs</CardTitle>
            </div>
            <Badge variant={auditChainValid ? "emerald" : "amber"}>
              {auditChainValid === null
                ? "Not Loaded"
                : auditChainValid
                  ? "SHA-256 Chain Verified"
                  : "Chain Mismatch"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-2">
            {auditLogs.length === 0 ? (
              <p className="text-xs text-slate-500">No audit entries yet.</p>
            ) : (
              auditLogs.slice(0, 10).map((log) => (
                <div
                  key={log.id}
                  className="flex flex-col justify-between gap-1 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-xs sm:flex-row sm:items-center"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant="navy">{log.event_type}</Badge>
                    <span className="font-mono text-slate-600">
                      {log.complaint_id.slice(0, 8)}...
                    </span>
                  </div>
                  <span className="text-slate-500">
                    {new Date(log.created_at).toLocaleString()}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
