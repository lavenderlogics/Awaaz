"use client";

import {
  CheckCircle2,
  ClipboardList,
  Clock,
  Download,
  Inbox,
  KeyRound,
  LockOpen,
  LogOut,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input, Select, Textarea } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { PLANNED_CASE_STAGES } from "@/lib/constants";
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
  evidenceCount: number;
}

interface CommitteeMemberSummary {
  userId: string;
  fullName: string;
  role: string;
  hasPublicKey: boolean;
  isActive: boolean;
}

interface AuditLogEntry {
  id: number;
  complaint_id: string;
  actor_member_id: string | null;
  event_type: string;
  event_details: Record<string, unknown> | null;
  created_at: string;
}

interface DecryptedDetails {
  complaintId: string;
  payload: Record<string, unknown>;
  evidenceFiles: Array<{
    id: string;
    mime_type: string | null;
    file_size: number | null;
    file_hash: string | null;
  }>;
}

interface CommitteeDashboardClientProps {
  isConfigured: boolean;
  isServiceRoleReady: boolean;
  userEmail: string | null;
  userId: string | null;
}

const SUMMARY_METRICS = [
  { key: "total", label: "Total Complaints", icon: ClipboardList },
  { key: "pending", label: "Pending Triage", icon: Clock },
  { key: "awaitingUnlock", label: "Awaiting 2-Key Unlock", icon: ShieldAlert },
  { key: "resolved", label: "Resolved Cases", icon: CheckCircle2 },
] as const;

function arrayBufferToPem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

/** Protected committee dashboard connecting auth, key registration, two-key unlock, and audit logs. */
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
    useState<CommitteeMemberSummary | null>(null);

  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditChainValid, setAuditChainValid] = useState<boolean | null>(null);

  const [selectedComplaintId, setSelectedComplaintId] = useState<string | null>(
    null
  );
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [unlockFeedback, setUnlockFeedback] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [decrypted, setDecrypted] = useState<DecryptedDetails | null>(null);

  const [generatedPrivatePem, setGeneratedPrivatePem] = useState<string | null>(
    null
  );
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [keyStatusMessage, setKeyStatusMessage] = useState("");

  const loadDashboard = useCallback(async () => {
    if (!userEmail || !isServiceRoleReady) return;

    try {
      const [dashRes, auditRes] = await Promise.all([
        fetch("/api/committee/dashboard"),
        fetch("/api/committee/audit-logs"),
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
      setCurrentMember(
        (dashJson.currentMember as CommitteeMemberSummary | null) ?? null
      );

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
  }, [isServiceRoleReady, userEmail]);

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
      awaitingUnlock: complaints.filter(
        (c) => c.approvalCount < c.requiredApprovals
      ).length,
      resolved: complaints.filter((c) =>
        ["resolved", "closed"].includes(c.status)
      ).length,
    };
  }, [complaints, currentMember, userEmail]);

  const handleGenerateAndRegisterKey = async () => {
    setIsGeneratingKey(true);
    setKeyStatusMessage("");
    setApiError("");

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

      const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pkcs8 = await window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
      );

      const publicKeyPem = arrayBufferToPem(spki, "PUBLIC KEY");
      const privateKey = arrayBufferToPem(pkcs8, "PRIVATE KEY");

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

      setGeneratedPrivatePem(privateKey);
      setKeyStatusMessage(
        "RSA-2048 public key saved to committee_members. Download and keep your private key PEM safely—it is never stored on the server."
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
  };

  const handleUnlockOrApprove = async (complaintId: string) => {
    setIsUnlocking(true);
    setUnlockError("");
    setUnlockFeedback("");

    try {
      const res = await fetch("/api/committee/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          complaintId,
          privateKeyPem: privateKeyPem.trim() || undefined,
        }),
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setUnlockError(
          typeof json.error === "string" ? json.error : "Unlock failed."
        );
        return;
      }

      if (json.unlocked === true) {
        setDecrypted({
          complaintId,
          payload: (json.payload as Record<string, unknown>) ?? {},
          evidenceFiles: Array.isArray(json.evidenceFiles)
            ? (json.evidenceFiles as DecryptedDetails["evidenceFiles"])
            : [],
        });
        setUnlockFeedback(
          "Dual-key threshold met (2 approvals). AES-256-GCM payload decrypted."
        );
      } else {
        setDecrypted(null);
        setUnlockFeedback(
          `Approval recorded (${String(json.approvalsCount ?? 1)}/${String(
            json.requiredApprovals ?? 2
          )}). A second committee member must approve to decrypt.`
        );
      }

      setPrivateKeyPem("");
      await loadDashboard();
    } catch {
      setUnlockError("Network error while submitting unlock request.");
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleStatusChange = async (complaintId: string, status: string) => {
    try {
      const res = await fetch("/api/committee/status", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ complaintId, status }),
      });
      if (res.ok) {
        await loadDashboard();
      }
    } catch {
      // Ignore transient UI error; reload will reflect latest state.
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
              {currentMember?.role ?? "Committee"}).
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
                  Complaint payloads remain encrypted until 2 committee members
                  approve unlock.
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
          </CardHeader>

          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 bg-slate-50/80 text-xs font-semibold tracking-wider text-slate-600 uppercase">
                  <tr>
                    <th className="px-5 py-3.5">Complaint ID</th>
                    <th className="px-5 py-3.5">Category</th>
                    <th className="px-5 py-3.5">Approvals</th>
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
                              row.approvalCount >= row.requiredApprovals
                                ? "emerald"
                                : "amber"
                            }
                          >
                            {row.approvalCount}/{row.requiredApprovals} Keys
                          </Badge>
                        </td>
                        <td className="px-5 py-4">
                          <Select
                            value={row.status}
                            onChange={(e) =>
                              void handleStatusChange(row.id, e.target.value)
                            }
                            className="h-8 py-1 text-xs"
                            aria-label={`Update status for ${row.id}`}
                          >
                            {PLANNED_CASE_STAGES.map((stage) => (
                              <option key={stage.id} value={stage.id}>
                                {stage.label}
                              </option>
                            ))}
                          </Select>
                        </td>
                        <td className="px-5 py-4">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setSelectedComplaintId(row.id);
                              setUnlockError("");
                              setUnlockFeedback("");
                              setDecrypted(null);
                            }}
                          >
                            <LockOpen className="h-3.5 w-3.5" />
                            {row.approvalCount >= row.requiredApprovals
                              ? "Decrypt"
                              : "Approve"}
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
                Two-Key Setup
              </span>
            </div>
            <CardTitle className="mt-2">Committee Key Readiness</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm text-slate-600">
            {currentMember ? (
              <div className="space-y-3">
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
                    : currentMember.hasPublicKey
                      ? "Rotate My RSA Public Key"
                      : "Generate & Register My Key"}
                </Button>

                {generatedPrivatePem ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={downloadPrivateKey}
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download Private Key (.pem)
                  </Button>
                ) : null}

                {keyStatusMessage ? (
                  <StatusNotice title="Public Key Saved" variant="success">
                    {keyStatusMessage}
                  </StatusNotice>
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
                  Dual-Key Unlock &amp; Decryption ({selectedComplaintId})
                </CardTitle>
                <p className="mt-1 text-sm text-slate-600">
                  Submit your RSA private key in memory to approve this unlock,
                  or click Decrypt directly if 2 committee members have already
                  approved.
                </p>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setSelectedComplaintId(null)}
              >
                Close
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4 pt-6">
            <FormField
              id="privateKeyPem"
              label="Your RSA Private Key PEM (Optional if already 2 approvals)"
              hint="Processed in server memory only to unwrap your Shamir share; never stored."
            >
              <Textarea
                id="privateKeyPem"
                className="min-h-24 font-mono text-xs"
                placeholder="-----BEGIN PRIVATE KEY-----"
                value={privateKeyPem}
                onChange={(e) => setPrivateKeyPem(e.target.value)}
                disabled={isUnlocking}
              />
            </FormField>

            <div className="flex flex-wrap gap-3">
              <Button
                type="button"
                variant="primary"
                disabled={isUnlocking}
                onClick={() => void handleUnlockOrApprove(selectedComplaintId)}
              >
                <LockOpen className="h-4 w-4" />
                {isUnlocking ? "Verifying Key..." : "Approve / Decrypt Complaint"}
              </Button>
            </div>

            {unlockError ? (
              <StatusNotice title="Unlock Failed" variant="warning">
                {unlockError}
              </StatusNotice>
            ) : null}

            {unlockFeedback ? (
              <StatusNotice title="Unlock Status" variant="success">
                {unlockFeedback}
              </StatusNotice>
            ) : null}

            {decrypted && decrypted.complaintId === selectedComplaintId ? (
              <div className="space-y-3 rounded-xl border border-emerald-200 bg-emerald-50/40 p-4 text-sm text-slate-800">
                <p className="font-semibold text-emerald-950">
                  Decrypted Complaint Payload
                </p>
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
