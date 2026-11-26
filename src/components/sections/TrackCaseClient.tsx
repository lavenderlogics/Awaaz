"use client";

import {
  CheckCircle2,
  Clock,
  FileUp,
  Lock,
  MessageSquare,
  Search,
  Send,
  Shield,
  Trash2,
} from "lucide-react";
import { type FormEvent, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input, Textarea } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { PLANNED_CASE_STAGES } from "@/lib/constants";
import {
  encryptComplaintInBrowser,
  encryptEvidenceBytesInBrowser,
  type PublicCommitteeRecipient,
  validateEvidenceBytesSignature,
} from "@/lib/security/client-crypto";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  MAX_EVIDENCE_BYTES,
} from "@/lib/security/validation";

interface TimelineEntry {
  id: number;
  eventType: string;
  title: string;
  detail: string;
  createdAt: string;
  digest?: string;
}

interface DeletionReceiptSummary {
  receiptId: string;
  shreddedAt: string;
  deletedFileCount: number;
  receiptDigest: string;
}

interface FollowUpMessage {
  id: number;
  sender: "committee" | "reporter";
  note: string;
  createdAt: string;
}

interface TrackResult {
  complaintId: string | null;
  caseCode: string;
  category: string;
  status: string;
  encryptionAlgorithm: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  retentionUntil: string | null;
  evidenceCount: number;
  recoveryVerified: boolean | null;
  timeline: TimelineEntry[];
  deletionReceipts: DeletionReceiptSummary[];
  followUpMessages: FollowUpMessage[];
}

/** Live anonymous Case ID lookup, event timeline, and encrypted follow-up portal. */
export function TrackCaseClient() {
  const [caseId, setCaseId] = useState("");
  const [recoverySecret, setRecoverySecret] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<TrackResult | null>(null);

  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [isUploading, setIsUploading] = useState(false);

  const [followUpText, setFollowUpText] = useState("");
  const [isSendingFollowUp, setIsSendingFollowUp] = useState(false);
  const [followUpStatus, setFollowUpStatus] = useState("");
  const [followUpError, setFollowUpError] = useState("");

  const handleLookup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = caseId.trim().toUpperCase();

    if (!trimmed) {
      setError("Please enter your Case ID.");
      setResult(null);
      return;
    }

    setError("");
    setUploadStatus("");
    setUploadError("");
    setIsLoading(true);

    try {
      const res = await fetch("/api/complaints/track", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          caseCode: trimmed,
          recoverySecret: recoverySecret.trim() || undefined,
        }),
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setResult(null);
        setError(
          typeof json.error === "string"
            ? json.error
            : "Unable to find that Case ID."
        );
        return;
      }

      setResult({
        complaintId:
          typeof json.complaintId === "string" ? json.complaintId : null,
        caseCode: String(json.caseCode ?? trimmed),
        category: String(json.category ?? "General"),
        status: String(json.status ?? "submitted"),
        encryptionAlgorithm:
          typeof json.encryptionAlgorithm === "string"
            ? json.encryptionAlgorithm
            : null,
        createdAt: typeof json.createdAt === "string" ? json.createdAt : null,
        updatedAt: typeof json.updatedAt === "string" ? json.updatedAt : null,
        retentionUntil:
          typeof json.retentionUntil === "string" ? json.retentionUntil : null,
        evidenceCount: Number(json.evidenceCount ?? 0),
        recoveryVerified:
          typeof json.recoveryVerified === "boolean"
            ? json.recoveryVerified
            : null,
        timeline: Array.isArray(json.timeline)
          ? (json.timeline as TimelineEntry[])
          : [],
        deletionReceipts: Array.isArray(json.deletionReceipts)
          ? (json.deletionReceipts as DeletionReceiptSummary[])
          : [],
        followUpMessages: Array.isArray(json.followUpMessages)
          ? (json.followUpMessages as FollowUpMessage[])
          : [],
      });
    } catch {
      setResult(null);
      setError("Network error while looking up complaint status.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleEvidenceUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (
      !result ||
      !result.complaintId ||
      !evidenceFile ||
      !recoverySecret.trim()
    ) {
      return;
    }

    if (evidenceFile.size > MAX_EVIDENCE_BYTES) {
      setUploadError("Evidence file exceeds the 5 MB limit.");
      return;
    }

    if (!ALLOWED_EVIDENCE_MIME_TYPES.has(evidenceFile.type)) {
      setUploadError(
        `Unsupported file type (${evidenceFile.type || "unknown"}). Allowed: PNG, JPEG, WEBP, PDF, TXT.`
      );
      return;
    }

    setIsUploading(true);
    setUploadError("");
    setUploadStatus("");

    try {
      const keysRes = await fetch("/api/committee/public-keys", {
        cache: "no-store",
      });
      const keysJson = (await keysRes.json()) as {
        members?: PublicCommitteeRecipient[];
        error?: string;
      };

      if (
        !keysRes.ok ||
        !Array.isArray(keysJson.members) ||
        keysJson.members.length < 2
      ) {
        setUploadError(
          keysJson.error ??
            "Unable to load committee public keys. Evidence was not uploaded."
        );
        return;
      }

      const fileId = window.crypto.randomUUID();
      const rawBytes = new Uint8Array(await evidenceFile.arrayBuffer());
      const signatureCheck = validateEvidenceBytesSignature(
        rawBytes,
        evidenceFile.type
      );
      if (!signatureCheck.ok) {
        rawBytes.fill(0);
        setUploadError(signatureCheck.error);
        return;
      }
      const encryptedResult = await encryptEvidenceBytesInBrowser({
        fileBytes: rawBytes,
        mimeType: evidenceFile.type,
        complaintId: result.complaintId,
        fileId,
        recipients: keysJson.members,
      });
      rawBytes.fill(0);

      const copy = new Uint8Array(encryptedResult.encryptedBytes.byteLength);
      copy.set(encryptedResult.encryptedBytes);
      const encryptedBlob = new Blob([copy.buffer], {
        type: "application/octet-stream",
      });

      const formData = new FormData();
      formData.set("caseCode", result.caseCode);
      formData.set("recoverySecret", recoverySecret.trim());
      formData.set("fileId", fileId);
      formData.set("mimeType", encryptedResult.mimeType);
      formData.set("file", encryptedBlob, `${fileId}.enc`);

      const res = await fetch("/api/evidence", {
        method: "POST",
        body: formData,
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setUploadError(
          typeof json.error === "string"
            ? json.error
            : "Failed to upload encrypted evidence."
        );
        return;
      }

      setEvidenceFile(null);
      setUploadStatus(
        "Browser-encrypted evidence uploaded to awaaz-evidence."
      );
      setResult((prev) =>
        prev ? { ...prev, evidenceCount: prev.evidenceCount + 1 } : prev
      );
    } catch {
      setUploadError(
        "Browser encryption failed. Raw evidence was not transmitted."
      );
    } finally {
      setIsUploading(false);
    }
  };

  const handleSendFollowUp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!result || !result.complaintId || !recoverySecret.trim()) return;
    const trimmedMessage = followUpText.trim();
    if (trimmedMessage.length < 5) {
      setFollowUpError("Please enter at least 5 characters for your follow-up note.");
      return;
    }

    setIsSendingFollowUp(true);
    setFollowUpError("");
    setFollowUpStatus("");

    try {
      const keysRes = await fetch("/api/committee/public-keys", {
        cache: "no-store",
      });
      const keysJson = (await keysRes.json()) as {
        members?: PublicCommitteeRecipient[];
        error?: string;
      };
      if (!keysRes.ok || !Array.isArray(keysJson.members) || keysJson.members.length < 2) {
        setFollowUpError(
          keysJson.error ?? "Unable to load committee public keys for encryption."
        );
        return;
      }

      const messageId = window.crypto.randomUUID();
      const encryptedEnvelope = await encryptComplaintInBrowser({
        complaintId: messageId,
        payload: {
          type: "reporter_followup",
          parentComplaintId: result.complaintId,
          message: trimmedMessage,
          sentAt: new Date().toISOString(),
        },
        recipients: keysJson.members,
      });

      const res = await fetch("/api/complaints/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          caseCode: result.caseCode,
          recoverySecret: recoverySecret.trim(),
          messageId,
          encryptedEnvelope,
        }),
      });
      const json = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        setFollowUpError(
          typeof json.error === "string"
            ? json.error
            : "Unable to send encrypted follow-up."
        );
        return;
      }

      const sentAt = String(json.sentAt ?? new Date().toISOString());
      setFollowUpText("");
      setFollowUpStatus("Follow-up note encrypted in browser and sent securely.");
      setResult((prev) =>
        prev
          ? {
              ...prev,
              followUpMessages: [
                ...prev.followUpMessages,
                {
                  id: Date.now(),
                  sender: "reporter",
                  note: "Encrypted follow-up message sent (AES-256-GCM ciphertext stored for committee decryption).",
                  createdAt: sentAt,
                },
              ],
              timeline: [
                ...prev.timeline,
                {
                  id: Date.now(),
                  eventType: "REPORTER_FOLLOWUP_SENT",
                  title: "Encrypted Reporter Follow-Up Sent",
                  detail: "Follow-up message encrypted in browser for committee review.",
                  createdAt: sentAt,
                },
              ],
            }
          : prev
      );
    } catch {
      setFollowUpError(
        "Client-side encryption failed. Plaintext message was never transmitted."
      );
    } finally {
      setIsSendingFollowUp(false);
    }
  };

  const activeStageIndex = result
    ? PLANNED_CASE_STAGES.findIndex((s) => s.id === result.status)
    : -1;

  return (
    <div className="space-y-8">
      <Card>
        <CardHeader className="border-b border-slate-100">
          <CardTitle>Look Up Complaint Status</CardTitle>
          <p className="mt-1 text-sm text-slate-600">
            Enter your Case ID (and optionally your Recovery Secret to attach
            additional browser-encrypted evidence).
          </p>
        </CardHeader>
        <CardContent className="pt-6">
          <form onSubmit={handleLookup} className="space-y-4" noValidate>
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                id="caseId"
                label="Case Reference ID"
                hint="Example: AWZ-ABCD-EFGH-JKLM"
                error={error}
                required
              >
                <Input
                  id="caseId"
                  type="text"
                  className="font-mono uppercase"
                  placeholder="AWZ-XXXX-XXXX-XXXX"
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                  disabled={isLoading}
                />
              </FormField>

              <FormField
                id="recoverySecret"
                label="Recovery Secret (Optional)"
                hint="Only needed if adding follow-up encrypted evidence."
              >
                <Input
                  id="recoverySecret"
                  type="text"
                  className="font-mono uppercase"
                  placeholder="XXXXXX-XXXXXX"
                  value={recoverySecret}
                  onChange={(e) => setRecoverySecret(e.target.value)}
                  disabled={isLoading}
                />
              </FormField>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={isLoading}
            >
              <Search className="h-4 w-4" />
              {isLoading ? "Checking..." : "Check Status"}
            </Button>
          </form>

          {isLoading ? (
            <div className="mt-6 space-y-3 border-t border-slate-100 pt-6" aria-busy="true">
              <div className="h-6 w-48 animate-pulse rounded-lg bg-slate-200" />
              <div className="grid gap-3 sm:grid-cols-4">
                <div className="h-14 animate-pulse rounded-xl bg-slate-100" />
                <div className="h-14 animate-pulse rounded-xl bg-slate-100" />
                <div className="h-14 animate-pulse rounded-xl bg-slate-100" />
                <div className="h-14 animate-pulse rounded-xl bg-slate-100" />
              </div>
            </div>
          ) : result ? (
            <div className="mt-6 space-y-5 border-t border-slate-100 pt-6" aria-live="polite">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold tracking-wider text-slate-500 uppercase">
                    Case Status
                  </p>
                  <p className="mt-1 font-mono text-lg font-bold text-navy-950">
                    {result.caseCode}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="navy">{result.status}</Badge>
                  <Badge variant="outline">{result.category}</Badge>
                  <Badge variant="slate">
                    {result.evidenceCount} Evidence File
                    {result.evidenceCount === 1 ? "" : "s"}
                  </Badge>
                </div>
              </div>

              <div className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4 text-xs text-slate-600 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <span className="font-semibold text-slate-900">Submitted:</span>{" "}
                  {result.createdAt
                    ? new Date(result.createdAt).toLocaleString()
                    : "—"}
                </div>
                <div>
                  <span className="font-semibold text-slate-900">Updated:</span>{" "}
                  {result.updatedAt
                    ? new Date(result.updatedAt).toLocaleString()
                    : "—"}
                </div>
                <div>
                  <span className="font-semibold text-slate-900">
                    Encryption:
                  </span>{" "}
                  {result.encryptionAlgorithm ?? "AES-256-GCM"}
                </div>
                <div>
                  <span className="font-semibold text-slate-900">
                    Auto-Shred Date:
                  </span>{" "}
                  {result.retentionUntil
                    ? new Date(result.retentionUntil).toLocaleDateString()
                    : "—"}
                </div>
              </div>

              {result.deletionReceipts.length > 0 ? (
                <div className="space-y-2 rounded-xl border border-amber-200 bg-amber-50/50 p-4 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-amber-950">
                    <Trash2 className="h-4 w-4 text-amber-700" />
                    Auto-Shred Deletion Receipts Preserved
                  </div>
                  {result.deletionReceipts.map((receipt) => (
                    <div
                      key={receipt.receiptId}
                      className="rounded-lg border border-amber-200/80 bg-white px-3 py-2 text-slate-700"
                    >
                      <p>
                        Purged <strong>{receipt.deletedFileCount}</strong> file(s) on{" "}
                        {new Date(receipt.shreddedAt).toLocaleString()}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                        Receipt Digest: {receipt.receiptDigest}
                      </p>
                    </div>
                  ))}
                </div>
              ) : null}

              {result.timeline.length > 0 ? (
                <div className="space-y-3 rounded-xl border border-slate-200 bg-white p-4">
                  <p className="text-xs font-semibold tracking-wider text-navy-900 uppercase">
                    Case Activity Timeline
                  </p>
                  <ol className="space-y-2.5 border-l-2 border-navy-100 pl-4">
                    {result.timeline.map((item) => (
                      <li key={`${item.id}-${item.eventType}`} className="relative text-xs">
                        <span className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-semibold text-slate-900">
                            {item.title}
                          </span>
                          <span className="text-slate-500">
                            {new Date(item.createdAt).toLocaleString()}
                          </span>
                        </span>
                        <p className="mt-0.5 text-slate-600">{item.detail}</p>
                      </li>
                    ))}
                  </ol>
                </div>
              ) : null}

              {result.recoveryVerified === false ? (
                <StatusNotice title="Recovery Secret Mismatch" variant="warning">
                  The Case ID matched, but the Recovery Secret did not match.
                  Follow-up communication and evidence uploads remain locked.
                </StatusNotice>
              ) : null}

              {result.recoveryVerified === true ? (
                <div className="grid gap-4 lg:grid-cols-2">
                  <form
                    onSubmit={handleEvidenceUpload}
                    className="space-y-3 rounded-xl border border-navy-700/20 bg-navy-50/40 p-4"
                  >
                    <div className="flex items-center gap-2 text-sm font-semibold text-navy-950">
                      <FileUp className="h-4 w-4 text-navy-700" />
                      Attach Follow-Up Encrypted Evidence
                    </div>
                    <div className="flex flex-col gap-3">
                      <input
                        type="file"
                        accept="image/png,image/jpeg,image/webp,application/pdf,text/plain"
                        onChange={(e) =>
                          setEvidenceFile(e.target.files?.[0] ?? null)
                        }
                        className="text-xs text-slate-700"
                      />
                      <Button
                        type="submit"
                        variant="primary"
                        size="sm"
                        disabled={!evidenceFile || isUploading}
                      >
                        {isUploading
                          ? "Encrypting in Browser..."
                          : "Upload Encrypted File"}
                      </Button>
                    </div>
                    {uploadError ? (
                      <p className="text-xs font-medium text-red-700">
                        {uploadError}
                      </p>
                    ) : null}
                    {uploadStatus ? (
                      <p className="text-xs font-medium text-emerald-700">
                        {uploadStatus}
                      </p>
                    ) : null}
                  </form>

                  <form
                    onSubmit={handleSendFollowUp}
                    className="space-y-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-2 text-sm font-semibold text-navy-950">
                        <MessageSquare className="h-4 w-4 text-navy-700" />
                        Secure Follow-Up Communication
                      </span>
                      <Badge variant="emerald">
                        <Lock className="mr-1 h-3 w-3" />
                        Encrypted
                      </Badge>
                    </div>

                    {result.followUpMessages.length > 0 ? (
                      <div className="max-h-36 space-y-2 overflow-y-auto rounded-lg border border-slate-200 bg-white p-2.5 text-xs">
                        {result.followUpMessages.map((msg) => (
                          <div key={msg.id} className="space-y-0.5">
                            <div className="flex items-center justify-between text-[11px] text-slate-500">
                              <span className="font-semibold text-navy-900">
                                {msg.sender === "committee"
                                  ? "Committee Update"
                                  : "You (Encrypted)"}
                              </span>
                              <span>
                                {new Date(msg.createdAt).toLocaleString()}
                              </span>
                            </div>
                            <p className="text-slate-700">{msg.note}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-slate-500">
                        No follow-up messages yet. Messages you send are encrypted
                        with AES-256-GCM in your browser before transmission.
                      </p>
                    )}

                    <Textarea
                      id="followUpMessage"
                      className="min-h-20 bg-white text-xs"
                      placeholder="Add anonymous clarifications or updates for the committee..."
                      value={followUpText}
                      onChange={(e) => setFollowUpText(e.target.value)}
                      disabled={isSendingFollowUp}
                    />
                    <Button
                      type="submit"
                      variant="primary"
                      size="sm"
                      disabled={isSendingFollowUp || !followUpText.trim()}
                    >
                      <Send className="h-3.5 w-3.5" />
                      {isSendingFollowUp
                        ? "Encrypting in Browser..."
                        : "Send Encrypted Follow-Up"}
                    </Button>
                    {followUpError ? (
                      <p className="text-xs font-medium text-red-700">
                        {followUpError}
                      </p>
                    ) : null}
                    {followUpStatus ? (
                      <p className="text-xs font-medium text-emerald-700">
                        {followUpStatus}
                      </p>
                    ) : null}
                  </form>
                </div>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card subtle>
        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Case Review Lifecycle</CardTitle>
            <p className="mt-1 text-sm text-slate-600">
              Non-sensitive status progression for your Case ID.
            </p>
          </div>
          <Badge variant="outline">
            {result ? `Current: ${result.status}` : "Status Stages"}
          </Badge>
        </CardHeader>
        <CardContent className="pt-2">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {PLANNED_CASE_STAGES.map((stage, index) => {
              const isCompletedOrActive =
                activeStageIndex >= 0 && index <= activeStageIndex;
              return (
                <div
                  key={stage.id}
                  className={`relative rounded-xl border p-4 shadow-2xs ${
                    isCompletedOrActive
                      ? "border-navy-700 bg-white ring-1 ring-navy-700/15"
                      : "border-slate-200 bg-white"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`inline-flex h-7 w-7 items-center justify-center rounded-lg font-mono text-xs font-bold ${
                        isCompletedOrActive
                          ? "bg-navy-900 text-white"
                          : "bg-navy-50 text-navy-900"
                      }`}
                    >
                      0{index + 1}
                    </span>
                    {index === 0 ? (
                      <Shield className="h-4 w-4 text-navy-700" />
                    ) : index === PLANNED_CASE_STAGES.length - 1 ? (
                      <CheckCircle2
                        className={`h-4 w-4 ${
                          isCompletedOrActive
                            ? "text-emerald-700"
                            : "text-slate-400"
                        }`}
                      />
                    ) : (
                      <Clock
                        className={`h-4 w-4 ${
                          isCompletedOrActive
                            ? "text-navy-700"
                            : "text-slate-400"
                        }`}
                      />
                    )}
                  </div>
                  <h4 className="mt-3 text-sm font-semibold text-slate-900">
                    {stage.label}
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-slate-600">
                    {stage.description}
                  </p>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
