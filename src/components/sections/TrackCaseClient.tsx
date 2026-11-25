"use client";

import { CheckCircle2, Clock, FileUp, Search, Shield } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { PLANNED_CASE_STAGES } from "@/lib/constants";
import {
  encryptEvidenceBytesInBrowser,
  type PublicCommitteeRecipient,
} from "@/lib/security/client-crypto";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  MAX_EVIDENCE_BYTES,
} from "@/lib/security/validation";

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
}

/** Live anonymous Case ID lookup and client-encrypted follow-up evidence uploader. */
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

          {result ? (
            <div className="mt-6 space-y-4 border-t border-slate-100 pt-6">
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

              <div className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4 text-xs text-slate-600 sm:grid-cols-3">
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
              </div>

              {result.recoveryVerified === false ? (
                <StatusNotice title="Recovery Secret Mismatch" variant="warning">
                  The Case ID matched, but the Recovery Secret did not match.
                  Follow-up evidence uploads remain locked.
                </StatusNotice>
              ) : null}

              {result.recoveryVerified === true ? (
                <form
                  onSubmit={handleEvidenceUpload}
                  className="space-y-3 rounded-xl border border-navy-700/20 bg-navy-50/40 p-4"
                >
                  <div className="flex items-center gap-2 text-sm font-semibold text-navy-950">
                    <FileUp className="h-4 w-4 text-navy-700" />
                    Attach Follow-Up Encrypted Evidence
                  </div>
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
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
