import {
  INCIDENT_CATEGORIES,
  PLANNED_CASE_STAGES,
  URGENCY_LEVELS,
} from "@/lib/constants";

export const MAX_EVIDENCE_FILES = 3;
export const MAX_EVIDENCE_BYTES = 5 * 1024 * 1024; // 5 MB
export const ALLOWED_EVIDENCE_MIME_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "application/pdf",
  "text/plain",
]);

export const RETENTION_POLICY_OPTIONS = [
  { days: 30, label: "30 Days (Rapid Auto-Shred)" },
  { days: 90, label: "90 Days (Standard Investigation Window)" },
  { days: 365, label: "365 Days (Extended Compliance Archive)" },
] as const;

const ALLOWED_RETENTION_DAYS = new Set<number>(
  RETENTION_POLICY_OPTIONS.map((option) => option.days)
);

export function parseRetentionDays(value: unknown, fallbackDays = 90): number {
  const numeric =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Number.parseInt(value.trim(), 10)
        : Number.NaN;
  return ALLOWED_RETENTION_DAYS.has(numeric) ? numeric : fallbackDays;
}

/** Basic server-side input sanitization and validation helpers. */

export function readNonEmptyString(
  value: unknown,
  minLength = 1,
  maxLength = 5000
): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length < minLength || trimmed.length > maxLength) {
    return null;
  }
  return trimmed;
}

export function isIsoDateString(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  return /^\d{4}-\d{2}-\d{2}$/.test(value.trim());
}

export function isValidCaseIdFormat(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  return /^[A-Z0-9-]{6,32}$/.test(value.trim().toUpperCase());
}

export function isValidCategory(value: unknown): value is string {
  return (
    typeof value === "string" &&
    (INCIDENT_CATEGORIES as readonly string[]).includes(value.trim())
  );
}

export function isValidUrgency(value: unknown): value is string {
  return (
    typeof value === "string" &&
    URGENCY_LEVELS.some((level) => level.value === value.trim())
  );
}

export function isValidComplaintStatus(value: unknown): value is string {
  return (
    typeof value === "string" &&
    PLANNED_CASE_STAGES.some((stage) => stage.id === value.trim())
  );
}

export function isUuid(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value.trim()
  );
}
