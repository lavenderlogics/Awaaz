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
