const DISALLOWED_ROUTE_PREFIXES = [
  '/auth/callback',
  '/logged-out',
  '/verification-required',
  '/access-denied',
  '/access-pending',
  '/api',
];

/**
 * Checks whether a given path corresponds to an internal auth lifecycle or API route
 * that should never be used as a post-login redirection target.
 */
export function isDisallowedReturnPath(pathname: string): boolean {
  const normalized = pathname.toLowerCase().replace(/\/+$/, '') || '/';
  return DISALLOWED_ROUTE_PREFIXES.some(
    (prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`),
  );
}

/**
 * Validates and sanitizes a post-login return path.
 *
 * Rules:
 * - Must be a non-empty string.
 * - Must start with a single leading slash (rejects protocol-relative and external schemes).
 * - Must not contain backslashes.
 * - Must not contain control characters.
 * - Must parse as a valid URL relative to origin without changing origin.
 * - Decoded path must also not contain backslashes or start with '//'.
 * - Must not target auth lifecycle-only routes (/auth/callback, /logged-out,
 *   /verification-required, /access-denied, /access-pending) or /api.
 *
 * Preserves exact valid application paths and query parameters (e.g. /sboms/42?tab=components).
 * Returns '/' whenever the input is invalid, missing, or disallowed.
 */
export function safeReturnPath(value: string | null | undefined): string {
  if (!value || typeof value !== 'string') return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  if (/[\x00-\x1f\x7f]/.test(value)) return '/';

  try {
    const parsed = new URL(value, 'http://localhost');
    if (parsed.origin !== 'http://localhost') return '/';

    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(parsed.pathname);
    } catch {
      return '/';
    }

    if (
      decodedPath.startsWith('//') ||
      decodedPath.includes('\\') ||
      isDisallowedReturnPath(parsed.pathname) ||
      isDisallowedReturnPath(decodedPath)
    ) {
      return '/';
    }

    return value;
  } catch {
    return '/';
  }
}
