/**
 * Environment-variable helpers.
 *
 * This file is deliberately side-effect free: importing it will NOT evaluate
 * any env vars or throw. The actual resolution happens when `resolveBaseUrl`
 * is called (from `lib/api.ts` at module load). Keeping the helper separate
 * from `lib/api.ts` makes it trivial to unit-test without needing to bypass
 * the api.ts module's top-level BASE_URL evaluation.
 */

/**
 * Resolve the backend base URL from an environment variable.
 *
 * Strips any trailing slash so `${BASE_URL}/api/foo` always produces a clean
 * `http://host/api/foo` URL regardless of whether the user's env var ends
 * in a slash.
 *
 * Throws if the value is missing or empty — we intentionally do not fall
 * back to a default host in source, because a silent fallback in
 * production sends every call into the void with no visible error.
 *
 * @param raw  Optional override, mainly for tests. Defaults to
 *             `process.env.NEXT_PUBLIC_API_URL`.
 * @throws Error if the value is missing, empty, or whitespace-only.
 */
export function resolveBaseUrl(
  raw: string | undefined = process.env.NEXT_PUBLIC_API_URL,
): string {
  if (raw === undefined || raw === null || raw.trim() === '') {
    throw new Error(
      'NEXT_PUBLIC_API_URL is not configured. Set it in your environment ' +
        '(see frontend/.env.development for the dev default and ' +
        'frontend/.env.local.example for the template) before building the frontend.',
    );
  }
  return raw.replace(/\/$/, '');
}
