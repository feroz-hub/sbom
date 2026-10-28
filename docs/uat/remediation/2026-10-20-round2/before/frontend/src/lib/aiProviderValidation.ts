const LOCAL_HTTP_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  'host.docker.internal',
]);

/** Mirrors the backend's custom OpenAI transport-safety rule. */
export function customOpenAiBaseUrlError(value: string): string | null {
  if (!value.trim()) return 'Base URL is required.';
  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'https:') return null;
    if (parsed.protocol === 'http:' && LOCAL_HTTP_HOSTS.has(parsed.hostname.toLowerCase())) {
      return null;
    }
  } catch {
    // Return the same safe guidance for malformed values.
  }
  return 'Use HTTPS for remote endpoints; HTTP is allowed only for localhost.';
}
