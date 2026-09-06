/** Derive the normal backend tenant header from same-origin BFF context. */
export function applyServerDerivedTenantHeader(
  headers: Headers,
  cookieTenantId: string | undefined,
): void {
  if (headers.has('X-Tenant-ID')) return;
  if (cookieTenantId && /^\d+$/.test(cookieTenantId)) {
    headers.set('X-Tenant-ID', cookieTenantId);
  }
}
