/** Derive the normal backend tenant header from same-origin BFF context. */
export function applyServerDerivedTenantHeader(
  headers: Headers,
  cookieTenantId: string | undefined,
  path = '',
): void {
  // Platform routes resolve database platform grants, not a selected tenant.
  if (path.startsWith('/api/platform/')) {
    headers.delete('X-Tenant-ID');
    return;
  }
  if (headers.has('X-Tenant-ID')) return;
  if (cookieTenantId && /^\d+$/.test(cookieTenantId)) {
    headers.set('X-Tenant-ID', cookieTenantId);
  }
}
