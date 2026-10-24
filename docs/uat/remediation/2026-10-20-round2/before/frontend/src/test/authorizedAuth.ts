import catalogue from './permissionCatalogue.json';

/** Explicit authorized fixture for existing workflow tests. Denial behavior is tested separately. */
export function authorizedAuth() {
  return {
    user: { userId: 1, roles: ['TENANT_ADMIN', 'PLATFORM_ADMIN'], permissions: catalogue.permissions },
    isLoading: false, isTenantContextLoading: false, bootstrapState: 'ready', bootstrapError: null,
    hasPermission: (permission: string) => catalogue.permissions.includes(permission),
  };
}
