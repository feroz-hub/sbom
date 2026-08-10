export type RoleValue =
  | string
  | {
      id?: string | number;
      code?: string;
      name?: string;
    }
  | null
  | undefined;

const KNOWN_ROLE_LABELS: Record<string, string> = {
  TENANT_ADMIN: 'Tenant Admin',
  SECURITY_ANALYST: 'Security Analyst',
  DEVELOPER: 'Developer',
  VIEWER: 'Viewer',
  PLATFORM_ADMIN: 'Platform Admin',
};

export function getRoleLabel(role: RoleValue): string {
  if (!role) {
    return 'No role';
  }

  if (typeof role === 'string') {
    const trimmed = role.trim();
    if (KNOWN_ROLE_LABELS[trimmed]) {
      return KNOWN_ROLE_LABELS[trimmed];
    }
    return trimmed;
  }

  if (role.name) {
    return role.name;
  }

  if (role.code && KNOWN_ROLE_LABELS[role.code]) {
    return KNOWN_ROLE_LABELS[role.code];
  }

  return (
    role.code ??
    String(role.id ?? 'Unknown role')
  );
}

export function getRoleCode(role: RoleValue): string {
  if (!role) {
    return '';
  }

  if (typeof role === 'string') {
    return role;
  }

  return (
    role.code ??
    role.name ??
    String(role.id ?? '')
  );
}
