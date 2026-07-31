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

  const code = role.code ?? role.name ?? String(role.id ?? '');
  if (code && KNOWN_ROLE_LABELS[code]) {
    return KNOWN_ROLE_LABELS[code];
  }

  return (
    role.name ??
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
