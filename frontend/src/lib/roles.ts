export type RoleValue =
  | string
  | {
      id?: string | number;
      code?: string;
      name?: string;
    }
  | null
  | undefined;

export function getRoleLabel(role: RoleValue): string {
  if (!role) {
    return 'No role';
  }

  if (typeof role === 'string') {
    return role;
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
