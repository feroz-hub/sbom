import type { CreateTenantRequest } from '@/lib/api';

const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function slugFromName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 128)
    .replace(/-+$/g, '');
}

export function validateTenantForm(
  values: CreateTenantRequest,
): Partial<Record<keyof CreateTenantRequest, string>> {
  const errors: Partial<Record<keyof CreateTenantRequest, string>> = {};
  const name = values.name.trim();
  const slug = values.slug.trim();
  if (!name || name.length > 255) errors.name = 'Enter a valid tenant name.';
  if (slug.length < 3 || slug.length > 128 || !SLUG_PATTERN.test(slug)) {
    errors.slug = 'Slug may contain lowercase letters, numbers, and single hyphens only.';
  }
  if (values.initial_admin_invitation) {
    const profile = values.initial_admin_invitation;
    if (!profile.first_name.trim() || !profile.last_name.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(profile.email)) {
      errors.initial_admin_invitation = 'Enter the administrator’s first name, last name, and valid email.';
    }
  } else if (!Number.isInteger(values.initial_admin_user_id) || (values.initial_admin_user_id ?? 0) < 1) {
    errors.initial_admin_user_id = 'Select an initial Tenant Administrator.';
  }
  return errors;
}
