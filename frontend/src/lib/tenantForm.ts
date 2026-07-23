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
  const externalId = values.external_iam_tenant_id.trim();
  if (!name || name.length > 255) errors.name = 'Enter a valid tenant name.';
  if (slug.length < 3 || slug.length > 128 || !SLUG_PATTERN.test(slug)) {
    errors.slug = 'Slug may contain lowercase letters, numbers, and single hyphens only.';
  }
  if (!externalId || externalId.length > 255) errors.external_iam_tenant_id = 'External IAM tenant ID is required.';
  return errors;
}
