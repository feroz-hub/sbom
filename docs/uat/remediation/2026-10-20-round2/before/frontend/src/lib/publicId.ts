/** Public resource IDs are canonical UUIDv4 strings. Numeric compatibility in
 * fixture types never authorizes a numeric ID at the HTTP boundary. */
export type ResourceId = string | number;
export const PUBLIC_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function publicId(value: unknown): string | null {
  return typeof value === 'string' && PUBLIC_ID.test(value) ? value.toLowerCase() : null;
}
