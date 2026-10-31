/** Server resource metadata only. It never grants resource ownership. */
export function sessionNamespace(environment: Record<string, string | undefined>): string {
  const name = 'SBOM_DEV_RESOURCE_ID';
  if (Object.keys(environment).some(key => key.toUpperCase() === name && key !== name)) {
    throw new Error('DEV_INSTANCE_RESOURCE_ID_INVALID');
  }
  if (!Object.prototype.hasOwnProperty.call(environment, name)) return 'sbom:bff:';
  const value = environment[name];
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new Error('DEV_INSTANCE_RESOURCE_ID_INVALID');
  }
  return `sbom:bff:${value.replaceAll('-', '')}:`;
}
