/** Cookie mutations require the browser's exact configured application origin. */
export function trustedMutationOrigin(request: Request): boolean {
  const expected = new URL(process.env.APP_ORIGIN || process.env.NEXT_PUBLIC_HCL_IAM_REDIRECT_URI || 'https://localhost:3000').origin;
  const origin = request.headers.get('origin');
  const site = request.headers.get('sec-fetch-site');
  return origin === expected && site !== 'cross-site';
}
