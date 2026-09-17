import { NextRequest } from 'next/server';
import { afterEach, expect, it } from 'vitest';
import { config, proxy } from './proxy';

afterEach(() => {
  delete process.env.NEXT_PUBLIC_AUTH_ENABLED;
});

it('excludes logged-out and callback from session enforcement while protecting the root', () => {
  const matcher = new RegExp(`^${config.matcher[0]}$`);
  expect(matcher.test('/logged-out')).toBe(false);
  expect(matcher.test('/auth/callback')).toBe(false);
  expect(matcher.test('/')).toBe(true);

  process.env.NEXT_PUBLIC_AUTH_ENABLED = 'true';
  const response = proxy(new NextRequest('https://sbom.example/'));
  expect(response.headers.get('location')).toBe('https://sbom.example/api/auth/login?returnTo=%2F');
});
