import { expect, it } from 'vitest';
import { GET } from './route';

it('serves the installed bridge as same-origin JavaScript without caching', async () => {
  const response = GET();
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('content-type')).toContain('text/javascript');
  expect(await response.text()).toContain('msalRedirectBridge.broadcastResponseToMainFrame()');
});
