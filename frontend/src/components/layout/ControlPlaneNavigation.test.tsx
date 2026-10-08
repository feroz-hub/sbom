// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { CommandPalette } from './CommandPalette';
import { KeyboardCheatsheet } from './KeyboardCheatsheet';
const state = vi.hoisted(() => ({ permissions: new Set<string>(), push: vi.fn(), sboms: vi.fn(), runs: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: state.push }) }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: 1, permissions: [] }, activeTenantId: null, hasPermission: (p: string) => state.permissions.has(p) }) }));
vi.mock('@/components/theme/ThemeProvider', () => ({ useTheme: () => ({ resolvedTheme: 'light', setTheme: vi.fn() }) }));
vi.mock('@/lib/api', () => ({ getRecentSboms: () => state.sboms(), getRuns: () => state.runs() }));
beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() });
  state.permissions = new Set(['platform:tenant:read', 'platform:administrator:read', 'platform:health:read']);
});
function show() { render(<QueryClientProvider client={new QueryClient()}><CommandPalette /><KeyboardCheatsheet /></QueryClientProvider>); }
it('offers only control-plane navigation and does not fetch tenant recents', () => {
  show(); fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  expect(screen.getByText('Platform Dashboard')).toBeInTheDocument();
  expect(screen.queryByText('Upload SBOM')).not.toBeInTheDocument();
  expect(screen.queryByText('Projects')).not.toBeInTheDocument();
  expect(screen.queryByText('Analysis runs')).not.toBeInTheDocument();
  expect(state.sboms).not.toHaveBeenCalled(); expect(state.runs).not.toHaveBeenCalled();
});
it('routes platform dashboard chords correctly and ignores tenant chords', () => {
  show(); fireEvent.keyDown(window, { key: 'g' }); fireEvent.keyDown(window, { key: 's' });
  expect(state.push).not.toHaveBeenCalled();
  fireEvent.keyDown(window, { key: 'g' }); fireEvent.keyDown(window, { key: 'd' });
  expect(state.push).toHaveBeenCalledWith('/platform');
});
