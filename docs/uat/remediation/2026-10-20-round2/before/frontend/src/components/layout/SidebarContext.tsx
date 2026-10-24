'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

/**
 * The sidebar has two orthogonal states:
 *
 *   • `collapsed` — desktop behaviour. Shrinks the rail from 240px → 64px so
 *     the user can reclaim horizontal space. Persists across pages.
 *   • `mobileOpen` — mobile behaviour. Slides the full rail in as an overlay
 *     drawer; auto-closes on navigation. Irrelevant on desktop.
 *
 * Keeping them separate (rather than one `open` flag) avoids the classic
 * "resize browser → sidebar in the wrong state" bug that plagues single-flag
 * drawer implementations.
 */
interface SidebarContextValue {
  collapsed: boolean;
  toggleCollapsed: () => void;
  mobileOpen: boolean;
  openMobile: () => void;
  closeMobile: () => void;
}

const SidebarContext = createContext<SidebarContextValue>({
  collapsed: false,
  toggleCollapsed: () => {},
  mobileOpen: false,
  openMobile: () => {},
  closeMobile: () => {},
});

export function SidebarProvider({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const toggleCollapsed = useCallback(() => setCollapsed((c) => !c), []);
  const openMobile = useCallback(() => setMobileOpen(true), []);
  const closeMobile = useCallback(() => setMobileOpen(false), []);

  // Lock body scroll while the mobile drawer is open so the content behind
  // doesn't accidentally scroll when the user drags across the backdrop.
  useEffect(() => {
    if (!mobileOpen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [mobileOpen]);

  // Close the drawer if the viewport grows past the mobile breakpoint, so the
  // user isn't stuck with an overlay that no longer makes sense on desktop.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 768px)');
    const onChange = (e: MediaQueryListEvent) => {
      if (e.matches) setMobileOpen(false);
    };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  // Escape closes the drawer on mobile.
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  const value = useMemo(
    () => ({ collapsed, toggleCollapsed, mobileOpen, openMobile, closeMobile }),
    [collapsed, toggleCollapsed, mobileOpen, openMobile, closeMobile],
  );

  return <SidebarContext.Provider value={value}>{children}</SidebarContext.Provider>;
}

export function useSidebar() {
  return useContext(SidebarContext);
}
