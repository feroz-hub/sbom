'use client';

import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Info } from 'lucide-react';
import { Button } from './Button';

/** Portalled metric help, with hover/focus disclosure and tap-to-pin behavior. */
export function InfoTooltip({ label, description }: { label: string; description: string }) {
  const id = useId();
  const anchor = useRef<HTMLButtonElement>(null);
  const tooltip = useRef<HTMLDivElement>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pinned = useRef(false);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 8, top: 8 });

  const cancelHide = () => {
    if (hideTimer.current) clearTimeout(hideTimer.current);
  };
  const show = () => { cancelHide(); setOpen(true); };
  const dismiss = () => { cancelHide(); pinned.current = false; setOpen(false); };
  const hide = () => {
    cancelHide();
    hideTimer.current = setTimeout(() => {
      if (!pinned.current && document.activeElement !== anchor.current) setOpen(false);
    }, 120);
  };

  useLayoutEffect(() => {
    if (!open || !anchor.current || !tooltip.current) return;
    const rect = anchor.current.getBoundingClientRect();
    const help = tooltip.current.getBoundingClientRect();
    const top = rect.bottom + 8 + help.height <= window.innerHeight - 8
      ? rect.bottom + 8 : rect.top - help.height - 8;
    setPosition({
      left: Math.max(8, Math.min(rect.left, window.innerWidth - help.width - 8)),
      top: Math.max(8, top),
    });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = () => { pinned.current = false; setOpen(false); };
    const outside = (event: PointerEvent) => {
      if (!anchor.current?.contains(event.target as Node) && !tooltip.current?.contains(event.target as Node)) close();
    };
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') close(); };
    const scroll = (event: Event) => { if (!tooltip.current?.contains(event.target as Node)) close(); };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', escape);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', scroll, true);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', escape);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', scroll, true);
    };
  }, [open]);

  useEffect(() => () => { if (hideTimer.current) clearTimeout(hideTimer.current); }, []);

  return <>
    <Button
      ref={anchor}
      variant="ghost"
      size="icon"
      aria-label={`About ${label}`}
      aria-describedby={open ? id : undefined}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={dismiss}
      onClick={() => {
        if (pinned.current) dismiss();
        else { pinned.current = true; show(); }
      }}
      className="h-8 w-8 shrink-0 rounded-full !text-foreground/60 hover:!text-foreground"
    >
      <Info className="h-4 w-4" aria-hidden="true" />
    </Button>
    {open && createPortal(
      <div
        ref={tooltip}
        id={id}
        role="tooltip"
        onMouseEnter={cancelHide}
        onMouseLeave={hide}
        style={position}
        className="fixed z-[100] w-72 max-w-[calc(100vw-16px)] max-h-[calc(100vh-16px)] overflow-y-auto rounded-lg border border-border bg-surface p-3 text-left text-xs font-normal leading-relaxed text-foreground shadow-lg"
      >
        {description}
      </div>, document.body,
    )}
  </>;
}
