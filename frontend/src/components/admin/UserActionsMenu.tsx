'use client';
import { useEffect, useRef, useState } from 'react';
import { MoreHorizontal } from 'lucide-react';

export function UserActionsMenu({ name, onView }: { name: string; onView: () => void }) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const action = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    action.current?.focus();
    const close = (event: PointerEvent) => { if (!container.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener('pointerdown', close);
    return () => document.removeEventListener('pointerdown', close);
  }, [open]);
  return <div ref={container} className="relative" onKeyDown={event => { if (event.key === 'Escape') { setOpen(false); trigger.current?.focus(); } }} onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false); }}>
    <button ref={trigger} type="button" aria-label={`Actions for ${name}`} aria-expanded={open} onClick={() => setOpen(value => !value)}><MoreHorizontal size={20} aria-hidden="true" /></button>
    {open && <div className="absolute right-0 z-20 w-44 rounded-lg border border-border bg-surface p-1 shadow-lg"><button ref={action} className="w-full text-left" onClick={() => { setOpen(false); onView(); }}>View details</button></div>}
  </div>;
}
