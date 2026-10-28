'use client';

import { useEffect, useState } from 'react';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import type { CompareTab } from '@/types/compare';

interface Props {
  setTab: (tab: CompareTab) => void;
  onOpenExport: () => void;
}

const SHORTCUTS: Array<{ keys: string; label: string }> = [
  { keys: '1', label: 'Findings tab' },
  { keys: '2', label: 'Components tab' },
  { keys: '3', label: 'Posture detail tab' },
  { keys: 's, /', label: 'Focus filter input' },
  { keys: 'e', label: 'Open export dialog' },
  { keys: '?', label: 'Toggle this overlay' },
  { keys: 'Esc', label: 'Close overlays' },
];

/**
 * Listens for compare-page keyboard shortcuts. Only responds when no input,
 * textarea, or contenteditable is focused — typing into the search box must
 * never trigger tab swap.
 */
export function KeyboardShortcutsOverlay({ setTab, onOpenExport }: Props) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const editable =
        tag === 'input' ||
        tag === 'textarea' ||
        target?.isContentEditable === true;
      if (editable && e.key !== 'Escape') return;

      if (e.key === '?') {
        e.preventDefault();
        setOpen((v) => !v);
        return;
      }
      if (e.key === '1') {
        setTab('findings');
      } else if (e.key === '2') {
        setTab('components');
      } else if (e.key === '3') {
        setTab('delta');
      } else if (e.key === 'e' && !e.metaKey && !e.ctrlKey) {
        onOpenExport();
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [setTab, onOpenExport]);

  return (
    <Dialog
      open={open}
      onClose={() => setOpen(false)}
      title="Keyboard shortcuts"
      maxWidth="sm"
    >
      <DialogBody>
        <table className="w-full text-sm">
          <tbody>
            {SHORTCUTS.map((s) => (
              <tr key={s.keys} className="border-b border-border-subtle last:border-b-0">
                <td className="py-2 pr-4">
                  <kbd className="rounded border border-border bg-surface-muted px-1.5 py-0.5 font-mono text-xs text-hcl-navy">
                    {s.keys}
                  </kbd>
                </td>
                <td className="py-2 text-hcl-muted">{s.label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DialogBody>
    </Dialog>
  );
}
