'use client';

import styles from './ai-configuration.module.css';

import { useEffect, useState, type ReactNode } from 'react';
import { Dialog, DialogBody } from '@/components/ui/Dialog';

/** Reuse the application focus trap, scroll containment and focus restoration. */
export function ProviderDialogFrame({
  title,
  onClose,
  busy,
  children,
}: {
  title: string;
  onClose: () => void;
  busy: boolean;
  children: (close: () => void) => ReactNode;
}) {
  useEffect(() => {
    const trigger = document.activeElement;
    return () => {
      if (trigger instanceof HTMLElement && trigger.isConnected)
        trigger.focus();
    };
  }, []);
  const [dirty, setDirty] = useState(false);
  const [discard, setDiscard] = useState(false);
  const close = () => {
    if (!busy) {
      if (dirty) setDiscard(true);
      else onClose();
    }
  };
  return (
    <Dialog
      open
      title={title}
      onClose={close}
      maxWidth="xl"
      dismissOnBackdrop={!busy}
    >
      <DialogBody className={styles.page}>
        {discard && (
          <div
            role="alert"
            className="mb-4 rounded-lg border border-border bg-surface-muted p-4 text-hcl-navy"
          >
            <p>Discard unsaved provider changes?</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                autoFocus
                onClick={() => setDiscard(false)}
                className="min-h-10 rounded-lg border border-border px-3"
              >
                Keep editing
              </button>
              <button
                type="button"
                onClick={onClose}
                className="min-h-10 rounded-lg bg-primary px-3 text-white"
              >
                Discard changes
              </button>
            </div>
          </div>
        )}
        <div onChangeCapture={() => setDirty(true)}>{children(close)}</div>
      </DialogBody>
    </Dialog>
  );
}
