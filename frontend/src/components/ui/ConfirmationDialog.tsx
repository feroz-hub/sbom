'use client';

import { Dialog, DialogBody, DialogFooter } from './Dialog';
import { Button } from './Button';

interface ConfirmationDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  loading?: boolean;
  danger?: boolean;
}

export function ConfirmationDialog({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onClose,
  loading = false,
  danger = true,
}: ConfirmationDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} title={title} dismissOnBackdrop={!loading} maxWidth="md">
      <DialogBody><p className="text-sm text-hcl-muted">{description}</p></DialogBody>
      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>Cancel</Button>
        <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} loading={loading} disabled={loading}>
          {loading ? `${confirmLabel.replace(/…$/, '')}…` : confirmLabel}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
