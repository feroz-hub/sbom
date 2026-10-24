'use client';

import { useEffect, useState } from 'react';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';

interface BaseDialogProps {
  open: boolean;
  onClose: () => void;
  displayName: string;
  tenantName: string;
  isSelf?: boolean;
  loading?: boolean;
  onConfirm: () => Promise<void>;
}

export function DisableMembershipDialog({
  open,
  onClose,
  displayName,
  tenantName,
  isSelf = false,
  loading = false,
  onConfirm,
}: BaseDialogProps) {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) setError(null);
  }, [open]);

  const handleConfirm = async () => {
    setError(null);
    try {
      await onConfirm();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to disable membership.');
      }
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Disable tenant membership?"
      dismissOnBackdrop={!loading}
      maxWidth="md"
    >
      <DialogBody className="space-y-3">
        {error && (
          <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300">
            {error}
          </div>
        )}

        <p className="text-sm text-hcl-muted">
          <strong className="text-foreground">{displayName || 'This user'}</strong> will no longer be able to access{' '}
          <strong className="text-foreground">{tenantName}</strong>. Their HCL.CS identity and SBOM user account will remain unchanged. Their tenant membership record and assigned roles will be retained.
        </p>

        {isSelf && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-medium text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300">
            Warning: You are disabling your own membership in this tenant. You will lose access immediately.
          </div>
        )}
      </DialogBody>

      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant="danger" onClick={handleConfirm} loading={loading} disabled={loading}>
          Disable membership
        </Button>
      </DialogFooter>
    </Dialog>
  );
}

export function EnableMembershipDialog({
  open,
  onClose,
  displayName,
  tenantName,
  loading = false,
  onConfirm,
}: BaseDialogProps) {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) setError(null);
  }, [open]);

  const handleConfirm = async () => {
    setError(null);
    try {
      await onConfirm();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to enable membership.');
      }
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Enable tenant membership?"
      dismissOnBackdrop={!loading}
      maxWidth="md"
    >
      <DialogBody className="space-y-3">
        {error && (
          <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300">
            {error}
          </div>
        )}

        <p className="text-sm text-hcl-muted">
          <strong className="text-foreground">{displayName || 'This user'}</strong> will regain access to{' '}
          <strong className="text-foreground">{tenantName}</strong> using their currently active tenant role assignments.
        </p>
      </DialogBody>

      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleConfirm} loading={loading} disabled={loading}>
          Enable membership
        </Button>
      </DialogFooter>
    </Dialog>
  );
}

export function RemoveMemberDialog({
  open,
  onClose,
  displayName,
  tenantName,
  isSelf = false,
  loading = false,
  onConfirm,
}: BaseDialogProps) {
  const [confirmedCheckbox, setConfirmedCheckbox] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setConfirmedCheckbox(false);
      setError(null);
    }
  }, [open]);

  const handleConfirm = async () => {
    if (!confirmedCheckbox || loading) return;
    setError(null);
    try {
      await onConfirm();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to remove member.');
      }
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Remove user from tenant?"
      dismissOnBackdrop={!loading}
      maxWidth="md"
    >
      <DialogBody className="space-y-4">
        {error && (
          <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300">
            {error}
          </div>
        )}

        <p className="text-sm text-hcl-muted">
          This removes <strong className="text-foreground">{displayName || 'this user'}</strong> from{' '}
          <strong className="text-foreground">{tenantName}</strong> and removes or deactivates their tenant role assignments according to the existing backend contract.
        </p>

        <div className="rounded-xl border border-border bg-surface-elevated p-3 text-xs text-hcl-muted space-y-1">
          <span className="font-semibold text-foreground">This does not delete:</span>
          <ul className="list-disc list-inside space-y-0.5 ml-1">
            <li>their HCL.CS identity</li>
            <li>their SBOM user account</li>
            <li>memberships in other tenants</li>
            <li>their platform-level role, when present</li>
          </ul>
        </div>

        {isSelf && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-medium text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300">
            Warning: You are removing yourself from this tenant. You will lose access immediately upon confirmation.
          </div>
        )}

        <label className="flex items-center gap-2.5 pt-1 cursor-pointer">
          <input
            type="checkbox"
            checked={confirmedCheckbox}
            onChange={(e) => setConfirmedCheckbox(e.target.checked)}
            disabled={loading}
            className="h-4 w-4 rounded border-border text-red-600 focus:ring-red-500"
          />
          <span className="text-xs font-medium text-foreground">
            I understand this user will lose access to this tenant
          </span>
        </label>
      </DialogBody>

      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="danger"
          onClick={handleConfirm}
          loading={loading}
          disabled={!confirmedCheckbox || loading}
        >
          Remove from tenant
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
