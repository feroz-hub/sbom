'use client';

import { useEffect, useMemo, useState } from 'react';
import { type TenantRole } from '@/lib/api';
import { getRoleCode, getRoleLabel } from '@/lib/roles';
import { ROLE_DESCRIPTIONS } from './StatusBadges';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';

interface ManageRolesModalProps {
  open: boolean;
  onClose: () => void;
  displayName: string;
  tenantName: string;
  currentRoles: (TenantRole | string)[];
  membershipVersion?: number;
  isMembershipActive?: boolean;
  assignableRoles?: string[];
  loading?: boolean;
  errorMessage?: string | null;
  onSave: (selectedRoles: TenantRole[]) => Promise<void>;
}

const ALL_TENANT_ROLES: { code: string; label: string }[] = [
  { code: 'TENANT_ADMIN', label: 'Tenant Admin' },
  { code: 'SECURITY_ANALYST', label: 'Security Analyst' },
  { code: 'DEVELOPER', label: 'Developer' },
  { code: 'VIEWER', label: 'Viewer' },
];

export function ManageRolesModal({
  open,
  onClose,
  displayName,
  tenantName,
  currentRoles,
  isMembershipActive = true,
  loading = false,
  errorMessage = null,
  onSave,
}: ManageRolesModalProps) {
  const initialSelectedCodes = useMemo(() => {
    const codes = (currentRoles || [])
      .map(getRoleCode)
      .filter((c): c is string => Boolean(c));
    return new Set<string>(codes);
  }, [currentRoles]);

  const [draftRoles, setDraftRoles] = useState<Set<string>>(initialSelectedCodes);
  const [error, setError] = useState<string | null>(errorMessage);

  useEffect(() => {
    if (open) {
      setDraftRoles(new Set(initialSelectedCodes));
      setError(errorMessage);
    }
  }, [open, initialSelectedCodes, errorMessage]);

  const addedRoles = useMemo(() => {
    const added: string[] = [];
    draftRoles.forEach((role) => {
      if (!initialSelectedCodes.has(role)) {
        added.push(role);
      }
    });
    return added;
  }, [draftRoles, initialSelectedCodes]);

  const removedRoles = useMemo(() => {
    const removed: string[] = [];
    initialSelectedCodes.forEach((role) => {
      if (!draftRoles.has(role)) {
        removed.push(role);
      }
    });
    return removed;
  }, [draftRoles, initialSelectedCodes]);

  const hasChanges = addedRoles.length > 0 || removedRoles.length > 0;
  const isInvalid = isMembershipActive && draftRoles.size === 0;

  const toggleRole = (code: string) => {
    setDraftRoles((prev) => {
      const next = new Set(prev);
      if (next.has(code)) {
        next.delete(code);
      } else {
        next.add(code);
      }
      return next;
    });
  };

  const handleSave = async () => {
    if (!hasChanges || isInvalid || loading) return;
    setError(null);
    try {
      await onSave(Array.from(draftRoles) as TenantRole[]);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to update roles.');
      }
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Manage roles — ${displayName || 'User'}`}
      dismissOnBackdrop={!loading}
      maxWidth="lg"
    >
      <DialogBody className="space-y-4">
        <p className="text-xs text-hcl-muted">
          Tenant: <span className="font-semibold text-foreground">{tenantName}</span>
        </p>

        {error && (
          <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300">
            {error}
          </div>
        )}

        <div className="space-y-3 pt-1">
          {ALL_TENANT_ROLES.map(({ code, label }) => {
            const isChecked = draftRoles.has(code);
            const description = ROLE_DESCRIPTIONS[code];

            return (
              <label
                key={code}
                className={`flex items-start gap-3 rounded-xl border p-3.5 transition-colors cursor-pointer ${
                  isChecked
                    ? 'border-hcl-blue/40 bg-hcl-blue/5 dark:border-hcl-blue/30 dark:bg-hcl-blue/10'
                    : 'border-border bg-surface hover:bg-surface-elevated'
                }`}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={() => toggleRole(code)}
                  disabled={loading}
                  className="mt-0.5 h-4 w-4 rounded border-border text-hcl-blue focus:ring-hcl-blue"
                />
                <div className="space-y-0.5">
                  <span className="text-sm font-semibold text-foreground">{label}</span>
                  {description && <p className="text-xs text-hcl-muted">{description}</p>}
                </div>
              </label>
            );
          })}
        </div>

        {isInvalid && (
          <p className="text-xs font-medium text-amber-700 dark:text-amber-400">
            Active tenant memberships require at least one assigned role.
          </p>
        )}

        {hasChanges && (
          <div className="rounded-xl border border-border bg-surface-elevated p-4 text-xs space-y-2">
            <span className="font-semibold text-foreground">Change Summary:</span>
            {addedRoles.length > 0 && (
              <div>
                <span className="text-emerald-700 dark:text-emerald-400 font-medium">Adding:</span>
                <ul className="list-disc list-inside ml-2 text-hcl-muted">
                  {addedRoles.map((r) => (
                    <li key={r}>{getRoleLabel(r)}</li>
                  ))}
                </ul>
              </div>
            )}
            {removedRoles.length > 0 && (
              <div>
                <span className="text-red-700 dark:text-red-400 font-medium">Removing:</span>
                <ul className="list-disc list-inside ml-2 text-hcl-muted">
                  {removedRoles.map((r) => (
                    <li key={r}>{getRoleLabel(r)}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </DialogBody>

      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="primary"
          onClick={handleSave}
          loading={loading}
          disabled={!hasChanges || isInvalid || loading}
        >
          Save changes
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
