'use client';

/**
 * Soft + permanent delete confirmation modal.
 *
 * Phase 4 §4.1 — replaces every project / SBOM / schedule single-button
 * confirm modal with a two-mode dialog:
 *
 *  * "Move to deleted" (default radio) — soft-delete, recoverable.
 *  * "Delete permanently"               — hard-delete, requires typing
 *                                         the record's name to confirm.
 *
 * The cascade impact is shown explicitly under each option so the user
 * sees what they're about to nuke ("12 SBOMs, 87 runs, 4231 findings")
 * before confirming. The button label and variant flip based on the
 * selection.
 *
 * Accessibility: native ``<input type="radio">`` + ``<input type="text">``
 * with explicit labels; dialog focus trapping inherited from the
 * underlying ``Dialog`` component.
 */

import { useEffect, useId, useMemo, useState } from 'react';
import { Dialog, DialogBody, DialogFooter } from './Dialog';
import { Button } from './Button';

export interface CascadeImpactItem {
  /** Singular noun ("SBOM"). The component pluralises automatically. */
  label: string;
  count: number;
}

export interface DeleteConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called with ``permanent: false`` for soft, ``true`` for hard. */
  onConfirm: (args: { permanent: boolean }) => void;
  loading?: boolean;
  /** "Production Backend" — the human-readable label for the record. */
  recordName: string;
  /** "project" | "SBOM" | "schedule" — used in copy. */
  recordKind: string;
  /**
   * Counts of dependent rows. Empty array (or omitted) = "no children" —
   * the cascade-impact paragraph is suppressed for schedules etc.
   */
  cascadeImpact?: CascadeImpactItem[];
  /**
   * If false, hides the "Delete permanently" radio entirely. Used on
   * surfaces (none today) where permanent delete is disallowed.
   */
  allowPermanent?: boolean;
  /** Explanation shown when permanent deletion is unavailable. */
  permanentBlockedReason?: string;
  /** Override the title; defaults to ``Delete <recordKind>?``. */
  title?: string;
}

function pluralise(label: string, count: number): string {
  if (count === 1) return label;
  return `${label}s`;
}

function formatImpact(items: CascadeImpactItem[]): string {
  if (items.length === 0) return '';
  const parts = items
    .filter((i) => i.count > 0)
    .map((i) => `${i.count.toLocaleString()} ${pluralise(i.label, i.count)}`);
  if (parts.length === 0) return 'no dependent records';
  if (parts.length === 1) return parts[0];
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}`;
}

export function DeleteConfirmDialog({
  open,
  onClose,
  onConfirm,
  loading = false,
  recordName,
  recordKind,
  cascadeImpact = [],
  allowPermanent = true,
  permanentBlockedReason,
  title,
}: DeleteConfirmDialogProps) {
  const [mode, setMode] = useState<'soft' | 'permanent'>('soft');
  const [typed, setTyped] = useState('');

  // Reset state every time the dialog opens. Prevents a stale "permanent"
  // radio + name confirmation from carrying across openings, which would
  // be a footgun in a list view where the same dialog instance is reused
  // for different rows.
  useEffect(() => {
    if (open) {
      setMode('soft');
      setTyped('');
    }
  }, [open]);

  const softRadioId = useId();
  const permRadioId = useId();
  const nameInputId = useId();
  const impactDescribedById = useId();

  const impactSummary = useMemo(() => formatImpact(cascadeImpact), [cascadeImpact]);
  const hasImpact = cascadeImpact.length > 0;
  const totalImpactCount = useMemo(
    () => cascadeImpact.reduce((acc, i) => acc + i.count, 0),
    [cascadeImpact],
  );

  const permanentArmed = mode === 'permanent';
  const nameMatches = typed.trim() === recordName.trim();
  const confirmDisabled =
    loading || (permanentArmed && (!nameMatches || recordName.trim() === ''));

  const dialogTitle = title ?? `Delete ${recordKind}?`;
  const confirmLabel = permanentArmed ? 'Delete permanently' : 'Delete';
  const confirmVariant = permanentArmed ? 'danger' : 'primary';

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={dialogTitle}
      maxWidth="lg"
      dismissOnBackdrop={!loading}
      describedBy={hasImpact ? impactDescribedById : undefined}
      footer={
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant={confirmVariant}
            onClick={() => onConfirm({ permanent: permanentArmed })}
            loading={loading}
            disabled={confirmDisabled}
          >
            {confirmLabel}
          </Button>
        </DialogFooter>
      }
    >
      <DialogBody>
        <p className="text-sm text-hcl-muted">
          Choose what happens to{' '}
          <span className="font-mono text-hcl-navy">{recordName || `this ${recordKind}`}</span>:
        </p>

        <fieldset
          className="mt-4 space-y-2"
          aria-label={`Delete ${recordKind} options`}
        >
          <legend className="sr-only">Delete options</legend>

          {/* SOFT — default. Outer is a <div> (not <label>) because we
              also nest a typed-name <input> inside the permanent option;
              nested form controls inside <label> is invalid HTML and
              also breaks ``getByLabelText`` matching. The whole card
              stays clickable via the onClick handler. */}
          <div
            className={
              'rounded-md border p-3 text-sm transition ' +
              (mode === 'soft'
                ? 'border-hcl-blue bg-hcl-blue/5'
                : 'border-border-subtle bg-surface hover:border-border')
            }
            onClick={() => !loading && setMode('soft')}
          >
            <div className="flex items-start gap-3">
              <input
                id={softRadioId}
                type="radio"
                name="delete-mode"
                value="soft"
                checked={mode === 'soft'}
                onChange={() => setMode('soft')}
                disabled={loading}
                className="mt-0.5 h-4 w-4 cursor-pointer accent-hcl-blue"
              />
              <div className="min-w-0 flex-1">
                <label htmlFor={softRadioId} className="cursor-pointer font-medium text-hcl-navy">
                  Move to deleted
                </label>
                <p className="mt-1 text-xs leading-relaxed text-hcl-muted">
                  {hasImpact && totalImpactCount > 0 ? (
                    <>
                      The {recordKind}
                      {' and its '}
                      {impactSummary}
                      {' will be hidden. You can restore them later if needed.'}
                    </>
                  ) : (
                    <>
                      The {recordKind} will be hidden. You can restore it later
                      if needed.
                    </>
                  )}
                </p>
              </div>
            </div>
          </div>

          {/* PERMANENT */}
          {allowPermanent ? (
            <div
              className={
                'rounded-md border p-3 text-sm transition ' +
                (mode === 'permanent'
                  ? 'border-red-500 bg-red-50'
                  : 'border-border-subtle bg-surface hover:border-border')
              }
              onClick={(e) => {
                // Don't auto-toggle the radio when the user clicks the
                // typed-confirm input.
                if (loading) return;
                const target = e.target as HTMLElement;
                if (target.tagName === 'INPUT' && target.id === nameInputId) return;
                setMode('permanent');
              }}
            >
              <div className="flex items-start gap-3">
                <input
                  id={permRadioId}
                  type="radio"
                  name="delete-mode"
                  value="permanent"
                  checked={mode === 'permanent'}
                  onChange={() => setMode('permanent')}
                  disabled={loading}
                  className="mt-0.5 h-4 w-4 cursor-pointer accent-red-600"
                />
                <div className="min-w-0 flex-1">
                  <label htmlFor={permRadioId} className="cursor-pointer font-medium text-red-800">
                    Delete permanently
                  </label>
                  <p className="mt-1 text-xs leading-relaxed text-hcl-muted">
                    {hasImpact && totalImpactCount > 0 ? (
                      <>
                        The {recordKind}
                        {' and its '}
                        {impactSummary}
                        {' will be permanently removed. This cannot be undone.'}
                      </>
                    ) : (
                      <>
                        The {recordKind} will be permanently removed. This cannot
                        be undone.
                      </>
                    )}
                  </p>

                  {permanentArmed ? (
                    <div className="mt-3">
                      <label
                        htmlFor={nameInputId}
                        className="block text-xs font-medium text-red-800"
                      >
                        Type{' '}
                        <span className="font-mono">{recordName}</span>{' '}
                        to confirm
                      </label>
                      <input
                        id={nameInputId}
                        type="text"
                        value={typed}
                        onChange={(e) => setTyped(e.target.value)}
                        autoComplete="off"
                        autoFocus
                        disabled={loading}
                        className={
                          'mt-1 w-full rounded-md border px-2 py-1 font-mono text-sm ' +
                          (typed === '' || nameMatches
                            ? 'border-border-subtle bg-surface'
                            : 'border-red-400 bg-red-50')
                        }
                      />
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          ) : null}
        </fieldset>

        {!allowPermanent && permanentBlockedReason ? (
          <p className="mt-3 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">
            {permanentBlockedReason}
          </p>
        ) : null}

        {/* sr-only summary for the dialog's aria-describedby */}
        {hasImpact ? (
          <p id={impactDescribedById} className="sr-only">
            Cascade impact: {impactSummary}.
          </p>
        ) : null}
      </DialogBody>
    </Dialog>
  );
}
