'use client';

import { useState } from 'react';
import { Download, FileJson, FileSpreadsheet, FileText } from 'lucide-react';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { useToast } from '@/hooks/useToast';
import { exportCompare } from '@/lib/api';
import type { CompareExportFormat } from '@/types/compare';

interface Props {
  open: boolean;
  onClose: () => void;
  cacheKey: string;
}

const OPTIONS: Array<{
  format: CompareExportFormat;
  label: string;
  hint: string;
  Icon: typeof FileText;
}> = [
  { format: 'markdown', label: 'Markdown', hint: 'Paste into Slack, Notion, or a release ticket.', Icon: FileText },
  { format: 'csv', label: 'CSV', hint: 'Open in a spreadsheet.', Icon: FileSpreadsheet },
  { format: 'json', label: 'JSON', hint: 'Full payload for automation.', Icon: FileJson },
];

export function ExportDialog({ open, onClose, cacheKey }: Props) {
  const { showToast } = useToast();
  const [busy, setBusy] = useState<CompareExportFormat | null>(null);

  const onPick = async (format: CompareExportFormat) => {
    setBusy(format);
    try {
      const { blob, filename } = await exportCompare(cacheKey, format);
      // Trigger browser download.
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast(`Downloaded ${filename}`, 'success');
      onClose();
    } catch (err) {
      showToast(
        err instanceof Error ? err.message : 'Export failed',
        'error',
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Export comparison"
      maxWidth="md"
      footer={
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={busy !== null}>
            Cancel
          </Button>
        </DialogFooter>
      }
    >
      <DialogBody>
        <p className="text-sm text-hcl-muted">
          Pick a format. The file streams from the server using the cached comparison.
        </p>
        <ul className="mt-4 space-y-2">
          {OPTIONS.map((opt) => {
            const { Icon } = opt;
            const isBusy = busy === opt.format;
            return (
              <li key={opt.format}>
                <button
                  type="button"
                  onClick={() => onPick(opt.format)}
                  disabled={busy !== null}
                  className="flex w-full items-center gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-left transition-colors hover:border-primary hover:bg-hcl-light/30 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Icon className="h-5 w-5 shrink-0 text-primary" aria-hidden />
                  <div className="flex-1">
                    <div className="text-sm font-semibold text-hcl-navy">
                      {opt.label}
                    </div>
                    <div className="text-xs text-hcl-muted">{opt.hint}</div>
                  </div>
                  {isBusy ? (
                    <span className="text-xs text-hcl-muted">Downloading…</span>
                  ) : (
                    <Download className="h-4 w-4 text-hcl-muted" aria-hidden />
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </DialogBody>
    </Dialog>
  );
}
