'use client';

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Pencil, Plus, Trash2, Upload } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/hooks/useToast';
import {
  createLifecycleVendorRecord,
  deleteLifecycleVendorRecord,
  exportLifecycleVendorRecords,
  importLifecycleVendorRecords,
  listLifecycleVendorRecords,
  updateLifecycleVendorRecord,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type { LifecycleVendorRecord, LifecycleVendorRecordPayload } from '@/types';

const EMPTY_RECORD: LifecycleVendorRecordPayload = {
  vendor_name: '',
  product_name: '',
  product_aliases: [],
  ecosystem: 'generic',
  version_pattern: '',
  lifecycle_status: 'EOL',
  confidence: 'High',
  enabled: true,
};

export function LifecycleVendorRecordsPage() {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<LifecycleVendorRecord | null>(null);
  const [creating, setCreating] = useState(false);
  const [importText, setImportText] = useState('');

  const recordsQuery = useQuery({
    queryKey: ['lifecycle-vendor-records', search],
    queryFn: ({ signal }) => listLifecycleVendorRecords({ search: search || undefined, limit: 100 }, signal),
    staleTime: 30_000,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['lifecycle-vendor-records'] });

  const createMutation = useMutation({
    mutationFn: (payload: LifecycleVendorRecordPayload) => createLifecycleVendorRecord(payload),
    onSuccess: () => {
      invalidate();
      setCreating(false);
      showToast('Vendor record created', 'success');
    },
    onError: (error: Error) => showToast(error.message, 'error'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: LifecycleVendorRecordPayload }) =>
      updateLifecycleVendorRecord(id, payload),
    onSuccess: () => {
      invalidate();
      setEditing(null);
      showToast('Vendor record saved', 'success');
    },
    onError: (error: Error) => showToast(error.message, 'error'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteLifecycleVendorRecord(id),
    onSuccess: () => {
      invalidate();
      showToast('Vendor record disabled', 'success');
    },
    onError: (error: Error) => showToast(error.message, 'error'),
  });

  const importMutation = useMutation({
    mutationFn: (records: LifecycleVendorRecordPayload[]) => importLifecycleVendorRecords(records),
    onSuccess: (result) => {
      invalidate();
      setImportText('');
      showToast(`Imported ${result.created} records`, result.errors.length ? 'info' : 'success');
    },
    onError: (error: Error) => showToast(error.message, 'error'),
  });

  // @no-invalidation-needed export downloads current records without mutating server state.
  const exportMutation = useMutation({
    mutationFn: () => exportLifecycleVendorRecords(),
    onSuccess: (result) => {
      const blob = new Blob([JSON.stringify(result.records, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'lifecycle-vendor-records.json';
      anchor.click();
      URL.revokeObjectURL(url);
    },
    onError: (error: Error) => showToast(error.message, 'error'),
  });

  const records = recordsQuery.data?.items ?? [];

  const parsedImport = useMemo(() => {
    if (!importText.trim()) return null;
    try {
      const parsed = JSON.parse(importText);
      return Array.isArray(parsed) ? parsed : parsed.records;
    } catch {
      return null;
    }
  }, [importText]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-10 w-full max-w-sm rounded-md border border-border bg-background px-3 text-sm"
          placeholder="Search records"
        />
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => exportMutation.mutate()}>
            <Download className="h-4 w-4" />
            Export
          </Button>
          <Button onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" />
            Add
          </Button>
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border bg-surface-muted text-xs uppercase tracking-wide text-hcl-muted">
            <tr>
              <th className="px-4 py-3">Vendor</th>
              <th className="px-4 py-3">Product</th>
              <th className="px-4 py-3">Ecosystem</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">EOL</th>
              <th className="px-4 py-3">Evidence</th>
              <th className="px-4 py-3">Updated</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {recordsQuery.isLoading ? (
              <tr><td className="px-4 py-5 text-hcl-muted" colSpan={8}>Loading records</td></tr>
            ) : records.length === 0 ? (
              <tr><td className="px-4 py-5 text-hcl-muted" colSpan={8}>No vendor lifecycle records</td></tr>
            ) : (
              records.map((record) => (
                <tr key={record.id}>
                  <td className="px-4 py-3 font-medium text-hcl-navy">{record.vendor_name}</td>
                  <td className="px-4 py-3">{record.product_name}</td>
                  <td className="px-4 py-3 text-hcl-muted">{record.ecosystem}</td>
                  <td className="px-4 py-3"><Badge variant={record.enabled ? 'warning' : 'gray'}>{record.lifecycle_status}</Badge></td>
                  <td className="px-4 py-3 text-hcl-muted">{record.eol_date ?? '—'}</td>
                  <td className="px-4 py-3">
                    {record.evidence_url ? <a className="text-hcl-blue underline" href={record.evidence_url}>Open</a> : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-hcl-muted">{formatDate(record.updated_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => setEditing(record)}>
                        <Pencil className="h-3.5 w-3.5" />
                        Edit
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => deleteMutation.mutate(record.id)}>
                        <Trash2 className="h-3.5 w-3.5" />
                        Disable
                      </Button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-hcl-navy">Import</h2>
          <Button
            variant="secondary"
            size="sm"
            disabled={!Array.isArray(parsedImport)}
            onClick={() => Array.isArray(parsedImport) && importMutation.mutate(parsedImport)}
          >
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
        </div>
        <textarea
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          className="mt-3 min-h-28 w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
        />
      </div>

      {creating && (
        <VendorRecordDialog
          title="Add Vendor Record"
          initial={EMPTY_RECORD}
          saving={createMutation.isPending}
          onClose={() => setCreating(false)}
          onSave={(payload) => createMutation.mutate(payload)}
        />
      )}
      {editing && (
        <VendorRecordDialog
          title="Edit Vendor Record"
          initial={editing}
          saving={updateMutation.isPending}
          onClose={() => setEditing(null)}
          onSave={(payload) => updateMutation.mutate({ id: editing.id, payload })}
        />
      )}
    </div>
  );
}

function VendorRecordDialog({
  title,
  initial,
  saving,
  onClose,
  onSave,
}: {
  title: string;
  initial: LifecycleVendorRecordPayload | LifecycleVendorRecord;
  saving: boolean;
  onClose: () => void;
  onSave: (payload: LifecycleVendorRecordPayload) => void;
}) {
  const [form, setForm] = useState<LifecycleVendorRecordPayload>({
    vendor_name: initial.vendor_name ?? '',
    product_name: initial.product_name ?? '',
    product_aliases: initial.product_aliases ?? [],
    ecosystem: initial.ecosystem ?? 'generic',
    version_pattern: initial.version_pattern ?? '',
    lifecycle_status: initial.lifecycle_status ?? 'EOL',
    maintenance_status: initial.maintenance_status ?? '',
    eol_date: initial.eol_date ?? '',
    eos_date: initial.eos_date ?? '',
    eof_date: initial.eof_date ?? '',
    latest_supported_version: initial.latest_supported_version ?? '',
    recommended_version: initial.recommended_version ?? '',
    evidence_url: initial.evidence_url ?? '',
    confidence: initial.confidence ?? 'High',
    enabled: initial.enabled ?? true,
  });

  const set = (key: keyof LifecycleVendorRecordPayload, value: unknown) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  return (
    <div className="fixed inset-0 z-50 bg-black/40">
      <div className="ml-auto flex h-dvh w-full max-w-xl flex-col border-l border-border bg-background shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-base font-semibold text-hcl-navy">{title}</h2>
          <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
        </div>
        <div className="grid flex-1 grid-cols-2 gap-4 overflow-y-auto px-5 py-5">
          <Field label="Vendor" value={form.vendor_name ?? ''} onChange={(v) => set('vendor_name', v)} />
          <Field label="Product" value={form.product_name ?? ''} onChange={(v) => set('product_name', v)} />
          <Field label="Aliases" value={(form.product_aliases ?? []).join(', ')} onChange={(v) => set('product_aliases', v.split(',').map((x) => x.trim()).filter(Boolean))} />
          <Field label="Ecosystem" value={form.ecosystem ?? ''} onChange={(v) => set('ecosystem', v)} />
          <Field label="Version pattern" value={form.version_pattern ?? ''} onChange={(v) => set('version_pattern', v)} />
          <Field label="Status" value={form.lifecycle_status ?? ''} onChange={(v) => set('lifecycle_status', v)} />
          <Field label="EOL date" value={form.eol_date ?? ''} onChange={(v) => set('eol_date', v)} />
          <Field label="EOS date" value={form.eos_date ?? ''} onChange={(v) => set('eos_date', v)} />
          <Field label="EOF date" value={form.eof_date ?? ''} onChange={(v) => set('eof_date', v)} />
          <Field label="Confidence" value={form.confidence ?? ''} onChange={(v) => set('confidence', v)} />
          <Field label="Latest supported" value={form.latest_supported_version ?? ''} onChange={(v) => set('latest_supported_version', v)} />
          <Field label="Recommended" value={form.recommended_version ?? ''} onChange={(v) => set('recommended_version', v)} />
          <label className="col-span-2 block text-sm font-medium text-hcl-navy">
            Evidence URL
            <input value={form.evidence_url ?? ''} onChange={(e) => set('evidence_url', e.target.value)} className="mt-1 h-9 w-full rounded-md border border-border bg-background px-2 text-sm" />
          </label>
          <label className="flex items-center gap-2 text-sm font-medium text-hcl-navy">
            <input type="checkbox" checked={Boolean(form.enabled)} onChange={(e) => set('enabled', e.target.checked)} />
            Enabled
          </label>
          <label className="flex items-center gap-2 text-sm font-medium text-hcl-navy">
            <input type="checkbox" checked={Boolean(form.unsupported)} onChange={(e) => set('unsupported', e.target.checked)} />
            Unsupported
          </label>
        </div>
        <div className="flex justify-end gap-2 border-t border-border px-5 py-4">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button loading={saving} onClick={() => onSave(form)}>Save</Button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="block text-sm font-medium text-hcl-navy">
      {label}
      <input value={value} onChange={(e) => onChange(e.target.value)} className="mt-1 h-9 w-full rounded-md border border-border bg-background px-2 text-sm" />
    </label>
  );
}
