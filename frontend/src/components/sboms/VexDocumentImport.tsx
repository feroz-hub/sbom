'use client';

import { useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Upload, X } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { previewVexDocument } from '@/lib/vexPreview';

/** Guard against someone dropping a 200MB file into a textarea. */
const MAX_BYTES = 8 * 1024 * 1024;

export interface VexDocumentImportProps {
  value: string;
  onChange: (next: string) => void;
  onImport: () => void;
  importing: boolean;
  /** Shared status line — also carries messages from Discover. */
  message?: string;
}

/**
 * VEX document intake: pick a file, drop a file, or paste JSON.
 *
 * A real CSAF advisory runs to thousands of lines, so paste-only intake made
 * the panel unusable for the documents it exists to accept. The file path
 * mirrors the SBOM upload modal's picker (SbomUploadModal.tsx:538) — the
 * endpoint takes a JSON body either way, so the file is read client-side and
 * the parsed text flows through the same textarea state.
 *
 * The preview line is the other half: it names the format the server will
 * detect and how many statements it expects to write, so a truncated paste or
 * the wrong file is caught before a request that mutates data.
 */
export function VexDocumentImport({
  value,
  onChange,
  onImport,
  importing,
  message,
}: VexDocumentImportProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const preview = previewVexDocument(value);
  const canImport = preview.ok && !importing;

  const readFile = async (file: File) => {
    setFileError(null);
    if (file.size > MAX_BYTES) {
      setFileError(`${file.name} is ${(file.size / 1024 / 1024).toFixed(1)} MB — the limit is 8 MB.`);
      return;
    }
    try {
      const text = await file.text();
      onChange(text);
      setFileName(file.name);
    } catch {
      setFileError(`Could not read ${file.name}.`);
    }
  };

  const clear = () => {
    onChange('');
    setFileName(null);
    setFileError(null);
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="rounded-lg border border-hcl-border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label
          htmlFor="vex-document-text"
          className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted"
        >
          Import VEX document
        </label>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            disabled={importing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-hcl-border bg-surface px-3 py-1.5 text-xs font-medium text-hcl-navy transition-colors hover:bg-hcl-light disabled:opacity-50"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden />
            Choose file
          </button>
          {value ? (
            <button
              type="button"
              onClick={clear}
              disabled={importing}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:text-hcl-navy disabled:opacity-50"
            >
              <X className="h-3.5 w-3.5" aria-hidden />
              Clear
            </button>
          ) : null}
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void readFile(file);
            }}
            className="hidden"
          />
        </div>
      </div>

      <div
        onDragOver={(event) => {
          event.preventDefault();
          if (!importing) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          if (importing) return;
          const file = event.dataTransfer.files?.[0];
          if (file) void readFile(file);
        }}
        className={`mt-2 rounded-lg border-2 border-dashed transition-colors ${
          dragging ? 'border-hcl-blue bg-hcl-light/60' : 'border-transparent'
        }`}
      >
        <textarea
          id="vex-document-text"
          value={value}
          onChange={(event) => {
            onChange(event.target.value);
            setFileName(null);
            setFileError(null);
          }}
          disabled={importing}
          className="min-h-28 w-full rounded-lg border border-hcl-border p-2 font-mono text-xs text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue disabled:opacity-60"
          placeholder='Drop a .json file here, choose one above, or paste: {"bomFormat":"CycloneDX","vulnerabilities":[...]}'
        />
      </div>

      {/* Preview — what the server will make of this document. */}
      {fileError ? (
        <p className="mt-2 flex items-start gap-1.5 text-xs text-red-600">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          {fileError}
        </p>
      ) : preview.error ? (
        <p className="mt-2 flex items-start gap-1.5 text-xs text-red-600">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          {preview.error}
        </p>
      ) : preview.ok ? (
        <p className="mt-2 flex items-start gap-1.5 text-xs text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          <span>
            {fileName ? <span className="font-medium">{fileName} · </span> : null}
            <span className="font-medium">{preview.format}</span> ·{' '}
            {preview.statementCount?.toLocaleString()}{' '}
            {preview.statementCount === 1 ? 'statement' : 'statements'}
            {preview.author ? ` · ${preview.author}` : ''}
            {preview.vulnerabilityIds?.length ? (
              <>
                {' · '}
                {preview.vulnerabilityIds.slice(0, 3).join(', ')}
                {preview.vulnerabilityIds.length > 3
                  ? ` +${preview.vulnerabilityIds.length - 3} more`
                  : ''}
              </>
            ) : null}
          </span>
        </p>
      ) : null}

      <div className="mt-2 flex items-center justify-between gap-3">
        <p className="text-xs text-hcl-muted">{message}</p>
        <Button size="sm" onClick={onImport} loading={importing} disabled={!canImport}>
          Import VEX
        </Button>
      </div>
    </div>
  );
}
