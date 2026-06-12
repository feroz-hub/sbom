'use client';

import { useRef, useState } from 'react';
import Link from 'next/link';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import { Upload, AlertCircle, AlertOctagon, ArrowRight } from 'lucide-react';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Button } from '@/components/ui/Button';
import { getProjects, getSbomTypes, HttpError } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { useSbomsList } from '@/hooks/useSbomsList';
import { useUploadSbom } from '@/hooks/useSbomMutations';
import { stageLabel, stageNumber } from '@/lib/sbomValidation';
import type { SBOMSource, SbomValidationFailureDetail } from '@/types';

function normalizeValidationFailureDetail(detail: unknown): SbomValidationFailureDetail | null {
  if (typeof detail !== 'object' || detail === null || Array.isArray(detail)) return null;
  const raw = detail as Partial<SbomValidationFailureDetail>;
  const looksLikeValidationFailure =
    raw.code === 'sbom_validation_failed' ||
    raw.status === 'validation_failed' ||
    Array.isArray(raw.entries) ||
    Boolean(raw.error_report);
  if (!looksLikeValidationFailure) return null;

  return {
    code: 'sbom_validation_failed',
    status: raw.status ?? 'validation_failed',
    message: raw.message ?? 'SBOM validation failed.',
    sbom_id: raw.sbom_id ?? null,
    session_id: raw.session_id ?? null,
    can_edit: raw.can_edit,
    can_ai_fix: raw.can_ai_fix,
    reason: raw.reason ?? null,
    failed_stage: raw.failed_stage ?? raw.error_report?.failed_stage ?? null,
    error_count: raw.error_count ?? raw.error_report?.error_count ?? 0,
    warning_count: raw.warning_count ?? raw.error_report?.warning_count ?? 0,
    entries: raw.entries ?? raw.error_report?.entries ?? [],
    truncated: raw.truncated ?? raw.error_report?.truncated ?? false,
    error_report: raw.error_report,
  };
}

const schema = z.object({
  sbom_name: z.string().min(1, 'Name is required'),
  sbom_data: z.string().min(2, 'SBOM content is required'),
  sbom_type_id: z.string().optional(),
  projectid: z.string().min(1, 'Project is required'),
  sbom_version: z.string().optional(),
  created_by: z.string().optional(),
  productver: z.string().optional(),
});

type FormValues = z.infer<typeof schema>;

function detectSbomTypeId(filename: string, types: { id: number; typename: string }[]): string {
  const lower = filename.toLowerCase();
  const hint =
    lower.includes('spdx') ? 'spdx' :
    lower.includes('cyclonedx') || lower.includes('cdx') ? 'cyclonedx' :
    lower.endsWith('.xml') ? 'spdx' :
    lower.endsWith('.json') ? 'cyclonedx' : '';
  if (!hint) return '';
  const match = types.find((t) => t.typename.toLowerCase().includes(hint));
  return match ? String(match.id) : '';
}

function formatUploadError(err: unknown): string {
  if (err instanceof HttpError) {
    if (err.status === 409)
      return `An SBOM with this name already exists. Rename your file or delete the existing SBOM first.`;
    if (err.status === 413)
      return 'File too large. Maximum size is 20 MB.';
    return err.message || 'Upload failed. Please try again.';
  }
  return err instanceof Error ? err.message : 'Upload failed. Please try again.';
}

interface SbomUploadModalProps {
  open: boolean;
  onClose: () => void;
  /** Called AFTER upload succeeds — before background analysis starts. */
  onSuccess?: (sbom: SBOMSource) => void;
}

export function SbomUploadModal({ open, onClose, onSuccess }: SbomUploadModalProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [validationFailure, setValidationFailure] = useState<SbomValidationFailureDetail | null>(null);
  const [duplicateNameError, setDuplicateNameError] = useState<string | null>(null);
  const { showToast } = useToast();
  const uploadMutation = useUploadSbom();
  const uploading = uploadMutation.isPending;

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
    enabled: open,
  });

  const { data: existingSboms } = useSbomsList({ enabled: open });

  const { data: sbomTypes } = useQuery({
    queryKey: ['sbom-types'],
    queryFn: ({ signal }) => getSbomTypes(signal),
    enabled: open,
  });

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      sbom_name: '', sbom_data: '', sbom_type_id: '',
      projectid: '', sbom_version: '', created_by: '', productver: '',
    },
  });
  const selectedProjectId = watch('projectid');
  const sbomNameValue = watch('sbom_name');
  const sbomDataValue = watch('sbom_data');
  const canSubmit = Boolean(
    selectedProjectId &&
    sbomNameValue?.trim() &&
    sbomDataValue?.trim() &&
    !duplicateNameError,
  );

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      setValue('sbom_data', content, { shouldValidate: true });
      if (!watch('sbom_name')) {
        setValue('sbom_name', file.name.replace(/\.[^/.]+$/, ''));
      }
      if (!watch('sbom_type_id') && sbomTypes?.length) {
        const detected = detectSbomTypeId(file.name, sbomTypes);
        if (detected) setValue('sbom_type_id', detected);
      }
    };
    reader.readAsText(file);
  };

  const handleNameBlur = (name: string) => {
    const trimmed = name.trim();
    setDuplicateNameError(null);
    if (!trimmed || !existingSboms?.length) return;
    const exists = existingSboms.some(
      (s) => s.sbom_name.trim().toLowerCase() === trimmed.toLowerCase(),
    );
    if (exists) {
      setDuplicateNameError(`An SBOM named "${trimmed}" already exists. Please choose a different name.`);
    }
  };

  const onSubmit = (values: FormValues) => {
    setUploadError(null);
    setValidationFailure(null);

    uploadMutation.mutate(
      {
        sbom_name: values.sbom_name,
        sbom_data: values.sbom_data,
        sbom_type: values.sbom_type_id ? Number(values.sbom_type_id) : undefined,
        projectid: values.projectid ? Number(values.projectid) : undefined,
        project_id: values.projectid ? Number(values.projectid) : undefined,
        sbom_version: values.sbom_version || undefined,
        created_by: values.created_by || undefined,
        productver: values.productver || undefined,
      },
      {
        onSuccess: (sbom) => {
          // Close modal IMMEDIATELY — user should never wait for analysis.
          reset();
          setUploadError(null);
          setValidationFailure(null);
          setDuplicateNameError(null);
          onClose();
          showToast(`"${sbom.sbom_name}" uploaded successfully`, 'success', {
            duration: 3000,
          });
          // Parent triggers background analysis after the modal closes.
          onSuccess?.(sbom);
        },
        onError: (err) => {
          // Validation failure (4xx with structured detail) → render the
          // structured rejection card with stage info + "View full report" link.
          const validationDetail = err instanceof HttpError ? normalizeValidationFailureDetail(err.detail) : null;
          if (validationDetail) {
            setValidationFailure(validationDetail);
            setUploadError(null);
          } else {
            // Generic upload failure (network, 409 duplicate, 413 too-large) —
            // fall back to the existing one-line error banner.
            setUploadError(formatUploadError(err));
          }
        },
      },
    );
  };

  const handleClose = () => {
    if (uploading) return; // don't close mid-upload
    reset();
    setUploadError(null);
    setValidationFailure(null);
    setDuplicateNameError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} title="Upload SBOM" maxWidth="lg">
      <form onSubmit={handleSubmit(onSubmit)}>
        <DialogBody className="space-y-4">

          {/* Structured validation failure — surfaces the persisted report
              and offers a one-click jump to the full detail page. */}
          {validationFailure && (
            <div
              className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm dark:border-red-800 dark:bg-red-950/40"
              role="alert"
            >
              <div className="flex items-start gap-2">
                <AlertOctagon className="h-4 w-4 mt-0.5 shrink-0 text-red-600 dark:text-red-400" aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-red-700 dark:text-red-300">
                    Upload rejected — {validationFailure.error_count} error
                    {validationFailure.error_count === 1 ? '' : 's'} found
                  </p>
                  <p className="mt-0.5 text-xs text-red-700/90 dark:text-red-300/90">
                    {validationFailure.failed_stage ? (
                      <>
                        Stopped at: <span className="font-medium">Stage {stageNumber(validationFailure.failed_stage)} — {stageLabel(validationFailure.failed_stage)}</span>
                      </>
                    ) : (
                      'Validation halted before any stage completed.'
                    )}
                    {validationFailure.warning_count > 0 && (
                      <> · {validationFailure.warning_count} warning{validationFailure.warning_count === 1 ? '' : 's'}</>
                    )}
                  </p>
                  {/* Show the first error inline so the user has immediate
                      context without opening the full detail page. */}
                  {validationFailure.entries[0] && (
                    <div className="mt-2 rounded-md border border-red-200 bg-white/60 px-3 py-2 text-xs dark:border-red-800 dark:bg-red-950/20">
                      <p className="font-mono font-semibold text-red-800 dark:text-red-300 break-all">
                        {validationFailure.entries[0].code}
                      </p>
                      {validationFailure.entries[0].path && (
                        <p className="mt-0.5 font-mono text-[11px] text-red-700/80 dark:text-red-300/80 break-all">
                          {validationFailure.entries[0].path}
                        </p>
                      )}
                      <p className="mt-1 text-red-800 dark:text-red-200 break-words">
                        {validationFailure.entries[0].message}
                      </p>
                    </div>
                  )}
                  <div className="mt-3 flex flex-wrap items-center gap-3">
                    {validationFailure.session_id && validationFailure.can_edit !== false ? (
                      <Link
                        href={`/sbom-validation-sessions/${validationFailure.session_id}`}
                        className="inline-flex items-center gap-1 text-xs font-medium text-red-700 hover:underline dark:text-red-300"
                        onClick={handleClose}
                      >
                        Open repair workspace
                        <ArrowRight className="h-3 w-3" aria-hidden />
                      </Link>
                    ) : (
                      <span className="text-xs font-medium text-red-700 dark:text-red-300">
                        {validationFailure.reason || 'This payload cannot be edited safely.'}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => fileRef.current?.click()}
                      className="text-xs font-medium text-hcl-muted hover:text-hcl-navy hover:underline"
                    >
                      Choose another file
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Inline upload error — shown only for non-validation failures
              (network errors, 409 duplicate, 413 too-large). */}
          {uploadError && !validationFailure && (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}

          <Input
            label="SBOM Name"
            required
            placeholder="e.g. my-app-sbom"
            error={errors.sbom_name?.message ?? duplicateNameError ?? undefined}
            disabled={uploading}
            {...register('sbom_name', {
              onBlur: (e) => handleNameBlur(e.target.value),
            })}
          />

          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-hcl-navy">
              SBOM Content (JSON / XML) <span className="text-red-500">*</span>
            </label>
            <div className="flex items-center gap-2 mb-2">
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                disabled={uploading}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-hcl-navy bg-surface border border-hcl-border rounded-lg hover:bg-hcl-light transition-colors disabled:opacity-50"
              >
                <Upload className="h-3.5 w-3.5" />
                Upload from file
              </button>
              <span className="text-xs text-hcl-muted">or paste JSON / XML below</span>
              <input
                ref={fileRef}
                type="file"
                accept=".json,.xml,.spdx"
                onChange={handleFileChange}
                className="hidden"
              />
            </div>
            <Textarea
              placeholder='{"bomFormat": "CycloneDX", ...}'
              error={errors.sbom_data?.message}
              className="font-mono text-xs min-h-[160px]"
              disabled={uploading}
              {...register('sbom_data')}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Project"
              placeholder="Select project..."
              disabled={uploading}
              required
              error={errors.projectid?.message}
              hint={!projects?.length ? 'Create a project before uploading an SBOM.' : undefined}
              {...register('projectid')}
            >
              {projects?.map((p) => (
                <option key={p.id} value={p.id}>{p.project_name}</option>
              ))}
            </Select>
            <Select label="SBOM Type / Format" placeholder="Select type..." disabled={uploading} {...register('sbom_type_id')}>
              {sbomTypes?.length
                ? sbomTypes.map((t) => <option key={t.id} value={t.id}>{t.typename}</option>)
                : <option value="">Unknown</option>}
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Input label="SBOM Version" placeholder="e.g. 1.0.0" disabled={uploading} {...register('sbom_version')} />
            <Input label="Product Version" placeholder="e.g. 2.3.1" disabled={uploading} {...register('productver')} />
          </div>

          <Input label="Created By" placeholder="Your name or username" disabled={uploading} {...register('created_by')} />
        </DialogBody>

        <DialogFooter>
          <Button type="button" variant="secondary" onClick={handleClose} disabled={uploading}>
            Cancel
          </Button>
          <Button type="submit" loading={uploading} disabled={uploading || !canSubmit}>
            {uploading ? 'Uploading…' : 'Upload SBOM'}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
