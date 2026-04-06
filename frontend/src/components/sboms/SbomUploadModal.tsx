'use client';

import { useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import { Upload, AlertCircle } from 'lucide-react';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Button } from '@/components/ui/Button';
import { createSbom, getProjects, getSbomTypes, getSboms, HttpError } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import type { SBOMSource } from '@/types';

const schema = z.object({
  sbom_name: z.string().min(1, 'Name is required'),
  sbom_data: z.string().min(2, 'SBOM content is required'),
  sbom_type_id: z.string().optional(),
  projectid: z.string().optional(),
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
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [duplicateNameError, setDuplicateNameError] = useState<string | null>(null);
  const { showToast } = useToast();

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
    enabled: open,
  });

  const { data: existingSboms } = useQuery({
    queryKey: ['sboms', { page: 1, pageSize: 500 }],
    queryFn: ({ signal }) => getSboms(1, 500, signal),
    enabled: open,
  });

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

  const onSubmit = async (values: FormValues) => {
    setUploading(true);
    setUploadError(null);

    let sbom: SBOMSource;
    try {
      sbom = await createSbom({
        sbom_name: values.sbom_name,
        sbom_data: values.sbom_data,
        sbom_type: values.sbom_type_id ? Number(values.sbom_type_id) : undefined,
        projectid: values.projectid ? Number(values.projectid) : undefined,
        sbom_version: values.sbom_version || undefined,
        created_by: values.created_by || undefined,
        productver: values.productver || undefined,
      });
    } catch (err) {
      // Upload failed — stay in modal, show inline error. No toast.
      setUploadError(formatUploadError(err));
      setUploading(false);
      return; // modal stays open
    }

    // ── Upload succeeded ────────────────────────────────────────────────
    // Close modal IMMEDIATELY — user should never wait for analysis.
    setUploading(false);
    reset();
    setUploadError(null);
    setDuplicateNameError(null);
    onClose(); // ← CLOSE HERE (line order matters — before onSuccess triggers analysis)

    // Quick confirmation toast — background analysis toast follows immediately
    showToast(`"${sbom.sbom_name}" uploaded successfully`, 'success', { duration: 3000 });

    // Notify parent AFTER modal closes — adds to list + fires background analysis
    onSuccess?.(sbom);
  };

  const handleClose = () => {
    if (uploading) return; // don't close mid-upload
    reset();
    setUploadError(null);
    setDuplicateNameError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} title="Upload SBOM" maxWidth="lg">
      <form onSubmit={handleSubmit(onSubmit)}>
        <DialogBody className="space-y-4">

          {/* Inline upload error — shown only for upload failures (NOT analysis failures) */}
          {uploadError && (
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
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-hcl-navy bg-white border border-hcl-border rounded-lg hover:bg-hcl-light transition-colors disabled:opacity-50"
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
            <Select label="Project" placeholder="Select project..." disabled={uploading} {...register('projectid')}>
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
          <Button type="submit" loading={uploading}>
            {uploading ? 'Uploading…' : 'Upload SBOM'}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
