'use client';

import { useRef } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Button } from '@/components/ui/Button';
import { createSbom, getProjects, getSbomTypes } from '@/lib/api';
import { useToast } from '@/hooks/useToast';

const schema = z.object({
  sbom_name: z.string().min(1, 'Name is required'),
  sbom_data: z.string().min(2, 'SBOM content is required'),
  sbom_type_id: z.string().optional(),   // stores the SBOMType id as string (select value)
  projectid: z.string().optional(),
  sbom_version: z.string().optional(),
  created_by: z.string().optional(),
  productver: z.string().optional(),
});

type FormValues = z.infer<typeof schema>;

// Detect SBOM format from filename
function detectSbomTypeId(filename: string, types: { id: number; typename: string }[]): string {
  const lower = filename.toLowerCase();
  const hint =
    lower.includes('spdx') ? 'spdx' :
    lower.includes('cyclonedx') || lower.includes('cdx') ? 'cyclonedx' :
    lower.endsWith('.xml') ? 'spdx' :
    lower.endsWith('.json') ? 'cyclonedx' :
    '';
  if (!hint) return '';
  const match = types.find((t) => t.typename.toLowerCase().includes(hint));
  return match ? String(match.id) : '';
}

interface SbomUploadModalProps {
  open: boolean;
  onClose: () => void;
}

export function SbomUploadModal({ open, onClose }: SbomUploadModalProps) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const fileRef = useRef<HTMLInputElement>(null);

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
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
      sbom_name: '',
      sbom_data: '',
      sbom_type_id: '',
      projectid: '',
      sbom_version: '',
      created_by: '',
      productver: '',
    },
  });

  const mutation = useMutation({
    mutationFn: (values: FormValues) =>
      createSbom({
        sbom_name: values.sbom_name,
        sbom_data: values.sbom_data,
        // send integer FK — backend expects sbom_type as int referencing SBOMType.id
        sbom_type: values.sbom_type_id ? Number(values.sbom_type_id) : undefined,
        projectid: values.projectid ? Number(values.projectid) : undefined,
        sbom_version: values.sbom_version || undefined,
        created_by: values.created_by || undefined,
        productver: values.productver || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sboms'] });
      showToast('SBOM uploaded successfully', 'success');
      reset();
      onClose();
    },
    onError: (err: Error) => {
      showToast(`Upload failed: ${err.message}`, 'error');
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
      // Auto-detect SBOM type from filename
      if (!watch('sbom_type_id') && sbomTypes?.length) {
        const detected = detectSbomTypeId(file.name, sbomTypes);
        if (detected) setValue('sbom_type_id', detected);
      }
    };
    reader.readAsText(file);
  };

  const onSubmit = (values: FormValues) => mutation.mutate(values);

  return (
    <Dialog open={open} onClose={onClose} title="Upload SBOM" maxWidth="lg">
      <form onSubmit={handleSubmit(onSubmit)}>
        <DialogBody className="space-y-4">
          <Input
            label="SBOM Name"
            required
            placeholder="e.g. my-app-sbom"
            error={errors.sbom_name?.message}
            {...register('sbom_name')}
          />

          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-hcl-navy">
              SBOM Content (JSON / XML) <span className="text-red-500">*</span>
            </label>
            <div className="flex items-center gap-2 mb-2">
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-hcl-navy bg-white border border-hcl-border rounded-lg hover:bg-hcl-light transition-colors"
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
              {...register('sbom_data')}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Project"
              placeholder="Select project..."
              {...register('projectid')}
            >
              {projects?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.project_name}
                </option>
              ))}
            </Select>

            <Select
              label="SBOM Type / Format"
              placeholder="Select type..."
              {...register('sbom_type_id')}
            >
              {sbomTypes?.length ? (
                sbomTypes.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.typename}
                  </option>
                ))
              ) : (
                // Fallback if types not seeded — these won't match real FK IDs
                <>
                  <option value="">Unknown</option>
                </>
              )}
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Input
              label="SBOM Version"
              placeholder="e.g. 1.0.0"
              {...register('sbom_version')}
            />
            <Input
              label="Product Version"
              placeholder="e.g. 2.3.1"
              {...register('productver')}
            />
          </div>

          <Input
            label="Created By"
            placeholder="Your name or username"
            {...register('created_by')}
          />
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={mutation.isPending}>
            Upload SBOM
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
