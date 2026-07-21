'use client';

import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Button } from '@/components/ui/Button';
import { createProject, updateProject } from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { toUserFacingApiError } from '@/lib/notifications';
import {
  invalidateProjectLists,
  invalidateSbomLists,
} from '@/lib/queryInvalidation';
import type { Project } from '@/types';

const schema = z.object({
  project_name: z.string().min(1, 'Project name is required'),
  project_details: z.string().optional(),
  project_status: z.enum(['Active', 'Inactive']),  // UI uses strings; converted to int on submit
  created_by: z.string().optional(),
});

type FormValues = z.infer<typeof schema>;

const toStatusInt = (s: 'Active' | 'Inactive') => (s === 'Active' ? 1 : 0);
const toStatusStr = (n: number): 'Active' | 'Inactive' => (n === 1 ? 'Active' : 'Inactive');

interface ProjectModalProps {
  open: boolean;
  onClose: () => void;
  project?: Project;
}

export function ProjectModal({ open, onClose, project }: ProjectModalProps) {
  const queryClient = useQueryClient();
  const { showSuccess, showApiError } = useNotifications();
  const isEdit = !!project;

  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      project_name: '',
      project_details: '',
      project_status: 'Active',
      created_by: '',
    },
  });

  useEffect(() => {
    if (project) {
      reset({
        project_name: project.project_name,
        project_details: project.project_details ?? '',
        project_status: toStatusStr(project.project_status),
        created_by: project.created_by ?? '',
      });
    } else {
      reset({ project_name: '', project_details: '', project_status: 'Active', created_by: '' });
    }
  }, [project, reset]);

  const mutation = useMutation({
    mutationFn: (values: FormValues) => {
      if (isEdit && project) {
        return updateProject(project.id, {
          project_name: values.project_name,
          project_details: values.project_details,
          project_status: toStatusInt(values.project_status),
        });
      }
      return createProject({
        project_name: values.project_name,
        project_details: values.project_details,
        project_status: toStatusInt(values.project_status),
        created_by: values.created_by,
      });
    },
    onSuccess: (_result, values) => {
      invalidateProjectLists(queryClient);
      // SBOM rows render project_name; a rename leaves them stale until
      // staleTime expires. Bust the SBOM list surfaces too.
      invalidateSbomLists(queryClient);
      showSuccess(
        `Project “${values.project_name.trim()}” was ${isEdit ? 'updated' : 'created'} successfully.`,
      );
      onClose();
    },
    onError: (error: unknown) => {
      const normalized = toUserFacingApiError(
        error,
        isEdit ? 'Project update failed. Please try again.' : 'Project creation failed. Please try again.',
      );
      for (const [field, messages] of Object.entries(normalized.fieldErrors)) {
        if (field in schema.shape) setError(field as keyof FormValues, { message: messages[0] });
      }
      showApiError(error, normalized.message);
    },
  });

  const onSubmit = (values: FormValues) => mutation.mutate(values);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={isEdit ? 'Edit Project' : 'New Project'}
      maxWidth="md"
    >
      <form onSubmit={handleSubmit(onSubmit)}>
        <DialogBody className="space-y-4">
          <Input
            label="Project Name"
            required
            placeholder="e.g. My Application"
            error={errors.project_name?.message}
            {...register('project_name')}
          />
          <Textarea
            label="Details"
            placeholder="Optional description..."
            error={errors.project_details?.message}
            {...register('project_details')}
          />
          <Select
            label="Status"
            required
            error={errors.project_status?.message}
            {...register('project_status')}
          >
            <option value="Active">Active</option>
            <option value="Inactive">Inactive</option>
          </Select>
          {!isEdit && (
            <Input
              label="Created By"
              placeholder="Your name or username"
              error={errors.created_by?.message}
              {...register('created_by')}
            />
          )}
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={mutation.isPending}>
            {isEdit ? 'Save Changes' : 'Create Project'}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
