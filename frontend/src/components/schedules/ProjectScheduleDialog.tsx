'use client';

import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { ScheduleCard } from './ScheduleCard';
import type { Project } from '@/types';

/**
 * Wraps ScheduleCard in a Dialog so the projects table row can launch
 * the schedule UI without a dedicated project-detail page. Re-uses the
 * same card the SBOM detail page renders for visual consistency.
 */

interface ProjectScheduleDialogProps {
  open: boolean;
  onClose: () => void;
  project: Project;
}

export function ProjectScheduleDialog({ open, onClose, project }: ProjectScheduleDialogProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Periodic analysis · ${project.project_name}`}
      maxWidth="xl"
    >
      <DialogBody>
        <p className="mb-4 text-sm text-hcl-muted">
          Configure how often eligible Product SBOMs in this Project are re-analyzed. Product and
          SBOM overrides, exclusions, and the selected version policy are respected.
        </p>
        <ScheduleCard scope="PROJECT" targetId={project.id} />
      </DialogBody>
    </Dialog>
  );
}
