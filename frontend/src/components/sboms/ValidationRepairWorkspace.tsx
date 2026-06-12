'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Bot, CheckCircle, FileInput, RefreshCw, Save, ShieldAlert, Wand2 } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Textarea } from '@/components/ui/Input';
import { PageSpinner } from '@/components/ui/Spinner';
import {
  applyValidationSessionPatch,
  getProject,
  getProjects,
  getValidationSession,
  getValidationSessionHistory,
  importValidationSession,
  suggestValidationSessionFixes,
  updateValidationSession,
  validateValidationSession,
} from '@/lib/api';
import { Select } from '@/components/ui/Select';
import { invalidateDashboardTiles, invalidateProjectSurfaces, invalidateSbomSurfaces } from '@/lib/queryInvalidation';
import { STAGE_NUMBERS, stageLabel, stageNumber } from '@/lib/sbomValidation';
import type { AiRepairSuggestion, ValidationErrorEntry, ValidationRepairPatch } from '@/types';

interface ValidationRepairWorkspaceProps {
  sessionId: string;
}

function groupErrors(entries: ValidationErrorEntry[]) {
  const grouped = entries.reduce<Record<string, ValidationErrorEntry[]>>((acc, entry) => {
    const key = entry.stage || 'unknown';
    acc[key] = acc[key] ?? [];
    acc[key].push(entry);
    return acc;
  }, {});
  return Object.entries(grouped).sort(([a], [b]) => {
    const rankA = STAGE_NUMBERS[a] ?? 99;
    const rankB = STAGE_NUMBERS[b] ?? 99;
    return rankA - rankB;
  });
}

function severityVariant(severity: string): 'error' | 'warning' | 'info' | 'gray' {
  if (severity === 'error') return 'error';
  if (severity === 'warning') return 'warning';
  if (severity === 'info') return 'info';
  return 'gray';
}

function formatPatchValue(value: unknown) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

function formatLocation(entry: ValidationErrorEntry) {
  if (entry.path) return entry.path;
  if (entry.json_pointer) return entry.json_pointer;
  if (entry.xpath) return entry.xpath;
  if (entry.line != null && entry.column != null) return `Line ${entry.line}, column ${entry.column}`;
  if (entry.line != null) return `Line ${entry.line}`;
  return '';
}

function mutationErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

export function ValidationRepairWorkspace({ sessionId }: ValidationRepairWorkspaceProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [content, setContent] = useState('');
  const [suggestion, setSuggestion] = useState<AiRepairSuggestion | null>(null);
  const [selected, setSelected] = useState<Record<number, boolean>>({});
  const [localMessage, setLocalMessage] = useState<string | null>(null);

  const sessionQuery = useQuery({
    queryKey: ['validation-repair-session', sessionId],
    queryFn: ({ signal }) => getValidationSession(sessionId, signal),
  });

  const historyQuery = useQuery({
    queryKey: ['validation-repair-history', sessionId],
    queryFn: ({ signal }) => getValidationSessionHistory(sessionId, signal),
  });

  const projectQuery = useQuery({
    queryKey: ['project', sessionQuery.data?.project_id],
    queryFn: ({ signal }) => getProject(sessionQuery.data!.project_id!, signal),
    enabled: sessionQuery.data?.project_id != null,
  });

  const projectsQuery = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const handleProjectChange = async (projectId: number | null) => {
    try {
      const updated = await updateValidationSession(sessionId, { project_id: projectId });
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['project', projectId] });
      setLocalMessage('Project assignment updated.');
    } catch (err: any) {
      setLocalMessage(`Failed to update project: ${err.message}`);
    }
  };

  useEffect(() => {
    if (sessionQuery.data) setContent(sessionQuery.data.current_content);
  }, [sessionQuery.data?.id, sessionQuery.data?.current_content]);

  const updateMutation = useMutation({
    mutationFn: () => updateValidationSession(sessionId, content),
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      setLocalMessage('Draft saved in the repair workspace.');
    },
  });

  const validateMutation = useMutation({
    mutationFn: async () => {
      if (sessionQuery.data && content !== sessionQuery.data.current_content) {
        const saved = await updateValidationSession(sessionId, content);
        queryClient.setQueryData(['validation-repair-session', sessionId], saved);
      }
      return validateValidationSession(sessionId);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      setLocalMessage(updated.validation_status === 'passed' ? 'Validation passed. Import is now available.' : 'Validation completed with remaining issues.');
    },
  });

  const importMutation = useMutation({
    mutationFn: () => importValidationSession(sessionId, true),
    onSuccess: (sbom) => {
      invalidateSbomSurfaces(queryClient, sbom.id);
      invalidateProjectSurfaces(queryClient, sbom.project_id ?? sbom.projectid ?? sessionQuery.data?.project_id);
      invalidateDashboardTiles(queryClient);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-session', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      router.push(`/sboms/${sbom.id}`);
    },
  });

  const suggestMutation = useMutation({
    mutationFn: () => suggestValidationSessionFixes(sessionId, { user_instruction: '' }),
    onSuccess: (result) => {
      setSuggestion(result);
      const initial: Record<number, boolean> = {};
      result.patches.forEach((_, idx) => {
        initial[idx] = true;
      });
      setSelected(initial);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
    },
  });

  const applyMutation = useMutation({
    mutationFn: async () => {
      if (!suggestion) return null;
      const patches = suggestion.patches.filter((_, idx) => selected[idx]);
      return applyValidationSessionPatch(sessionId, { patches });
    },
    onSuccess: (updated) => {
      if (!updated) return;
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      setContent(updated.current_content);
      setSuggestion(null);
      setSelected({});
      setLocalMessage(updated.validation_status === 'passed' ? 'Patch applied and validation passed.' : 'Patch applied and validation reran.');
    },
  });

  const session = sessionQuery.data;
  const report = session?.latest_error_report;
  const entries = report?.entries ?? [];
  const grouped = useMemo(() => groupErrors(entries), [entries]);
  const hardErrorCount = entries.filter((entry) => entry.severity === 'error').length;
  const canImport = session?.validation_status === 'passed' && (report?.error_count ?? hardErrorCount) === 0 && hardErrorCount === 0 && session?.project_id != null;
  const hasSelectedPatch = suggestion?.patches.some((_, idx) => selected[idx]) ?? false;
  const hasUnsavedChanges = Boolean(session && content !== session.current_content);

  if (sessionQuery.isLoading) return <PageSpinner />;

  if (sessionQuery.error || !session) {
    return (
      <Alert variant="error" title="Could not load validation session">
        {sessionQuery.error instanceof Error ? sessionQuery.error.message : 'The repair session does not exist or expired.'}
      </Alert>
    );
  }

  if (!session.can_edit && session.validation_status === 'security_blocked') {
    return (
      <Alert variant="error" title="Security-blocked payload">
        {session.security_blocked_reason || 'This payload cannot be opened safely in the repair workspace.'}
      </Alert>
    );
  }

  return (
    <div className="space-y-5">
      {localMessage && (
        <Alert variant={canImport ? 'success' : 'info'} title="Workspace updated">
          {localMessage}
        </Alert>
      )}
      {(updateMutation.error || validateMutation.error || suggestMutation.error || applyMutation.error || importMutation.error) && (
        <Alert variant="error" title="Repair action failed">
          {mutationErrorMessage(
            updateMutation.error || validateMutation.error || suggestMutation.error || applyMutation.error || importMutation.error,
            'The repair action could not be completed.',
          )}
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Validation Session</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-xs font-medium text-hcl-muted">Session ID</dt>
              <dd className="mt-1 font-mono text-xs text-hcl-navy break-all">{session.id}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted">Original filename</dt>
              <dd className="mt-1 text-hcl-navy">{session.original_filename || session.sbom_name || 'Unknown'}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted">Assigned project</dt>
              <dd className="mt-1">
                <Select
                  aria-label="Assign Project"
                  value={session.project_id || ''}
                  onChange={(e) => handleProjectChange(e.target.value ? Number(e.target.value) : null)}
                  disabled={!session.can_edit}
                  placeholder="Select a project..."
                  className="h-8 py-0 text-xs font-medium"
                >
                  {projectsQuery.data?.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.project_name}
                    </option>
                  ))}
                </Select>
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted">Detected format</dt>
              <dd className="mt-1 text-hcl-navy">
                {session.detected_format || 'Unknown'}{session.detected_version ? ` ${session.detected_version}` : ''}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-hcl-muted">Current status</dt>
              <dd className="mt-1">
                <Badge variant={session.validation_status === 'passed' || session.validation_status === 'imported' ? 'success' : 'warning'}>
                  {session.validation_status.replace('_', ' ')}
                </Badge>
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <Card className="min-w-0">
          <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>Repair Editor</CardTitle>
              <p className="mt-1 text-xs text-hcl-muted">
                {session.detected_format || 'Unknown format'} {session.detected_version ? `· ${session.detected_version}` : ''}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => updateMutation.mutate()}
                loading={updateMutation.isPending}
                disabled={!session.can_edit || !hasUnsavedChanges}
              >
                <Save className="h-4 w-4" />
                {hasUnsavedChanges ? 'Save changes' : 'Saved'}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => validateMutation.mutate()}
                loading={validateMutation.isPending}
              >
                <RefreshCw className="h-4 w-4" />
                Revalidate
              </Button>
              <Button
                size="sm"
                disabled={!canImport}
                onClick={() => importMutation.mutate()}
                loading={importMutation.isPending}
              >
                <FileInput className="h-4 w-4" />
                Import SBOM
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <Textarea
              aria-label="SBOM repair editor"
              value={content}
              onChange={(event) => setContent(event.target.value)}
              className="min-h-[520px] font-mono text-xs leading-relaxed"
              disabled={!session.can_edit}
            />
            {hasUnsavedChanges && (
              <p className="mt-2 text-xs font-medium text-amber-700 dark:text-amber-300">
                Unsaved changes
              </p>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Validation Status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <Badge variant={session.validation_status === 'passed' || session.validation_status === 'imported' ? 'success' : 'warning'}>
                  {session.validation_status.replace('_', ' ')}
                </Badge>
                <Badge variant={(report?.error_count ?? 0) > 0 ? 'error' : 'success'}>
                  {report?.error_count ?? 0} errors
                </Badge>
                <Badge variant="warning">{report?.warning_count ?? 0} warnings</Badge>
              </div>
              {canImport ? (
                <p className="text-sm text-emerald-700 dark:text-emerald-200">
                  Validation passed through all required stages.
                </p>
              ) : (
                <p className="text-sm text-hcl-muted">
                  Import remains disabled until the current content revalidates successfully.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Validation Errors</CardTitle>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => suggestMutation.mutate()}
                loading={suggestMutation.isPending}
                disabled={!session.can_ai_fix || entries.length === 0}
              >
                <Wand2 className="h-4 w-4" />
                AI fix
              </Button>
            </CardHeader>
            <CardContent className="max-h-[480px] space-y-4 overflow-auto">
              {entries.length === 0 ? (
                <div className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-200">
                  <CheckCircle className="h-4 w-4" />
                  No validation errors remain.
                </div>
              ) : (
                grouped.map(([stage, stageEntries]) => (
                  <div key={stage} className="space-y-2">
                    <h3 className="text-sm font-semibold text-hcl-navy">
                      Stage {stageNumber(stage)} · {stageLabel(stage)}
                    </h3>
                    {stageEntries.map((entry, idx) => (
                      <div key={`${entry.code}-${idx}`} className="rounded-lg border border-border bg-surface-muted p-3 text-xs">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <Badge variant={severityVariant(entry.severity)}>{entry.severity}</Badge>
                          <span className="font-mono font-semibold text-hcl-navy">{entry.code}</span>
                          {entry.can_ai_fix === false && <ShieldAlert className="h-3.5 w-3.5 text-amber-600" aria-label="Manual fix required" />}
                        </div>
                        {formatLocation(entry) && <p className="font-mono text-hcl-muted break-all">{formatLocation(entry)}</p>}
                        <p className="mt-1 text-foreground">{entry.message}</p>
                        {entry.remediation && <p className="mt-1 text-hcl-muted">{entry.remediation}</p>}
                        {entry.spec_reference && <p className="mt-1 text-hcl-muted">{entry.spec_reference}</p>}
                      </div>
                    ))}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </section>

      {suggestion && (
        <Card>
          <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>AI Suggestions</CardTitle>
              <p className="mt-1 text-sm text-hcl-muted">{suggestion.summary}</p>
            </div>
            <Button
              size="sm"
              onClick={() => applyMutation.mutate()}
              loading={applyMutation.isPending}
              disabled={!hasSelectedPatch}
            >
              <Bot className="h-4 w-4" />
              Apply selected
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            <Alert variant="warning" title="Review required">
              AI suggestions are not saved until you apply selected patches. The server revalidates immediately after applying.
            </Alert>
            {suggestion.patches.length === 0 ? (
              <p className="text-sm text-hcl-muted">No safe automated patches were returned.</p>
            ) : (
              suggestion.patches.map((patch, idx) => (
                <label key={`${patch.target}-${idx}`} className="block rounded-lg border border-border bg-surface-muted p-3">
                  <span className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      className="mt-1 h-4 w-4"
                      checked={Boolean(selected[idx])}
                      onChange={(event) => setSelected((old) => ({ ...old, [idx]: event.target.checked }))}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="font-mono text-xs font-semibold text-hcl-navy break-all">
                        {patch.operation.toUpperCase()} {patch.target}
                      </span>
                      <span className="mt-1 block text-sm text-foreground">{patch.reason}</span>
                      <span className="mt-2 grid gap-2 md:grid-cols-2">
                        <code className="max-h-44 overflow-auto rounded border border-red-200 bg-red-50 p-2 text-xs text-red-900 whitespace-pre-wrap">
                          {formatPatchValue(patch.before)}
                        </code>
                        <code className="max-h-44 overflow-auto rounded border border-emerald-200 bg-emerald-50 p-2 text-xs text-emerald-900 whitespace-pre-wrap">
                          {formatPatchValue(patch.after)}
                        </code>
                      </span>
                    </span>
                  </span>
                </label>
              ))
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Repair History</CardTitle>
        </CardHeader>
        <CardContent>
          {historyQuery.isLoading ? (
            <p className="text-sm text-hcl-muted">Loading history…</p>
          ) : historyQuery.error ? (
            <Alert variant="error" title="Could not load repair history">
              {mutationErrorMessage(historyQuery.error, 'Repair history could not be loaded.')}
            </Alert>
          ) : !historyQuery.data?.length ? (
            <p className="text-sm text-hcl-muted">No repair actions recorded yet.</p>
          ) : (
            <ol className="space-y-2">
              {historyQuery.data.map((event) => (
                <li key={event.id} className="flex flex-col gap-1 border-b border-border pb-2 text-sm last:border-b-0">
                  <span className="font-medium text-hcl-navy">{event.event_type.replaceAll('_', ' ')}</span>
                  <span className="text-xs text-hcl-muted">{event.timestamp}</span>
                  {event.summary && <span className="text-sm text-foreground">{event.summary}</span>}
                </li>
              ))}
            </ol>
          )}
          {session.imported_sbom_id && (
            <Link href={`/sboms/${session.imported_sbom_id}`} className="mt-4 inline-flex text-sm font-medium text-primary hover:underline">
              View imported SBOM
            </Link>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
