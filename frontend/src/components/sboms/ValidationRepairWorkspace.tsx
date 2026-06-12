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
  applyValidationRepairPatch,
  getValidationRepairHistory,
  getValidationRepairSession,
  importRepairSession,
  suggestValidationRepairFixes,
  updateValidationRepairSession,
  validateRepairSession,
} from '@/lib/api';
import { stageLabel, stageNumber } from '@/lib/sbomValidation';
import type { AiRepairSuggestion, ValidationErrorEntry, ValidationRepairPatch } from '@/types';

interface ValidationRepairWorkspaceProps {
  sessionId: string;
}

function groupErrors(entries: ValidationErrorEntry[]) {
  return entries.reduce<Record<string, ValidationErrorEntry[]>>((acc, entry) => {
    const key = entry.stage || 'unknown';
    acc[key] = acc[key] ?? [];
    acc[key].push(entry);
    return acc;
  }, {});
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

export function ValidationRepairWorkspace({ sessionId }: ValidationRepairWorkspaceProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [content, setContent] = useState('');
  const [suggestion, setSuggestion] = useState<AiRepairSuggestion | null>(null);
  const [selected, setSelected] = useState<Record<number, boolean>>({});
  const [localMessage, setLocalMessage] = useState<string | null>(null);

  const sessionQuery = useQuery({
    queryKey: ['validation-repair-session', sessionId],
    queryFn: ({ signal }) => getValidationRepairSession(sessionId, signal),
  });

  const historyQuery = useQuery({
    queryKey: ['validation-repair-history', sessionId],
    queryFn: ({ signal }) => getValidationRepairHistory(sessionId, signal),
  });

  useEffect(() => {
    if (sessionQuery.data) setContent(sessionQuery.data.current_content);
  }, [sessionQuery.data?.id, sessionQuery.data?.current_content]);

  const updateMutation = useMutation({
    mutationFn: () => updateValidationRepairSession(sessionId, content),
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      setLocalMessage('Draft saved in the repair workspace.');
    },
  });

  const validateMutation = useMutation({
    mutationFn: async () => {
      const saved = await updateValidationRepairSession(sessionId, content);
      queryClient.setQueryData(['validation-repair-session', sessionId], saved);
      return validateRepairSession(sessionId);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
      setLocalMessage(updated.validation_status === 'passed' ? 'Validation passed. Import is now available.' : 'Validation completed with remaining issues.');
    },
  });

  const importMutation = useMutation({
    mutationFn: () => importRepairSession(sessionId),
    onSuccess: (sbom) => {
      queryClient.invalidateQueries({ queryKey: ['sboms'] });
      queryClient.invalidateQueries({ queryKey: ['validation-repair-session', sessionId] });
      router.push(`/sboms/${sbom.id}`);
    },
  });

  const suggestMutation = useMutation({
    mutationFn: () => suggestValidationRepairFixes(sessionId),
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
      return applyValidationRepairPatch(sessionId, patches);
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
  const canImport = session?.validation_status === 'passed' && (report?.error_count ?? 0) === 0;
  const hasSelectedPatch = suggestion?.patches.some((_, idx) => selected[idx]) ?? false;

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
              >
                <Save className="h-4 w-4" />
                Save draft
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
                Object.entries(grouped).map(([stage, stageEntries]) => (
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
                        {entry.path && <p className="font-mono text-hcl-muted break-all">{entry.path}</p>}
                        <p className="mt-1 text-foreground">{entry.message}</p>
                        <p className="mt-1 text-hcl-muted">{entry.remediation}</p>
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
