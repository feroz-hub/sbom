'use client';
import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Save } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Input';
import { applyValidationSessionLinePatches, getValidationSessionContentLines, searchValidationSession } from '@/lib/api';
import type { ValidationRepairSession, LineRepairPatch } from '@/types';
function mutationErrorMessage(error: unknown, fallback: string) { return error instanceof Error ? error.message : fallback; }
function invalidateValidationRepairHistory(client: ReturnType<typeof useQueryClient>, id: string) { client.invalidateQueries({ queryKey: ['validation-repair-history', id] }); }
function invalidateValidationRepairDraftQueries(client: ReturnType<typeof useQueryClient>, id: string) { for (const key of ['sbom-auto-repair-analysis', 'sbom-auto-repair-job', 'validation-repair-content', 'validation-repair-lines', 'validation-repair-search']) client.invalidateQueries({ queryKey: [key, id] }); client.invalidateQueries({ queryKey: ['sbom-quality', 'session', id] }); }
function formatBytes(value: number | null | undefined) {
  if (value == null) return 'Unknown';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function LargeFileRepairEditor({
  session,
  sessionId,
  onSessionUpdate,
  navigation,
  onBusyChange,
}: {
  session: ValidationRepairSession;
  sessionId: string;
  onSessionUpdate: (session: ValidationRepairSession) => void;
  navigation: { line?: number; query?: string; token: number } | null;
  onBusyChange: (busy: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [startLine, setStartLine] = useState(1);
  const [jumpLine, setJumpLine] = useState('1');
  const [query, setQuery] = useState('');
  const [patch, setPatch] = useState<LineRepairPatch>({
    operation: 'replace_lines',
    start_line: 1,
    end_line: 1,
    replacement_text: '',
  });
  const [message, setMessage] = useState<string | null>(null);
  const pageSize = 500;

  const linesQuery = useQuery({
    queryKey: ['validation-repair-lines', sessionId, startLine, pageSize],
    queryFn: ({ signal }) => getValidationSessionContentLines(sessionId, startLine, pageSize, signal),
  });

  const searchQuery = useQuery({
    queryKey: ['validation-repair-search', sessionId, query],
    queryFn: ({ signal }) => searchValidationSession(sessionId, query, 'repair_draft', 100, signal),
    enabled: query.trim().length > 0,
  });

  const patchMutation = useMutation({
    mutationFn: () => applyValidationSessionLinePatches(sessionId, [patch]),
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      invalidateValidationRepairHistory(queryClient, sessionId);
      invalidateValidationRepairDraftQueries(queryClient, sessionId);
      onSessionUpdate(updated);
      setMessage('Patch saved to repair draft.');
      linesQuery.refetch();
    },
  });

  useEffect(() => { onBusyChange(patchMutation.isPending); return () => onBusyChange(false); }, [patchMutation.isPending, onBusyChange]);
  useEffect(() => {
    if (!navigation) return;
    if (navigation.line) {
      setStartLine(navigation.line);
      setJumpLine(String(navigation.line));
      setPatch(old => ({ ...old, start_line: navigation.line!, end_line: navigation.line! }));
    } else if (navigation.query) setQuery(navigation.query);
  }, [navigation]);

  const goToLine = () => {
    const parsed = Math.max(1, Number.parseInt(jumpLine, 10) || 1);
    setStartLine(parsed);
    setPatch((old) => ({ ...old, start_line: parsed, end_line: parsed }));
  };

  return (
    <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <CardHeader className="shrink-0 border-b border-border !px-3 !py-3">
        <CardTitle>Large File Mode</CardTitle>
        <p className="mt-1 text-xs text-hcl-muted">{formatBytes(session.file_size_bytes ?? session.original_size_bytes)} · {(session.total_lines ?? 0).toLocaleString()} lines · edits use saved line patches</p>
      </CardHeader>
      <CardContent className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto !p-3">
        {message && <Alert variant="info" title="Workspace updated">{message}</Alert>}
        {patchMutation.error && (
          <Alert variant="error" title="Large file action failed">
            {mutationErrorMessage(patchMutation.error, 'The action could not be completed.')}
          </Alert>
        )}
        <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
          <input
            aria-label="Jump to line"
            value={jumpLine}
            onChange={(event) => setJumpLine(event.target.value)}
            className="h-9 rounded-md border border-border bg-surface px-3 text-sm"
          />
          <input
            aria-label="Search repair draft"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search"
            className="h-9 rounded-md border border-border bg-surface px-3 text-sm"
          />
          <Button size="sm" variant="secondary" onClick={goToLine}>Jump</Button>
        </div>
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-border">
          <div className="flex items-center justify-between border-b border-border bg-surface-muted px-3 py-2 text-xs text-hcl-muted">
            <span>Lines {startLine.toLocaleString()}-{(startLine + (linesQuery.data?.lines.length ?? 0) - 1).toLocaleString()}</span>
            <span>{linesQuery.data?.eof ? 'End of file' : 'Page loaded'}</span>
          </div>
          <pre tabIndex={0} aria-label="Large-file repair viewer" className="min-h-[240px] flex-1 overflow-auto bg-surface p-0 text-xs leading-relaxed">
            {(linesQuery.data?.lines ?? []).map((line, idx) => (
              <div key={`${startLine}-${idx}`} data-highlighted-line={navigation?.line === startLine + idx ? startLine + idx : undefined} className={`grid grid-cols-[3rem_minmax(0,1fr)] border-b border-border/40 last:border-b-0 ${navigation?.line === startLine + idx ? 'bg-blue-50 ring-1 ring-inset ring-hcl-blue/30' : ''}`}>
                <span className="select-none bg-surface-muted px-2 py-1 text-right font-mono text-hcl-muted">{startLine + idx}</span>
                <code className="whitespace-pre-wrap break-words px-3 py-1 font-mono text-hcl-navy">{line || ' '}</code>
              </div>
            ))}
          </pre>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" disabled={startLine <= 1 || patchMutation.isPending} onClick={() => setStartLine(Math.max(1, startLine - pageSize))}>Previous</Button>
          <Button size="sm" variant="secondary" disabled={linesQuery.data?.eof || patchMutation.isPending} onClick={() => setStartLine(startLine + pageSize)}>Next</Button>
        </div>
        {searchQuery.data?.matches.length ? (
          <div className="rounded-md border border-border bg-surface-muted p-3">
            <p className="text-xs font-semibold text-hcl-navy">Search results</p>
            <div className="mt-2 max-h-48 space-y-1 overflow-auto text-xs">
              {searchQuery.data.matches.map((match) => (
                <button
                  key={`${match.line_number}-${match.column}`}
                  type="button"
                  className="block w-full rounded px-2 py-1 text-left hover:bg-surface"
                  onClick={() => {
                    setStartLine(match.line_number);
                    setJumpLine(String(match.line_number));
                  }}
                >
                  <span className="font-mono text-hcl-muted">Line {match.line_number}</span> {match.preview}
                </button>
              ))}
            </div>
          </div>
        ) : null}
        <details className="shrink-0 rounded-md border border-border bg-surface-muted p-3">
          <summary className="cursor-pointer text-sm font-semibold text-hcl-navy">Patch selected lines</summary>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <Select
              aria-label="Patch operation"
              disabled={!session.can_edit || patchMutation.isPending}
              value={patch.operation}
              onChange={(event) => setPatch((old) => ({ ...old, operation: event.target.value as LineRepairPatch['operation'] }))}
            >
              <option value="replace_lines">Replace lines</option>
              <option value="insert_before_line">Insert before line</option>
              <option value="delete_lines">Delete lines</option>
            </Select>
            <input
              aria-label="Patch start line"
              disabled={!session.can_edit || patchMutation.isPending}
              value={patch.start_line}
              onChange={(event) => setPatch((old) => ({ ...old, start_line: Number(event.target.value) || 1 }))}
              className="h-9 rounded-md border border-border bg-surface px-3 text-sm"
            />
            <input
              aria-label="Patch end line"
              disabled={!session.can_edit || patchMutation.isPending}
              value={patch.end_line ?? patch.start_line}
              onChange={(event) => setPatch((old) => ({ ...old, end_line: Number(event.target.value) || old.start_line }))}
              className="h-9 rounded-md border border-border bg-surface px-3 text-sm"
            />
          </div>
          {patch.operation !== 'delete_lines' && (
            <Textarea
              aria-label="Patch replacement text"
              disabled={!session.can_edit || patchMutation.isPending}
              value={patch.replacement_text ?? ''}
              onChange={(event) => setPatch((old) => ({ ...old, replacement_text: event.target.value }))}
              className="mt-3 min-h-[140px] font-mono text-xs"
            />
          )}
          <Button className="mt-3" size="sm" onClick={() => patchMutation.mutate()} loading={patchMutation.isPending} disabled={!session.can_edit}>
            <Save className="h-4 w-4" />
            Save patch
          </Button>
        </details>
      </CardContent>
    </Card>
  );
}

