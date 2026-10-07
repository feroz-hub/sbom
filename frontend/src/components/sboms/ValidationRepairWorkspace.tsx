'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { Bot, Download, FileInput, RefreshCw, Save, Search, MoreHorizontal, Maximize2, Minimize2, ListChecks, Code2, ArrowRight, Wand2 } from 'lucide-react';
import { SbomAutoRepairPanel } from './SbomAutoRepairPanel';
import { RepairQualitySummary } from './repair/RepairQualitySummary';
import { RepairIssueNavigator } from './repair/RepairIssueNavigator';
import { LargeFileRepairEditor } from './repair/LargeFileRepairEditor';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { PageSpinner } from '@/components/ui/Spinner';
import { Select } from '@/components/ui/Select';
import { applyValidationSessionPatch, downloadValidationSessionOriginal, downloadValidationSessionRepairDraft, getValidationSessionContent, getProject, getProjects, getValidationSession, getValidationSessionHistory, importValidationSession, saveValidationSessionRepairDraft, suggestValidationSessionFixes, updateValidationSession, validateValidationSession, analyzeSbomRepair, getLatestSbomRepair } from '@/lib/api';
import { invalidateDashboardTiles, invalidateProjectSurfaces, invalidateSbomSurfaces } from '@/lib/queryInvalidation';
import { formatDate } from '@/lib/utils';
import { formatSbomFormatLabel } from '@/lib/sbomFormat';
import { presentIssues, locateIssue, locateJsonPath, jsonPathValue, pathTokens, type RepairIssue, type SourceLocation } from '@/lib/repairIssuePresentation';
import type { AiRepairSuggestion } from '@/types';
interface ValidationRepairWorkspaceProps { sessionId: string; }
function formatPatchValue(value: unknown) { if (value == null) return ''; return typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
function mutationErrorMessage(error: unknown, fallback: string) { return error instanceof Error ? error.message : fallback; }
const CONTENT_CHUNK_SIZE = 65_536;
function invalidateValidationRepairHistory(queryClient: QueryClient, sessionId: string) { queryClient.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] }); }
function invalidateValidationRepairDraftQueries(queryClient: QueryClient, sessionId: string) {
  queryClient.invalidateQueries({ queryKey: ['sbom-quality', 'session', sessionId] });
  for (const key of ['sbom-auto-repair-analysis', 'sbom-auto-repair-job', 'validation-repair-content', 'validation-repair-lines', 'validation-repair-search']) queryClient.invalidateQueries({ queryKey: [key, sessionId] });
}
function formatBytes(value: number | null | undefined) {
  if (value == null) return 'Unknown';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function ValidationRepairWorkspace({ sessionId }: ValidationRepairWorkspaceProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [content, setContent] = useState('');
  const [loadedContentSize, setLoadedContentSize] = useState(0);
  const [totalContentSize, setTotalContentSize] = useState(0);
  const [contentEof, setContentEof] = useState(false);
  const [contentSha256, setContentSha256] = useState<string | null>(null);
  const [contentLoaded, setContentLoaded] = useState(false);
  const [suggestion, setSuggestion] = useState<AiRepairSuggestion | null>(null);
  const [selected, setSelected] = useState<Record<number, boolean>>({});
  const [localMessage, setLocalMessage] = useState<string | null>(null);
  const [focusMode, setFocusMode] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [savedContent, setSavedContent] = useState<string | null>(null);
  const [selectedIssueKey, setSelectedIssueKey] = useState<string | null>(null);
  const [workflowStep, setWorkflowStep] = useState<'review' | 'repair' | 'validate'>('review');
  const [issuesHidden, setIssuesHidden] = useState(false);
  const [mobilePane, setMobilePane] = useState<'issues' | 'editor'>('issues');
  const [repairReviewOpen, setRepairReviewOpen] = useState(false);
  const [aiReviewOpen, setAiReviewOpen] = useState(false);
  const [projectSaving, setProjectSaving] = useState(false);
  const [largeBusy, setLargeBusy] = useState(false);
  const [largeNavigation, setLargeNavigation] = useState<{ line?: number; query?: string; token: number } | null>(null);
  const [highlight, setHighlight] = useState<SourceLocation | null>(null);
  const [editorScrollTop, setEditorScrollTop] = useState(0);
  const [navigationMessage, setNavigationMessage] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [editorSearch, setEditorSearch] = useState('');
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const issuePaneRef = useRef<HTMLElement>(null);
  const editorPaneRef = useRef<HTMLElement>(null);
  const actionBarRef = useRef<HTMLDivElement>(null);
  const lastSaveContent = useRef('');
  const paneFocusRequested = useRef(false);
  useEffect(() => {
    if (!paneFocusRequested.current) return;
    paneFocusRequested.current = false;
    if (issuesHidden) editorPaneRef.current?.querySelector<HTMLButtonElement>('[aria-label="Show validation issues"]')?.focus();
    else issuePaneRef.current?.focus();
  }, [issuesHidden, mobilePane]);


  const sessionQuery = useQuery({
    queryKey: ['validation-repair-session', sessionId],
    queryFn: ({ signal }) => getValidationSession(sessionId, signal),
  });

  const repairAnalysis = useQuery({ queryKey: ['sbom-auto-repair-analysis', sessionId], queryFn: ({ signal }) => analyzeSbomRepair(sessionId, signal), retry: false, enabled: Boolean(sessionQuery.data && sessionQuery.data.validation_status !== 'security_blocked') });
  const latestRepair = useQuery({ queryKey: ['sbom-auto-repair-job', sessionId], queryFn: ({ signal }) => getLatestSbomRepair(sessionId, signal), retry: false, enabled: Boolean(sessionQuery.data && sessionQuery.data.validation_status !== 'security_blocked') });


  const initialContentQuery = useQuery({
    queryKey: ['validation-repair-content', sessionId, 0, CONTENT_CHUNK_SIZE],
    queryFn: ({ signal }) => getValidationSessionContent(sessionId, 0, CONTENT_CHUNK_SIZE, signal),
    enabled: sessionQuery.data?.full_editor_allowed !== false,
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
    setProjectSaving(true);
    try {
      const updated = await updateValidationSession(sessionId, { project_id: projectId });
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      queryClient.invalidateQueries({ queryKey: ['project', projectId] });
      setLocalMessage('Project assignment updated.');
    } catch (err: unknown) {
      setLocalMessage(`Failed to update project: ${mutationErrorMessage(err, 'Could not update project')}`);
    } finally { setProjectSaving(false); }
  };

  useEffect(() => {
    const chunk = initialContentQuery.data;
    if (!chunk || contentLoaded) return;
    setContent(chunk.content);
    if (chunk.eof) setSavedContent(chunk.content);
    setLoadedContentSize(chunk.offset + chunk.content.length);
    setTotalContentSize(chunk.total_size);
    setContentEof(chunk.eof);
    setContentSha256(chunk.sha256);
    setContentLoaded(true);
  }, [initialContentQuery.data, contentLoaded]);

  const updateMutation = useMutation({
    mutationFn: () => { lastSaveContent.current = content; return saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at); },
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      invalidateValidationRepairHistory(queryClient, sessionId);
      invalidateValidationRepairDraftQueries(queryClient, sessionId);
      setLoadedContentSize(content.length);
      setTotalContentSize(content.length);
      setContentEof(true);
      setContentSha256(updated.stored_sha256 ?? null);
      setSavedContent(lastSaveContent.current);
      setLocalMessage('Draft saved in the repair workspace.');
    },
  });

  const validateMutation = useMutation({
    mutationFn: async () => {
      if (sessionQuery.data?.full_editor_allowed !== false && hasUnsavedChanges) {
        const saved = await saveValidationSessionRepairDraft(sessionId, content, sessionQuery.data?.updated_at);
        queryClient.setQueryData(['validation-repair-session', sessionId], saved);
        setSavedContent(content);
      }
      return validateValidationSession(sessionId);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(['validation-repair-session', sessionId], updated);
      invalidateValidationRepairHistory(queryClient, sessionId);
      invalidateValidationRepairDraftQueries(queryClient, sessionId);
      setContentSha256(updated.stored_sha256 ?? null);
      if (sessionQuery.data?.full_editor_allowed !== false) setSavedContent(content);
      setWorkflowStep('validate');
      setLocalMessage(
        updated.validation_status === 'passed' || updated.validation_status === 'repaired_valid'
          ? 'Validation passed. Import is now available.'
          : 'Validation completed with remaining issues.',
      );
    },
  });

  // @no-invalidation-needed — appends an already-requested content chunk into local editor state only.
  const loadMoreMutation = useMutation({
    mutationFn: () => getValidationSessionContent(
      sessionId,
      loadedContentSize || content.length || initialContentQuery.data?.content.length || 0,
      CONTENT_CHUNK_SIZE,
    ),
    onSuccess: (chunk) => {
      setContent((old) => old + chunk.content);
      if (chunk.eof) setSavedContent(content + chunk.content);
      setLoadedContentSize(chunk.offset + chunk.content.length);
      setTotalContentSize(chunk.total_size);
      setContentEof(chunk.eof);
      setContentSha256(chunk.sha256);
    },
  });

  // @no-invalidation-needed — downloads the immutable original payload without changing server state.
  const downloadOriginalMutation = useMutation({
    mutationFn: () => downloadValidationSessionOriginal(sessionId),
    onSuccess: ({ blob, filename }) => {
      downloadBlob(blob, filename);
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
      setAiReviewOpen(true);
      const initial: Record<number, boolean> = {};
      result.patches.forEach((_, idx) => {
        initial[idx] = true;
      });
      setSelected(initial);
      invalidateValidationRepairHistory(queryClient, sessionId);
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
      invalidateValidationRepairHistory(queryClient, sessionId);
      invalidateValidationRepairDraftQueries(queryClient, sessionId);
      setContent(updated.current_content);
      setSavedContent(updated.current_content);
      setLoadedContentSize(updated.current_content.length);
      setTotalContentSize(updated.current_content.length);
      setContentEof(true);
      setContentSha256(updated.stored_sha256 ?? null);
      setSuggestion(null);
      setSelected({});
      setLocalMessage(updated.validation_status === 'passed' ? 'Patch applied and validation passed.' : 'Patch applied and validation reran.');
    },
  });

  const session = sessionQuery.data;
  const report = session?.latest_error_report;
  const entries = useMemo(() => report?.entries ?? [], [report?.entries]);
  const issues = useMemo(() => presentIssues(entries, repairAnalysis.data), [entries, repairAnalysis.data]);
  const selectedIssue = issues.find(issue => issue.key === selectedIssueKey) ?? issues.find(issue => issue.entry.severity === 'error') ?? issues[0] ?? null;
  const hardErrorCount = entries.filter((entry) => entry.severity === 'error').length;
  const canImport = (
    session?.validation_status === 'passed' ||
    session?.validation_status === 'valid' ||
    session?.validation_status === 'valid_with_warnings' ||
    session?.validation_status === 'repaired_valid'
  ) && (report?.error_count ?? hardErrorCount) === 0 && hardErrorCount === 0 && session?.project_id != null;
  const hasSelectedPatch = suggestion?.patches.some((_, idx) => selected[idx]) ?? false;
  const isLargeFile = session?.full_editor_allowed === false;
  // Compare text with its loaded/saved baseline; byte counts do not measure edits.
  const hasUnsavedChanges = !isLargeFile && savedContent !== null && content !== savedContent;
  const contentIsPartial = !isLargeFile && !contentEof;
  const metadataMismatch = Boolean(
    session &&
    content.length > 0 &&
    (((session.original_size_bytes ?? session.file_size_bytes ?? 0) === 0) || ((session.total_lines ?? 0) === 0)),
  );

  const parsedDocument = useMemo(() => { try { return JSON.parse(content) as unknown; } catch { return undefined; } }, [content]);
  const lineCount = useMemo(() => content.split('\n').length, [content]);
  const downloadDraftMutation = useMutation({
    mutationFn: () => downloadValidationSessionRepairDraft(sessionId),
    // @no-invalidation-needed — downloads the existing draft without modifying it.
    onSuccess: ({ blob, filename }) => downloadBlob(blob, filename),
  });

  if (sessionQuery.isLoading || (!isLargeFile && initialContentQuery.isLoading)) return <PageSpinner />;
  if (sessionQuery.error || (!isLargeFile && initialContentQuery.error) || !session) return <Alert variant="error" title="Could not load validation session">{mutationErrorMessage(sessionQuery.error || initialContentQuery.error, 'The repair session does not exist or expired.')}</Alert>;
  if (!session.can_edit && session.validation_status === 'security_blocked') return <Alert variant="error" title="Security-blocked payload">{session.security_blocked_reason || 'This payload cannot be opened safely in the repair workspace.'}</Alert>;

  const lastValidation = historyQuery.data?.filter(event => event.event_type === 'validation_run').sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0]?.timestamp;
  const errors = report?.error_count ?? hardErrorCount;
  const warnings = report?.warning_count ?? entries.filter(entry => entry.severity === 'warning').length;
  const validated = ['passed', 'valid', 'valid_with_warnings', 'repaired_valid'].includes(session.validation_status) && errors === 0 && hardErrorCount === 0;
  const busy = updateMutation.isPending || validateMutation.isPending || importMutation.isPending || applyMutation.isPending || projectSaving || largeBusy;
  const importReady = Boolean(canImport && !hasUnsavedChanges && !contentIsPartial && !busy);
  const autoFixable = repairAnalysis.data?.enabled ? repairAnalysis.data.auto_fixable : null;
  const status = session.imported_sbom_id ? 'IMPORTED' : hasUnsavedChanges ? 'DRAFT CHANGED' : validated ? 'PASSED' : errors ? 'FAILED' : session.validation_status.replaceAll('_', ' ').toUpperCase();
  const importHint = session.imported_sbom_id ? 'This repair session has already been imported.' : hasUnsavedChanges ? 'The draft has changed. Revalidate it successfully before importing.' : contentIsPartial ? 'Load the complete draft before revalidating and importing.' : !validated ? 'Resolve all validation errors and revalidate successfully before importing.' : session.project_id == null ? 'Choose a destination project before importing.' : 'Validation passed. This SBOM is ready to import.';
  const selectedValue = selectedIssue ? jsonPathValue(parsedDocument, selectedIssue.entry.json_pointer || selectedIssue.entry.path || '') : { found: false };
  const selectedValueText = selectedValue.found && (selectedValue.value === null || typeof selectedValue.value !== 'object') ? JSON.stringify(selectedValue.value) : undefined;
  const actionError = updateMutation.error || validateMutation.error || suggestMutation.error || applyMutation.error || importMutation.error || downloadOriginalMutation.error || downloadDraftMutation.error;

  function hideIssues() {
    paneFocusRequested.current = true; setIssuesHidden(true); setMobilePane('editor');
  }
  function showIssues() {
    paneFocusRequested.current = true; setIssuesHidden(false); setMobilePane('issues');
  }
  function focusEditor() {
    setMobilePane('editor'); setWorkflowStep('repair');
    requestAnimationFrame(() => { if (isLargeFile) editorPaneRef.current?.querySelector<HTMLElement>('[aria-label="Large-file repair viewer"]')?.focus(); else editorRef.current?.focus(); });
  }
  function canNavigate(issue: RepairIssue) {
    if (isLargeFile) return Boolean(issue.entry.line && issue.entry.line <= (session?.total_lines ?? 0) || pathTokens(issue.entry.json_pointer || issue.entry.path || '')?.length);
    return Boolean((issue.entry.json_pointer || issue.entry.path) && jsonPathValue(parsedDocument, issue.entry.json_pointer || issue.entry.path || '').found || issue.entry.line && issue.entry.line <= lineCount);
  }
  function selectLocation(location: SourceLocation) {
    setHighlight(location); setMobilePane('editor'); setWorkflowStep('repair');
    requestAnimationFrame(() => {
      const editor = editorRef.current;
      if (!editor) return;
      editor.focus(); editor.setSelectionRange(location.start, location.end);
      editor.scrollTop = Math.max(0, (location.line - 1) * 20 - editor.clientHeight / 3);
      setEditorScrollTop(editor.scrollTop);
      if (gutterRef.current) gutterRef.current.scrollTop = editor.scrollTop;
    });
  }
  function goToIssue(issue: RepairIssue) {
    setSelectedIssueKey(issue.key);
    if (isLargeFile) {
      setMobilePane('editor'); setWorkflowStep('repair');
      if (issue.entry.line && issue.entry.line <= (session?.total_lines ?? 0)) {
        setLargeNavigation({ line: issue.entry.line, token: Date.now() });
        setNavigationMessage(`Validator-reported line ${issue.entry.line} · ${issue.location}`);
      } else {
        const tokens = pathTokens(issue.entry.json_pointer || issue.entry.path || '');
        const token = tokens?.filter(part => !/^\d+$/.test(part)).at(-1);
        if (!token) { setNavigationMessage(`Location unavailable. Copy path: ${issue.location}`); return; }
        setLargeNavigation({ query: JSON.stringify(token), token: Date.now() });
        setNavigationMessage(`Searching for ${token}. Choose a result and check its full path: ${issue.location}`);
      }
      return;
    }
    const location = locateIssue(content, issue.entry);
    if (!location) { setNavigationMessage(`Location unavailable. Copy path: ${issue.location}`); return; }
    selectLocation(location);
    const exact = Boolean(issue.entry.json_pointer || issue.entry.path) && jsonPathValue(parsedDocument, issue.entry.json_pointer || issue.entry.path || '').found;
    setNavigationMessage(`${exact ? 'Draft' : 'Validator-reported'} line ${location.line} · ${issue.location}`);
  }
  function findInEditor() {
    if (!editorSearch) return;
    const from = editorRef.current?.selectionEnd ?? 0;
    const match = content.indexOf(editorSearch, from);
    const start = match < 0 ? content.indexOf(editorSearch) : match;
    if (start < 0) { setNavigationMessage('No matches in the loaded draft.'); return; }
    const location = { start, end: start + editorSearch.length, line: content.slice(0, start).split('\n').length };
    selectLocation(location); setNavigationMessage(`Search match at draft line ${location.line}`);
  }
  function revalidate() { if (!busy && !contentIsPartial) validateMutation.mutate(); }
  function downloadReport() { if (report) downloadBlob(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }), `${sessionId}.validation-report.json`); }
  const actionButtons = (header = false) => <>
    <Button size="sm" variant={importReady ? 'secondary' : 'primary'} aria-label={header ? 'Revalidate SBOM from header' : 'Revalidate'} disabled={busy || contentIsPartial} loading={validateMutation.isPending} loadingLabel="Revalidating" onClick={revalidate}><RefreshCw className="h-4 w-4" />{validateMutation.isPending ? 'Revalidating…' : 'Revalidate'}</Button>
    <span title={importHint}><Button size="sm" aria-label={header ? 'Import SBOM from header' : 'Import SBOM'} aria-describedby="import-readiness" variant={importReady ? 'primary' : 'secondary'} disabled={!importReady} loading={importMutation.isPending} onClick={() => { if (importReady) importMutation.mutate(); }}><FileInput className="h-4 w-4" />Import SBOM</Button></span>
  </>;

  return <div role={focusMode ? 'dialog' : undefined} aria-modal={focusMode || undefined} aria-label={focusMode ? 'Repair workspace focus mode' : undefined} className={focusMode ? 'fixed inset-2 z-40 flex min-h-0 flex-col gap-3 overflow-auto rounded-xl border border-border bg-background p-3 shadow-xl md:inset-4' : 'flex min-h-[700px] min-w-0 flex-col gap-3'} onKeyDown={event => {
    if (focusMode && event.key === 'Tab' && !repairReviewOpen && !aiReviewOpen) {
      const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, a[href]')).filter(item => item.getClientRects().length > 0);
      const first = items[0], last = items[items.length - 1];
      if (event.shiftKey && event.target === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && event.target === last) { event.preventDefault(); first?.focus(); }
    }
    if (event.key === 'Escape' && focusMode && !repairReviewOpen && !aiReviewOpen) { setFocusMode(false); return; }
    if (!event.altKey || !['ArrowDown', 'ArrowUp'].includes(event.key) || !issues.length) return;
    // The issue navigator handles its filtered list; this shortcut also works in the editor.
    if (issuePaneRef.current?.contains(event.target as Node)) return;
    event.preventDefault(); const current = issues.findIndex(issue => issue.key === selectedIssue?.key); const next = issues[current + (event.key === 'ArrowDown' ? 1 : -1)]; if (next) { setSelectedIssueKey(next.key); if (canNavigate(next)) goToIssue(next); }
  }}>
    <header className="shrink-0 rounded-xl border border-border bg-surface px-4 py-3">
      <div className="flex min-w-0 flex-col items-start justify-between gap-3 sm:flex-row sm:flex-wrap">
        <div className="w-full min-w-0 flex-1 sm:w-auto"><h1 className="text-lg font-semibold tracking-tight text-hcl-navy">Repair Workspace</h1><p title={session.sbom_name || session.original_filename || ''} className="mt-0.5 truncate text-sm font-medium text-foreground">{session.sbom_name || session.original_filename || 'SBOM document'}</p><p className="mt-0.5 text-xs text-hcl-muted">{formatSbomFormatLabel(session.detected_format)}{session.detected_version ? ` · ${session.detected_version}` : ''}</p></div>
        <div className="flex shrink-0 flex-wrap gap-2" role="group" aria-label="Header workflow actions">{actionButtons(true)}{focusMode && <Button size="sm" variant="ghost" onClick={() => setFocusMode(false)}><Minimize2 className="h-4 w-4" />Exit focus mode</Button>}</div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs"><Badge variant={validated && !hasUnsavedChanges ? 'success' : errors ? 'error' : 'warning'}>{status}</Badge><span className={errors ? 'font-semibold text-red-700' : 'text-hcl-muted'}>{errors} errors</span><span className="text-hcl-muted">{warnings} warnings</span>{autoFixable !== null && <span className="text-hcl-muted">{autoFixable} auto-fixable</span>}<span className="text-hcl-muted">{validated && !hasUnsavedChanges ? 'Validation passed. Prepare this SBOM for import.' : 'This SBOM must pass validation before it can be imported.'}</span></div>
    </header>
    <nav aria-label="Repair workflow" className="flex shrink-0 items-center gap-1 text-xs sm:gap-2">{([
      ['review', '1', 'Review issues'], ['repair', '2', 'Repair SBOM'], ['validate', '3', 'Revalidate & import'],
    ] as const).map(([step, number, label], index) => <div key={step} className="flex min-w-0 flex-1 items-center gap-1 sm:gap-2"><button aria-current={workflowStep === step ? 'step' : undefined} className={`flex min-w-0 flex-1 items-center gap-2 rounded-lg px-2 py-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50 ${workflowStep === step ? 'bg-hcl-blue/10 font-semibold text-hcl-blue' : 'text-hcl-muted hover:bg-surface-muted'}`} onClick={() => { setWorkflowStep(step); if (step === 'repair') focusEditor(); else if (step === 'review') { showIssues(); } else actionBarRef.current?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus(); }}><span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] ${workflowStep === step ? 'bg-hcl-blue text-white' : 'border border-border bg-surface'}`}>{number}</span><span className="leading-tight">{label}</span></button>{index < 2 && <ArrowRight className="h-3.5 w-3.5 shrink-0 text-hcl-muted" aria-hidden />}</div>)}</nav>
    {!focusMode && <RepairQualitySummary sessionId={sessionId} />}
    {localMessage && <p role="status" className={`shrink-0 rounded-lg px-3 py-2 text-xs ${validated ? 'bg-emerald-50 text-emerald-900' : 'bg-blue-50 text-hcl-blue'}`}>{localMessage}</p>}
    {actionError && <Alert variant="error" title="Repair action failed">{mutationErrorMessage(actionError, 'The repair action could not be completed.')}</Alert>}
    <div role="tablist" onKeyDown={event => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) { event.preventDefault(); const pane = event.key === 'Home' ? 'issues' : event.key === 'End' ? 'editor' : mobilePane === 'issues' ? 'editor' : 'issues'; setMobilePane(pane); if (pane === 'issues') setIssuesHidden(false); document.getElementById(`repair-${pane}-tab`)?.focus(); } }} aria-label="Workspace panes" className="flex shrink-0 gap-2 md:hidden"><button id="repair-issues-tab" role="tab" tabIndex={mobilePane === 'issues' ? 0 : -1} aria-selected={mobilePane === 'issues'} aria-controls="repair-issues-pane" onClick={showIssues} className={`rounded-lg border px-3 py-2 text-xs ${mobilePane === 'issues' ? 'border-hcl-blue bg-blue-50 text-hcl-blue' : 'border-border bg-surface'}`}><ListChecks className="mr-1 inline h-3.5 w-3.5" />Issues ({issues.length})</button><button id="repair-editor-tab" role="tab" tabIndex={mobilePane === 'editor' ? 0 : -1} aria-selected={mobilePane === 'editor'} aria-controls="repair-editor-pane" onClick={() => setMobilePane('editor')} className={`rounded-lg border px-3 py-2 text-xs ${mobilePane === 'editor' ? 'border-hcl-blue bg-blue-50 text-hcl-blue' : 'border-border bg-surface'}`}><Code2 className="mr-1 inline h-3.5 w-3.5" />Editor</button></div>
    <div data-issues-hidden={issuesHidden} className={`grid min-w-0 gap-3 ${focusMode ? 'min-h-0 flex-1' : 'h-[min(60dvh,640px)] min-h-[440px] shrink-0'} ${issuesHidden ? 'grid-cols-1' : 'md:grid-cols-[minmax(240px,0.38fr)_minmax(0,0.62fr)] lg:grid-cols-[minmax(260px,0.32fr)_minmax(0,0.68fr)]'}`}>
      <aside id="repair-issues-pane" ref={issuePaneRef} tabIndex={-1} className={`min-h-0 min-w-0 ${issuesHidden ? 'hidden' : mobilePane === 'issues' ? 'block md:block' : 'hidden md:block'}`}>
        <RepairIssueNavigator onHide={hideIssues} importReady={importReady} importHint={importHint} onViewReport={downloadReport} issues={issues} selectedKey={selectedIssue?.key ?? null} onSelect={issue => setSelectedIssueKey(issue.key)} onNavigate={goToIssue} canNavigate={canNavigate} passed={validated} errorCount={errors} warningCount={warnings} truncated={report?.truncated} lastValidated={lastValidation ? formatDate(lastValidation) : null} busy={busy || hasUnsavedChanges} onSafeRepair={() => setRepairReviewOpen(true)} currentValue={selectedValueText} />
      </aside>
      <section id="repair-editor-pane" ref={editorPaneRef} aria-label="Repair Editor" className={`flex min-h-0 min-w-0 flex-col rounded-xl border border-border bg-surface ${mobilePane === 'editor' ? '' : 'hidden'} md:flex`}>
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-border px-3 py-3">
          <div className="min-w-0"><h2 className="text-sm font-semibold text-hcl-navy">Repair Editor</h2>{issuesHidden && <Button size="sm" variant="secondary" aria-label="Show validation issues" aria-controls="repair-issues-pane" aria-expanded={false} onClick={showIssues}><ListChecks className="h-3.5 w-3.5" />Issues {issues.length}{errors > 0 ? ` · ${errors} errors` : warnings > 0 ? ` · ${warnings} ${warnings === 1 ? 'warning' : 'warnings'}` : ''}</Button>}<p className="mt-1 truncate text-[11px] text-hcl-muted">{formatSbomFormatLabel(session.detected_format)} · {session.detected_version || 'Version not detected'}</p><p className={`mt-1 text-[11px] ${hasUnsavedChanges ? 'text-amber-800' : 'text-hcl-muted'}`}>{updateMutation.isPending ? 'Saving…' : hasUnsavedChanges ? 'Unsaved changes' : isLargeFile ? 'Line patches save to the draft' : contentIsPartial ? 'Draft preview' : 'Draft saved ✓'}</p></div>
          <details className="relative shrink-0"><summary aria-label="Editor utilities" className="flex h-8 w-8 cursor-pointer list-none items-center justify-center rounded-lg border border-border text-hcl-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50"><MoreHorizontal className="h-4 w-4" /></summary><div className="absolute right-0 top-10 z-20 w-56 space-y-1 rounded-lg border border-border bg-surface p-2 shadow-lg"><Button className="w-full justify-start" size="sm" variant="ghost" onClick={() => downloadOriginalMutation.mutate()} loading={downloadOriginalMutation.isPending}><Download className="h-3.5 w-3.5" />Download original</Button><Button className="w-full justify-start" size="sm" variant="ghost" onClick={() => downloadDraftMutation.mutate()} loading={downloadDraftMutation.isPending}>Download repair draft</Button><Button className="w-full justify-start" size="sm" variant="ghost" disabled={!report} onClick={downloadReport}>Download validation report</Button><Button className="w-full justify-start" size="sm" variant="ghost" onClick={() => setFocusMode(!focusMode)}><Maximize2 className="h-3.5 w-3.5" />{focusMode ? 'Exit focus mode' : 'Focus mode'}</Button>{session.can_ai_fix && !isLargeFile && <Button className="w-full justify-start" size="sm" variant="ghost" disabled={busy || hasUnsavedChanges || !entries.length || selectedIssue?.classification === 'MANUAL_ONLY'} loading={suggestMutation.isPending} onClick={() => suggestMutation.mutate()}><Wand2 className="h-3.5 w-3.5" />AI fix suggestions</Button>}</div></details>
        </div>
        {isLargeFile ? <LargeFileRepairEditor session={session} sessionId={sessionId} navigation={largeNavigation} onBusyChange={setLargeBusy} onSessionUpdate={updated => { queryClient.setQueryData(['validation-repair-session', sessionId], updated); invalidateValidationRepairHistory(queryClient, sessionId); }} /> : <>
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-xs"><Button size="sm" variant="ghost" onClick={() => setSearchOpen(!searchOpen)}><Search className="h-3.5 w-3.5" />Search</Button>{contentIsPartial && <><span className="text-amber-800">Preview loaded · {formatBytes(loadedContentSize)} of {formatBytes(totalContentSize)}</span><Button size="sm" variant="secondary" onClick={() => loadMoreMutation.mutate()} loading={loadMoreMutation.isPending} disabled={busy}>Load more</Button></>}{highlight && <span className="text-hcl-blue">Line {highlight.line} selected</span>}</div>
          {searchOpen && <form className="flex shrink-0 gap-2 border-b border-border p-2" onSubmit={event => { event.preventDefault(); findInEditor(); }}><input aria-label="Find in repair draft" placeholder="Find text…" value={editorSearch} onChange={event => setEditorSearch(event.target.value)} className="h-8 min-w-0 flex-1 rounded-md border border-border bg-surface px-2 text-xs" /><Button type="submit" size="sm" variant="secondary" disabled={!editorSearch}>Find next</Button></form>}
          <div className="flex min-h-[260px] min-w-0 flex-1 overflow-hidden bg-surface md:min-h-0">
            <div ref={gutterRef} aria-hidden="true" className="w-12 shrink-0 overflow-hidden border-r border-border bg-surface-muted py-3 text-right font-mono text-xs leading-5 text-hcl-muted">{Array.from({ length: lineCount }, (_, i) => <div key={i} className={`px-2 ${highlight?.line === i + 1 ? 'bg-blue-100 text-hcl-blue' : ''}`}>{i + 1}</div>)}</div>
            <div className="relative min-h-0 min-w-0 flex-1 overflow-hidden">{highlight && <div aria-hidden="true" data-highlighted-line={highlight.line} className="pointer-events-none absolute left-0 right-0 bg-blue-50 ring-1 ring-inset ring-hcl-blue/10" style={{ top: (highlight.line - 1) * 20 + 12 - editorScrollTop, height: 20 }} />}
              <textarea ref={editorRef} aria-label="SBOM repair editor" aria-describedby="repair-editor-context" value={content} wrap="off" spellCheck={false} onScroll={event => { setEditorScrollTop(event.currentTarget.scrollTop); if (gutterRef.current) gutterRef.current.scrollTop = event.currentTarget.scrollTop; }} onChange={event => { setContent(event.target.value); setWorkflowStep('repair'); setHighlight(selectedIssue && (selectedIssue.entry.json_pointer || selectedIssue.entry.path) ? locateJsonPath(event.target.value, selectedIssue.entry.json_pointer || selectedIssue.entry.path || '') : null); }} style={{ lineHeight: '20px' }} className="relative z-10 h-full min-h-0 w-full flex-1 resize-none overflow-auto bg-transparent px-3 py-3 font-mono text-xs text-foreground outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary/30 disabled:cursor-not-allowed" disabled={!session.can_edit || contentIsPartial || busy} />
            </div>
          </div>
          <p id="repair-editor-context" className="shrink-0 truncate border-t border-border px-3 py-2 text-[11px] text-hcl-muted" title={selectedIssue?.location}>{contentIsPartial ? 'Editing is disabled until the loaded draft is complete.' : selectedIssue ? `Selected issue: ${selectedIssue.title} · ${selectedIssue.location}` : 'Review this draft before importing.'}</p>
        </>}
        {navigationMessage && <p role="status" className="shrink-0 break-words border-t border-border px-3 py-2 text-xs text-hcl-blue">{navigationMessage}</p>}
      </section>
    </div>
    <div ref={actionBarRef} id="repair-actions" role="region" aria-label="Repair workflow actions" className="sticky bottom-0 z-10 flex shrink-0 flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface px-3 py-3 shadow-sm">
      <div className="min-w-0 flex-1"><p className="text-xs font-semibold text-hcl-navy">{hasUnsavedChanges ? 'Unsaved changes' : validated ? 'Validation passed' : `${errors} ${errors === 1 ? 'error' : 'errors'} remaining`}</p><p id="import-readiness" className="mt-1 text-[11px] text-hcl-muted">{importHint}</p>{session.imported_sbom_id && <Link className="text-xs text-hcl-blue underline" href={`/sboms/${session.imported_sbom_id}`}>View imported SBOM</Link>}</div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">{!isLargeFile && <Button size="sm" variant="secondary" onClick={() => updateMutation.mutate()} loading={updateMutation.isPending} disabled={!session.can_edit || !hasUnsavedChanges || contentIsPartial || busy}><Save className="h-4 w-4" />Save draft</Button>}{actionButtons()}</div>
    </div>
    {!focusMode && <>
      <details className="shrink-0 rounded-lg border border-border bg-surface px-3 py-2"><summary className="cursor-pointer text-xs font-semibold text-hcl-navy">SBOM Information</summary><dl className="mt-3 grid min-w-0 gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4"><div className="min-w-0"><dt className="text-hcl-muted">Original filename</dt><dd className="mt-1 break-words" title={session.original_filename || ''}>{session.original_filename || session.sbom_name || 'Unknown'}</dd></div><div><dt className="text-hcl-muted">Detected format</dt><dd className="mt-1">{formatSbomFormatLabel(session.detected_format)} {session.detected_version}</dd></div><div><dt className="text-hcl-muted">Original size</dt><dd className="mt-1">{formatBytes(session.file_size_bytes ?? session.original_size_bytes)}</dd></div><div><dt className="text-hcl-muted">Total lines</dt><dd className="mt-1">{(session.total_lines ?? 0).toLocaleString()}</dd></div><div className="sm:col-span-2"><dt className="text-hcl-muted">Session ID</dt><dd className="mt-1 break-all font-mono">{session.id}</dd></div><div className="sm:col-span-2"><dt className="text-hcl-muted">SHA-256</dt><dd className="mt-1 break-all font-mono">{session.sha256 || session.original_sha256 || 'Unknown'}</dd></div>{contentSha256 && <div className="sm:col-span-2"><dt className="text-hcl-muted">Draft SHA-256</dt><dd className="mt-1 break-all font-mono">{contentSha256}</dd></div>}</dl>{metadataMismatch && <p className="mt-2 text-xs text-amber-800">Metadata mismatch: the workspace reports 0 B or 0 lines while content is loaded.</p>}</details>
      <div className="flex shrink-0 flex-wrap items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2"><label htmlFor="repair-project" className="text-xs font-semibold text-hcl-navy">Destination project</label><Select id="repair-project" aria-label="Assign Project" value={session.project_id || ''} onChange={event => { void handleProjectChange(event.target.value ? Number(event.target.value) : null); }} disabled={!session.can_edit || busy} placeholder="Select a project…" className="h-8 min-w-0 max-w-xs py-0 text-xs">{projectsQuery.data?.map(project => <option key={project.id} value={project.id}>{project.project_name}</option>)}</Select><span className="text-[11px] text-hcl-muted">{projectSaving ? 'Saving project…' : session.project_id ? projectQuery.data?.project_name || 'Required before import' : 'Choose where the validated SBOM will be imported.'}</span>{(autoFixable ?? 0) > 0 || latestRepair.data ? <Button size="sm" variant="ghost" disabled={busy || hasUnsavedChanges || contentIsPartial} onClick={() => setRepairReviewOpen(true)}>Review automatic repairs{autoFixable ? ` (${autoFixable})` : ''}</Button> : null}</div>
    </>}
    <Dialog open={repairReviewOpen} onClose={() => setRepairReviewOpen(false)} title="Review Automatic Repairs" maxWidth="2xl"><DialogBody><p className="mb-3 text-sm text-hcl-muted">Review the retained candidate and its changes. Accept Repairs imports the candidate using the existing approval workflow.</p>{(hasUnsavedChanges || busy) && <p className="mb-3 text-sm text-amber-800">Save and revalidate your draft before reviewing repairs.</p>}<SbomAutoRepairPanel sessionId={sessionId} disabled={busy || hasUnsavedChanges || contentIsPartial} onApproved={() => { setRepairReviewOpen(false); void initialContentQuery.refetch().then(() => setContentLoaded(false)); }} /></DialogBody></Dialog>
    <Dialog open={aiReviewOpen} onClose={() => setAiReviewOpen(false)} title="AI Repair Suggestions" maxWidth="2xl"><DialogBody>
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
              disabled={!hasSelectedPatch || busy || hasUnsavedChanges}
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

    </DialogBody></Dialog>
      {!focusMode && (
        <details className="shrink-0 rounded-lg border border-border bg-white px-4 py-2" open={historyOpen} onToggle={(event) => setHistoryOpen(event.currentTarget.open)}>
          <summary className="cursor-pointer text-sm font-semibold text-hcl-navy">Repair History</summary>
          <div className="mt-3 max-h-56 overflow-auto">
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
          </div>
        </details>
      )}
  </div>;
}
