import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(dateStr));
  } catch {
    return dateStr;
  }
}

export function formatDateShort(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(new Date(dateStr));
  } catch {
    return dateStr;
  }
}

/** duration_ms comes from the backend in milliseconds */
export function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const rem = secs % 60;
  return rem > 0 ? `${mins}m ${rem}s` : `${mins}m`;
}

export function truncate(str: string | null | undefined, maxLen = 80): string {
  if (!str) return '—';
  return str.length > maxLen ? `${str.slice(0, maxLen)}…` : str;
}

/**
 * Render the time between an ISO timestamp and now as "in 3d 4h" / "5m ago".
 * Used by the periodic-analysis schedule UI for "Next run" hints.
 */
export function formatRelative(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    const target = new Date(dateStr).getTime();
    const now = Date.now();
    const diffSec = Math.round((target - now) / 1000);
    const sign = diffSec >= 0 ? 'in ' : '';
    const suffix = diffSec >= 0 ? '' : ' ago';
    const abs = Math.abs(diffSec);

    if (abs < 60) return `${sign}<1m${suffix}`;
    const m = Math.floor(abs / 60);
    if (m < 60) return `${sign}${m}m${suffix}`;
    const h = Math.floor(m / 60);
    const remM = m % 60;
    if (h < 24) return `${sign}${h}h${remM ? ` ${remM}m` : ''}${suffix}`;
    const d = Math.floor(h / 24);
    const remH = h % 24;
    return `${sign}${d}d${remH ? ` ${remH}h` : ''}${suffix}`;
  } catch {
    return dateStr;
  }
}

export function severityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'text-red-600';
    case 'HIGH': return 'text-orange-600';
    case 'MEDIUM': return 'text-yellow-600';
    case 'LOW': return 'text-blue-600';
    default: return 'text-gray-500';
  }
}

export function severityBg(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-100 text-red-700 border-red-200';
    case 'HIGH': return 'bg-orange-100 text-orange-700 border-orange-200';
    case 'MEDIUM': return 'bg-yellow-100 text-yellow-700 border-yellow-200';
    case 'LOW': return 'bg-blue-100 text-blue-700 border-blue-200';
    default: return 'bg-gray-100 text-gray-600 border-gray-200';
  }
}

export function statusBg(status: string): string {
  switch (status?.toUpperCase()) {
    case 'PASS': return 'bg-green-100 text-green-700 border-green-200';
    case 'FAIL': return 'bg-red-100 text-red-700 border-red-200';
    case 'PARTIAL': return 'bg-yellow-100 text-yellow-700 border-yellow-200';
    case 'ERROR': return 'bg-red-100 text-red-700 border-red-200';
    case 'RUNNING': return 'bg-blue-100 text-blue-700 border-blue-200';
    case 'PENDING': return 'bg-gray-100 text-gray-600 border-gray-200';
    default: return 'bg-gray-100 text-gray-600 border-gray-200';
  }
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
