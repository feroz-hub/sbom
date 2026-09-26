'use client';
import { useEffect, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
type Snapshot = { readiness: { ready: boolean; checks: Record<string, boolean> }; delivery: { counts: Record<string, number>; recent: { id: number; purpose: string; status: string; attempts: number; created_at: string }[] } };
export default function IamOperations() {
  const { user, hasPermission } = useAuth();
  const allowed = Boolean(user?.isPlatformAdmin && hasPermission('platform:user:read'));
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!allowed) return;
    let current = true;
    fetch('/api/backend/api/platform/iam/operations', { cache: 'no-store' }).then(async r => {
      if (!r.ok) throw new Error();
      const value = await r.json(); if (current) { setSnapshot(value); setError(false); }
    }).catch(() => { if (current) { setSnapshot(null); setError(true); } });
    return () => { current = false; };
  }, [allowed, revision]);
  if (!allowed) return <p role="alert">Platform administration permission required.</p>;
  return <section className="space-y-6"><header><h1 className="text-2xl font-semibold">Authentication & operational health</h1><p>Security email delivery and dependency readiness. No credentials or delivery recipients are shown.</p></header><button className="rounded border px-4 py-2" onClick={() => setRevision(n => n + 1)}>Refresh health</button>
    {error ? <p role="alert">Health unavailable. Check service connectivity and retry.</p> : !snapshot ? <p role="status">Loading operational health…</p> : <>
      <h2 className="text-xl font-semibold">Session / operational readiness</h2><ul>{Object.entries(snapshot.readiness.checks).map(([name, ready]) => <li key={name} className="border-b py-2">{name.replaceAll('_', ' ')}: <strong>{ready ? 'Ready' : 'Unavailable'}</strong></li>)}</ul>
      <p>The BFF session store has its own readiness probe. Native sessions expire after 15 minutes by default; sign in again when prompted. Logout all immediately revokes native authority across devices.</p>
      <h2 className="text-xl font-semibold">Email / delivery health</h2><div className="grid grid-cols-2 sm:grid-cols-5 gap-3">{Object.entries(snapshot.delivery.counts).map(([status, count]) => <div className="rounded-lg border p-4" key={status}><p>{status}</p><strong className="text-2xl">{count}</strong></div>)}</div>
      <div className="overflow-x-auto"><table className="w-full text-left"><caption>Recent security email events</caption><thead><tr>{['Created', 'Purpose', 'Status', 'Attempts'].map(h => <th className="p-3" key={h}>{h}</th>)}</tr></thead><tbody>{snapshot.delivery.recent.map(row => <tr className="border-t" key={row.id}><td className="p-3">{new Date(row.created_at).toLocaleString()}</td><td>{row.purpose}</td><td>{row.status}</td><td>{row.attempts}</td></tr>)}</tbody></table>{!snapshot.delivery.recent.length && <p>No security email deliveries recorded.</p>}</div>
    </>}
  </section>;
}
