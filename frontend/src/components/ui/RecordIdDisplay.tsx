'use client';

import { useEffect } from 'react';
import { recordIdLabel } from '@/lib/recordDisplay';

export { recordIdLabel } from '@/lib/recordDisplay';

const warned = new Set<string>();

export function RecordIdDisplay({ kind = '', displayId }: { kind?: string; displayId?: number | null }) {
  const available = typeof displayId === 'number' && Number.isSafeInteger(displayId) && displayId > 0;
  useEffect(() => {
    if (process.env.NODE_ENV === 'development' && !available && !warned.has(kind)) {
      warned.add(kind);
      // No record values, identities, user data or tokens in diagnostics.
      console.warn('Record display field unavailable; verify the API presentation contract.', kind || 'Record');
    }
  }, [available, kind]);
  return <span className="whitespace-nowrap tabular-nums" data-record-id-state={available ? 'available' : 'unavailable'} aria-label={available ? `${kind || 'Record'} ID ${displayId}` : `${kind || 'Record'} ID unavailable`}>
    {recordIdLabel(kind, displayId)}
  </span>;
}
