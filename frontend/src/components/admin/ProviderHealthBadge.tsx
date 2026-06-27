'use client';

import { Badge } from '@/components/ui/Badge';

export function ProviderHealthBadge({ status }: { status: string }) {
  const normalized = status || 'unknown';
  if (normalized === 'healthy') return <Badge variant="success">Healthy</Badge>;
  if (normalized === 'degraded') return <Badge variant="warning">Degraded</Badge>;
  if (normalized === 'disabled') return <Badge variant="gray">Disabled</Badge>;
  return <Badge variant="info">Unknown</Badge>;
}
