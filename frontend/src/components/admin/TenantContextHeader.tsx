'use client';

import { Building2 } from 'lucide-react';
import { MembershipStatusBadge } from './StatusBadges';

interface TenantContextHeaderProps {
  name: string;
  slug: string;
  externalIamTenantId: string;
  status: string;
  memberCount?: number;
}

export function TenantContextHeader({
  name,
  slug,
  externalIamTenantId,
  status,
  memberCount,
}: TenantContextHeaderProps) {
  return (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-elev-1">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-hcl-blue/10 text-hcl-blue">
            <Building2 className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-foreground">{name}</h1>
              <MembershipStatusBadge status={status} />
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-hcl-muted">
              <span>Slug: <code className="font-mono">{slug}</code></span>
              <span>•</span>
              <span>External IAM Tenant ID: <code className="font-mono">{externalIamTenantId}</code></span>
              {typeof memberCount === 'number' && (
                <>
                  <span>•</span>
                  <span>{memberCount} member{memberCount === 1 ? '' : 's'}</span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
