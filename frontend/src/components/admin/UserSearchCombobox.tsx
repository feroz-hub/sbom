'use client';

import { useState, useEffect, useRef } from 'react';
import { Search, UserCheck, ChevronDown, ChevronUp, Loader2 } from 'lucide-react';
import { type UserSearchResult, searchPlatformUsers, searchTenantUserCandidates } from '@/lib/api';
import { VerificationBadge, UserStatusBadge } from './StatusBadges';
import { getRoleLabel } from '@/lib/roles';

interface UserSearchComboboxProps {
  tenantId?: number;
  onSelect: (user: UserSearchResult | null) => void;
  selectedUser: UserSearchResult | null;
  placeholder?: string;
  requireEligible?: boolean;
}

export function isEligibleAdministrator(user: UserSearchResult): boolean {
  return (
    user.status === 'ACTIVE'
    && user.email_verified
    && !user.verification_required
  );
}

export function UserSearchCombobox({
  tenantId,
  onSelect,
  selectedUser,
  placeholder = 'Search existing SBOM users by email or name…',
  requireEligible = false,
}: UserSearchComboboxProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<UserSearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [showTechDetails, setShowTechDetails] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [open]);

  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      setLoading(false);
      setSearchError(null);
      setOpen(false);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      setSearchError(null);
      try {
        const data = tenantId
          ? await searchTenantUserCandidates(tenantId, query)
          : await searchPlatformUsers(query);
        setResults(data);
        setOpen(true);
      } catch {
        setResults([]);
        setSearchError('User search could not be completed. Try again.');
        setOpen(true);
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query, tenantId]);

  if (selectedUser) {
    return (
      <div className="rounded-lg border border-hcl-blue/30 bg-hcl-blue/5 p-4 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-hcl-blue text-white font-bold text-sm">
              {(selectedUser.display_name || selectedUser.email || 'U')[0]?.toUpperCase()}
            </div>
            <div>
              <p className="font-semibold text-foreground text-sm">
                {selectedUser.display_name || 'No display name'}
              </p>
              <p className="text-xs text-hcl-muted">{selectedUser.email || 'No email'}</p>
              {selectedUser.username && (
                <p className="text-xs text-hcl-muted">@{selectedUser.username}</p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="text-xs text-hcl-muted hover:text-foreground hover:underline"
          >
            Change Selection
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-border/50">
          <UserStatusBadge status={selectedUser.status} />
          <VerificationBadge verified={selectedUser.email_verified} />
          {selectedUser.verification_required && (
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
              Verification required
            </span>
          )}
          {selectedUser.is_platform_admin && (
            <span className="rounded-full bg-hcl-blue/10 px-2 py-0.5 text-xs font-bold text-hcl-blue">
              Platform Admin
            </span>
          )}
          {selectedUser.tenant_membership && (
            <span className="text-xs text-hcl-muted">
              Current Tenant Role: <strong className="text-foreground">{getRoleLabel(selectedUser.tenant_membership.role)}</strong>
            </span>
          )}
          {(selectedUser.tenant_memberships ?? []).map((membership) => (
            <span key={membership.tenant_id} className="text-xs text-hcl-muted">
              {membership.tenant_name || `Tenant #${membership.tenant_id}`}: {' '}
              <strong className="text-foreground">
                {(membership.roles?.length ? membership.roles : [membership.role])
                  .map(getRoleLabel)
                  .join(', ')}
              </strong>
              {' '}({membership.status})
            </span>
          ))}
        </div>

        {selectedUser.external_subject && (
          <div>
            <button
              type="button"
              onClick={() => setShowTechDetails(!showTechDetails)}
              className="flex items-center gap-1 text-[11px] text-hcl-muted hover:underline mt-1"
            >
              {showTechDetails ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {showTechDetails ? 'Hide technical details' : 'Show technical details'}
            </button>
            {showTechDetails && (
              <div className="mt-2 rounded bg-background p-2 text-xs font-mono text-hcl-muted border border-border">
                <p>User ID: {selectedUser.id}</p>
                <p>HCL.CS Subject: {selectedUser.external_subject}</p>
                {selectedUser.external_issuer && <p>Issuer: {selectedUser.external_issuer}</p>}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative w-full">
      <div className="relative">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-hcl-muted" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => {
            if (results.length > 0) setOpen(true);
          }}
          placeholder={placeholder}
          className="w-full rounded-lg border border-border bg-background pl-9 pr-9 py-2 text-sm text-foreground focus:border-hcl-blue focus:outline-none"
        />
        {loading && (
          <>
            <Loader2 className="absolute right-3 top-2.5 h-4 w-4 animate-spin text-hcl-muted" />
            <span role="status" className="sr-only">User search loading…</span>
          </>
        )}
      </div>

      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 z-50 max-h-64 overflow-y-auto rounded-xl border border-border bg-surface shadow-elev-3 p-1">
          {results.length === 0 && !loading && (
            <div className="p-4 text-center text-xs text-hcl-muted">
              {searchError
                ? <span role="alert" className="text-red-700">{searchError}</span>
                : 'No matching existing SBOM users found. Users must sign in to SBOM Analyser at least once to be discoverable.'}
            </div>
          )}
          {results.map((user) => {
            const disabled = (
              (requireEligible && !isEligibleAdministrator(user))
              || Boolean(tenantId && user.tenant_membership)
            );
            return (
            <button
              key={user.id}
              type="button"
              disabled={disabled}
              aria-disabled={disabled}
              onClick={() => {
                if (disabled) return;
                onSelect(user);
                setOpen(false);
                setQuery('');
              }}
              className="flex w-full items-start justify-between rounded-lg p-2.5 text-left text-sm hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50 transition-colors border-b border-border/30 last:border-0"
            >
              <div className="min-w-0 flex-1">
                <p className="font-semibold text-foreground truncate">
                  {user.display_name || user.email || 'No name'}
                </p>
                <p className="text-xs text-hcl-muted truncate">{user.email || 'No email'}</p>
                {user.username && <p className="text-xs text-hcl-muted truncate">@{user.username}</p>}
                <div className="flex flex-wrap items-center gap-1.5 mt-1">
                  <UserStatusBadge status={user.status} />
                  <VerificationBadge verified={user.email_verified} />
                  {user.verification_required && (
                    <span className="text-[11px] font-medium text-amber-700">Verification required</span>
                  )}
                  {user.is_platform_admin && (
                    <span className="text-[11px] font-medium text-hcl-blue">Platform Admin</span>
                  )}
                  {user.tenant_membership && (
                    <span className="text-[11px] text-hcl-muted">
                      Member ({getRoleLabel(user.tenant_membership.role)})
                    </span>
                  )}
                  {(user.tenant_memberships ?? []).length > 0 && (
                    <span className="text-[11px] text-hcl-muted">
                      {(user.tenant_memberships ?? []).length} existing tenant membership
                      {(user.tenant_memberships ?? []).length === 1 ? '' : 's'}
                    </span>
                  )}
                </div>
              </div>
              <UserCheck className="h-4 w-4 text-hcl-blue shrink-0 mt-1 ml-2" />
            </button>
          )})}
        </div>
      )}
    </div>
  );
}
