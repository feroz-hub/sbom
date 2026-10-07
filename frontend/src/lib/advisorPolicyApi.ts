import { request } from './api';

export type AdvisorPolicyKind = 'accepted-risk' | 'trust' | 'scoring';
export type AdvisorPolicyStatus = 'ACTIVE' | 'DISABLED' | 'INHERIT';
export interface AdvisorPolicyVersion {
  id: number; version: number; status: AdvisorPolicyStatus; scope: string;
  rules: Record<string, unknown>; created_at: string | null; reason?: string; created_by?: string;
}
export interface AdvisorPolicyState {
  configured: boolean; row_version: number;
  effective: AdvisorPolicyVersion | null;
  tenant_override: AdvisorPolicyVersion | null;
  platform_default: AdvisorPolicyVersion | null;
}
const base = (tenantId: number | null) => tenantId === null ? '/api/platform/configuration/advisor-policies' : '/api/component-advisor/policies';
const options = (tenantId: number | null) => ({ ...(tenantId !== null ? { headers: { 'X-Tenant-ID': String(tenantId) } } : {}), authErrorMode: 'throw' as const });
export const getAdvisorPolicy = (tenantId: number | null, kind: AdvisorPolicyKind) => request<AdvisorPolicyState>(`${base(tenantId)}/${kind}`, options(tenantId));
export const getAdvisorPolicyHistory = (tenantId: number | null, kind: AdvisorPolicyKind) => request<{ items: AdvisorPolicyVersion[] }>(`${base(tenantId)}/${kind}/versions`, options(tenantId));
export const publishAdvisorPolicy = (tenantId: number | null, kind: AdvisorPolicyKind, body: { status: AdvisorPolicyStatus; rules: Record<string, unknown> | null; reason: string; row_version: number }) => request<AdvisorPolicyState>(`${base(tenantId)}/${kind}/versions`, { ...options(tenantId), method: 'POST', body: JSON.stringify(body) });
