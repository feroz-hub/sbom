import { request, requestVoid, downloadReportArtifact } from './api';
import type { ReportConfig, ReportDelivery, ReportPreferences, ReportPreview, ReportSubscription } from '@/types/reports';

export const getReportConfig = () => request<ReportConfig>('/api/report-notifications/config');
export const getReportTargets = (scope: string, search: string) => request<Array<{ id: number; label: string }>>(`/api/report-notifications/targets?scope=${encodeURIComponent(scope)}&search=${encodeURIComponent(search)}`);
export const getReportSubscriptions = (tenantId?: number) => request<ReportSubscription[]>(tenantId ? `/api/tenants/${tenantId}/report-subscriptions` : '/api/report-subscriptions');
export const getReportDeliveries = (allTenant = false, status = '') => request<ReportDelivery[]>(`/api/report-deliveries?all_tenant=${allTenant}&status=${encodeURIComponent(status)}`);
export const createReportSubscription = (body: ReportPreferences) => request<ReportSubscription>('/api/report-subscriptions', { method: 'POST', body: JSON.stringify(body) });
export const updateReportSubscription = (id: number, body: Partial<ReportPreferences>) => request<ReportSubscription>(`/api/report-subscriptions/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
export const deleteReportSubscription = (id: number) => requestVoid(`/api/report-subscriptions/${id}`, { method: 'DELETE' });
export const previewReport = (body: ReportPreferences) => request<ReportPreview>('/api/report-subscriptions/preview', { method: 'POST', body: JSON.stringify(body) }, 180_000);
export const sendReportNow = (id: number) => request<{ id: number; status: string; message?: string }>(`/api/report-subscriptions/${id}/send-now`, { method: 'POST' });
export { downloadReportArtifact };
