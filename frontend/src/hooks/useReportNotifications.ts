import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createReportSubscription, deleteReportSubscription, getReportConfig, getReportDeliveries, getReportSubscriptions, previewReport, sendReportNow, updateReportSubscription } from '@/lib/reportApi';
import { invalidateReportSurfaces } from '@/lib/queryInvalidation';
import type { ReportPreferences } from '@/types/reports';

export const useReportConfig = () => useQuery({ queryKey: ['reports', 'config'], queryFn: getReportConfig });
export const useReportSubscriptions = (tenantId?: number) => useQuery({ queryKey: ['reports', 'subscriptions', tenantId], queryFn: () => getReportSubscriptions(tenantId) });
export const useReportDeliveries = (allTenant = false, status = '', deliveryId?: number) => useQuery({ queryKey: ['reports', 'deliveries', allTenant, status, deliveryId], queryFn: () => getReportDeliveries(allTenant, status, deliveryId), refetchInterval: 15_000 });
export function useSaveReportSubscription() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: ({ id, body }: { id?: number; body: ReportPreferences }) => id ? updateReportSubscription(id, body) : createReportSubscription(body), onSuccess: () => invalidateReportSurfaces(qc) });
}
export function usePauseReportSubscription() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => updateReportSubscription(id, { enabled }), onSuccess: () => invalidateReportSurfaces(qc) });
}
export function useDeleteReportSubscription() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: deleteReportSubscription, onSuccess: () => invalidateReportSurfaces(qc) });
}
export function useSendReportNow() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: sendReportNow, onSuccess: () => invalidateReportSurfaces(qc) });
}
export function usePreviewReport() {
  // @no-invalidation-needed: synchronous read-only preview; no delivery/subscription is saved.
  return useMutation({ mutationFn: previewReport });
}
