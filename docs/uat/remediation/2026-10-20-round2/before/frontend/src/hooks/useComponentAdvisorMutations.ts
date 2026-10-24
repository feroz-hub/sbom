'use client';

/**
 * Secure Component Advisor mutations (FR-SCA-011/021).
 *
 * Every mutation invalidates the advisor surfaces through
 * ``invalidateComponentAdvisorSurfaces`` so component rows, details and the
 * recommendation view never show a stale status (CLAUDE.md cache rule,
 * enforced by src/__tests__/mutation-invalidation.test.ts).
 *
 * None of these touch a dependency, manifest or SBOM: the backend only
 * changes recommendation state and audit records (spec §1.1).
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  createAdvisorRecommendation,
  decideAdvisorRecommendation,
  evaluateAdvisorRecommendation,
} from '@/lib/api';
import { invalidateComponentAdvisorSurfaces } from '@/lib/queryInvalidation';
import type { AdvisorFilterParams, RecommendationDecision, RecommendationTrigger } from '@/types/componentAdvisor';

export function useCreateRecommendation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (args: {
      canonicalKey: string;
      trigger: RecommendationTrigger;
      scope?: Pick<AdvisorFilterParams, 'project_id' | 'product_id' | 'sbom_id'>;
    }) => createAdvisorRecommendation({ canonical_key: args.canonicalKey, trigger_type: args.trigger }, args.scope),
    onSuccess: (item) => {
      invalidateComponentAdvisorSurfaces(queryClient, item.id);
    },
  });
}

export function useEvaluateRecommendation(recommendationId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => evaluateAdvisorRecommendation(recommendationId),
    onSuccess: () => {
      invalidateComponentAdvisorSurfaces(queryClient, recommendationId);
    },
  });
}

export function useRecommendationDecision(recommendationId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (args: { decision: RecommendationDecision; reason: string; rowVersion: number; candidateId?: number }) =>
      decideAdvisorRecommendation(recommendationId, {
        decision: args.decision,
        reason: args.reason,
        row_version: args.rowVersion,
        ...(args.candidateId ? { candidate_id: args.candidateId } : {}),
      }),
    onSuccess: () => {
      invalidateComponentAdvisorSurfaces(queryClient, recommendationId);
    },
    onError: () => {
      // A 409 means someone else moved the item; refetch so the UI shows the truth.
      invalidateComponentAdvisorSurfaces(queryClient, recommendationId);
    },
  });
}
