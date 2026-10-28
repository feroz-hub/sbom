'use client';

import { useCallback } from 'react';
import { useToast } from './useToast';
import { actionSuccessMessage, getApiErrorMessage } from '@/lib/notifications';

export function useNotifications() {
  const { showToast, updateToast, dismiss } = useToast();

  const showSuccess = useCallback(
    (message: string) => showToast(message, 'success'),
    [showToast],
  );
  const showError = useCallback(
    (message: string) => showToast(message, 'error'),
    [showToast],
  );
  const showWarning = useCallback(
    (message: string) => showToast(message, 'warning'),
    [showToast],
  );
  const showInfo = useCallback(
    (message: string) => showToast(message, 'info'),
    [showToast],
  );
  const showActionSuccess = useCallback(
    (action: string, subject?: string) => showSuccess(actionSuccessMessage(action, subject)),
    [showSuccess],
  );
  const showApiError = useCallback(
    (error: unknown, fallbackMessage: string) => showError(getApiErrorMessage(error, fallbackMessage)),
    [showError],
  );

  return {
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showActionSuccess,
    showApiError,
    showToast,
    updateToast,
    dismiss,
  };
}
