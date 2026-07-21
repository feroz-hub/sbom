import type { ApiError } from './api';

const TENANT_CONTEXT_RE = /tenant context|active tenant|tenant-owned writes/i;
const INTERNAL_ERROR_RE = /(sqlalchemy|psycopg|traceback|stack trace|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|access[_ -]?token|refresh[_ -]?token|id[_ -]?token|authorization code|code verifier|nonce|cookie value)/i;
const MAX_MESSAGE_LENGTH = 240;

export interface UserFacingApiError {
  message: string;
  fieldErrors: Record<string, string[]>;
  status?: number;
}

function isApiError(error: unknown): error is ApiError {
  return error instanceof Error && typeof (error as Partial<ApiError>).status === 'number';
}

export function normalizeNotificationMessage(message: unknown, fallback: string): string {
  if (typeof message !== 'string') return fallback;
  const normalized = message.replace(/\s+/g, ' ').trim();
  if (!normalized || INTERNAL_ERROR_RE.test(normalized)) return fallback;
  if (TENANT_CONTEXT_RE.test(normalized)) {
    return 'The application could not determine your active tenant. Refresh the page and try again.';
  }
  return normalized.length > MAX_MESSAGE_LENGTH
    ? `${normalized.slice(0, MAX_MESSAGE_LENGTH - 1).trimEnd()}…`
    : normalized;
}

export function getApiErrorMessage(error: unknown, fallbackMessage: string): string {
  if (!isApiError(error)) return fallbackMessage;

  if (TENANT_CONTEXT_RE.test(error.message) || error.code === 'TENANT_CONTEXT_REQUIRED') {
    return 'The application could not determine your active tenant. Refresh the page and try again.';
  }

  switch (error.status) {
    case 400:
      return normalizeNotificationMessage(
        error.message,
        'The request could not be completed. Please review the entered information.',
      );
    case 401:
      return 'Your session has expired. Please sign in again.';
    case 403:
      return 'You do not have permission to perform this action.';
    case 404:
      return 'The requested item was not found or is not available in your tenant.';
    case 409:
      return normalizeNotificationMessage(error.message, 'The requested change conflicts with existing data.');
    case 422:
      return 'Please correct the highlighted fields.';
    case 429:
      return 'Too many requests were submitted. Please wait and try again.';
    case 500:
    case 502:
    case 503:
    case 504:
      return 'The operation could not be completed because the service is temporarily unavailable.';
    default:
      return normalizeNotificationMessage(error.message, fallbackMessage);
  }
}

export function toUserFacingApiError(error: unknown, fallbackMessage: string): UserFacingApiError {
  return {
    message: getApiErrorMessage(error, fallbackMessage),
    fieldErrors: isApiError(error) ? error.fieldErrors ?? {} : {},
    status: isApiError(error) ? error.status : undefined,
  };
}

export function actionSuccessMessage(action: string, subject?: string): string {
  const safeSubject = subject?.replace(/[“”]/g, '').trim();
  return safeSubject
    ? `${action} “${safeSubject}” was completed successfully.`
    : `${action} was completed successfully.`;
}
