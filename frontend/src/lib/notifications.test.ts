import { describe, expect, it } from 'vitest';
import { ApiError } from './api';
import { getApiErrorMessage, normalizeNotificationMessage, toUserFacingApiError } from './notifications';

describe('notification error mapping', () => {
  it.each([
    [401, 'Your session has expired. Please sign in again.'],
    [403, 'You do not have permission to perform this action.'],
    [404, 'The requested item was not found or is not available in your tenant.'],
    [429, 'Too many requests were submitted. Please wait and try again.'],
    [500, 'The operation could not be completed because the service is temporarily unavailable.'],
    [503, 'The operation could not be completed because the service is temporarily unavailable.'],
  ])('maps %i safely', (status, expected) => {
    expect(getApiErrorMessage(new ApiError('internal', status), 'fallback')).toBe(expected);
  });

  it('keeps a safe conflict reason', () => {
    expect(getApiErrorMessage(new ApiError('A project with this name already exists.', 409), 'fallback'))
      .toBe('A project with this name already exists.');
  });

  it('maps validation fields without rendering raw detail', () => {
    const error = new ApiError('raw validation', 422, undefined, undefined, { slug: ['Invalid slug'] });
    expect(toUserFacingApiError(error, 'fallback')).toEqual({
      message: 'Please correct the highlighted fields.',
      fieldErrors: { slug: ['Invalid slug'] },
      status: 422,
    });
  });

  it('redacts tenant context, SQLAlchemy, stack traces, and tokens', () => {
    expect(getApiErrorMessage(new ApiError('Tenant context is required for tenant-owned writes', 500), 'fallback'))
      .toMatch(/active tenant/);
    expect(normalizeNotificationMessage('sqlalchemy.exc.IntegrityError: INSERT INTO projects', 'fallback'))
      .toBe('fallback');
    expect(normalizeNotificationMessage('Traceback: access_token=secret', 'fallback')).toBe('fallback');
  });
});
