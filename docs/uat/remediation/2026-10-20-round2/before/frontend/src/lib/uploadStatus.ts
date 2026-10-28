export function normalizeValidationStatus(status?: string | null) {
  return String(status ?? '').toLowerCase().replaceAll('-', '_');
}

export function isValidUploadStatus(status?: string | null) {
  const s = normalizeValidationStatus(status);
  return s === 'valid' || s === 'validated' || s === 'imported';
}

export function isWarningUploadStatus(status?: string | null) {
  const s = normalizeValidationStatus(status);
  return s === 'valid_with_warnings' || s === 'warning' || s === 'warnings';
}

export function isFailedUploadStatus(status?: string | null) {
  const s = normalizeValidationStatus(status);
  return s === 'failed' || s === 'invalid' || s === 'validation_failed';
}

export function isUnsupportedUploadStatus(status?: string | null) {
  const s = normalizeValidationStatus(status);
  return s === 'unsupported' || s === 'unsupported_format';
}

export function shouldAutoOpenRepairWorkspace(status?: string | null) {
  return isFailedUploadStatus(status) || isUnsupportedUploadStatus(status);
}

export function shouldAutoCloseUploadModal(status?: string | null) {
  return isValidUploadStatus(status) || isWarningUploadStatus(status);
}
