'use strict';

// Internal development preload for the pinned Next compiler loader. This is a
// dependency-policy guard, not a general JavaScript or network sandbox.
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const CODE = 'FRONTEND_DEPENDENCY_DOWNLOAD_BLOCKED';
const MESSAGE = `${CODE}: Frontend compiler downloads are disabled. Review python scripts/dev.py setup --repair-dependencies.`;
const GUARD_MESSAGE = 'FRONTEND_GUARD_REQUIRED: Frontend dependency guard requires a prepared local Next installation. Review python scripts/dev.py setup --repair-dependencies.';
const DOWNLOADER_SUFFIX = '/next/dist/lib/download-swc.js';
const DOWNLOADER_WITHOUT_EXTENSION = '/next/dist/lib/download-swc';
const CANDIDATE_SUFFIX = '/dist/lib/download-swc.js';
const CANDIDATE_WITHOUT_EXTENSION = '/dist/lib/download-swc';
const MAX_MANIFEST_BYTES = 64 * 1024;

function normalize(filename) {
  return process.platform === 'win32' ? filename.replace(/\\/g, '/').toLowerCase() : filename;
}

let localDownloader;
try {
  // Resolution checks the local installed dependency without evaluating it.
  localDownloader = normalize(require.resolve(path.join(
    __dirname, '..', 'frontend', 'node_modules', 'next', 'dist', 'lib', 'download-swc.js',
  )));
} catch {
  // An uncaught preload error adds Node loader paths to stderr. Emit only the
  // fixed diagnostic, then stop before application code or Next can run.
  fs.writeSync(2, `${GUARD_MESSAGE}\n`);
  process.exit(1);
}

function denyDownload() {
  const error = new Error(MESSAGE);
  error.code = CODE;
  // Callers may log error.stack rather than error.message. Keep both safe.
  error.stack = MESSAGE;
  throw error;
}

const blockedDownloader = Object.freeze(Object.defineProperty({
  downloadNativeNextSwc: denyDownload,
  downloadWasmSwc: denyDownload,
}, '__esModule', { value: true }));

const originalLoad = Module._load;
const originalResolveFilename = Module._resolveFilename;

function isNextPackageOrUnknown(filename) {
  // Node resolves package symlinks to their real directory, whose basename need
  // not be "next". Inspect only this specific downloader candidate's bounded
  // public manifest; an absent, unsafe or changing manifest is not permission
  // to evaluate a possible downloader.
  const manifest = path.resolve(path.dirname(filename), '..', '..', 'package.json');
  let descriptor;
  try {
    const before = fs.lstatSync(manifest);
    if (!before.isFile() || before.size < 1 || before.size > MAX_MANIFEST_BYTES) return true;
    descriptor = fs.openSync(manifest, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      return true;
    }
    const bytes = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = fs.readSync(descriptor, bytes, length, bytes.length - length, length);
      if (read === 0) break;
      length += read;
    }
    const after = fs.fstatSync(descriptor);
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs
        || after.ctimeMs !== before.ctimeMs) return true;
    const metadata = JSON.parse(bytes.subarray(0, length).toString('utf8'));
    if (!metadata || typeof metadata.name !== 'string' || metadata.name.length === 0) return true;
    return metadata.name === 'next';
  } catch {
    return true;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Keep metadata failures closed and redacted. */ }
    }
  }
}

function isDownloaderRequest(request, parent) {
  if (typeof request !== 'string') return false;
  const normalizedRequest = normalize(request);
  if (normalizedRequest === 'next/dist/lib/download-swc' || normalizedRequest === 'next/dist/lib/download-swc.js') {
    return true;
  }
  let filename;
  if (path.isAbsolute(request)) {
    filename = request;
  } else if ((normalizedRequest.startsWith('./') || normalizedRequest.startsWith('../')) && parent && parent.filename) {
    filename = path.resolve(path.dirname(parent.filename), request);
  } else {
    return false;
  }
  const normalized = normalize(filename);
  if (normalized.endsWith(DOWNLOADER_SUFFIX) || normalized.endsWith(DOWNLOADER_WITHOUT_EXTENSION)) return true;
  return (normalized.endsWith(CANDIDATE_SUFFIX) || normalized.endsWith(CANDIDATE_WITHOUT_EXTENSION))
    && isNextPackageOrUnknown(filename);
}

Module._load = function guardedLoad(request, parent, isMain) {
  // Also pin the requested location: swapping the original path for a symlink
  // after preload must not evade the resolved-filename comparison below.
  if (isDownloaderRequest(request, parent)) return blockedDownloader;
  let resolved;
  try {
    resolved = Reflect.apply(originalResolveFilename, Module, [request, parent, isMain]);
  } catch {
    // Preserve normal resolution failures for unrelated modules. No module has
    // been evaluated, so a missing downloader cannot execute here either.
    return Reflect.apply(originalLoad, this, arguments);
  }
  if (typeof resolved === 'string') {
    const filename = normalize(resolved);
    if (filename === localDownloader || filename.endsWith(DOWNLOADER_SUFFIX)
        || (filename.endsWith(CANDIDATE_SUFFIX) && isNextPackageOrUnknown(resolved))) {
      // Never evaluate the real downloader, even if its contents change after
      // the initial resolution or another installed Next tree is selected.
      return blockedDownloader;
    }
  }
  return Reflect.apply(originalLoad, this, arguments);
};
