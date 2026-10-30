'use strict';

// Internal development preload for the pinned Next compiler loader. This is a
// dependency-policy guard, not a general JavaScript or network sandbox.
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const CODE = 'FRONTEND_DEPENDENCY_DOWNLOAD_BLOCKED';
const MESSAGE = `${CODE}: Frontend compiler downloads are disabled. Review python scripts/dev.py setup --repair-dependencies.`;
const GUARD_MESSAGE = 'FRONTEND_GUARD_REQUIRED: Frontend dependency guard requires a prepared local Next installation. Review python scripts/dev.py setup --repair-dependencies.';
const WATCHER_CODE = 'FRONTEND_WATCHER_CONTRACT_REQUIRED';
const WATCHER_MESSAGE = `${WATCHER_CODE}: Frontend source watching requires the verified development workspace and supported Next watcher contract. Review python scripts/dev.py setup --plan.`;
const DOWNLOADER_SUFFIX = '/next/dist/lib/download-swc.js';
const DOWNLOADER_WITHOUT_EXTENSION = '/next/dist/lib/download-swc';
const CANDIDATE_SUFFIX = '/dist/lib/download-swc.js';
const CANDIDATE_WITHOUT_EXTENSION = '/dist/lib/download-swc';
const MAX_MANIFEST_BYTES = 64 * 1024;

function normalize(filename) {
  return process.platform === 'win32' ? filename.replace(/\\/g, '/').toLowerCase() : filename;
}

let localDownloader;
let localNextRoot;
try {
  // Resolution checks the local installed dependency without evaluating it.
  const filename = require.resolve(path.join(
    __dirname, '..', 'frontend', 'node_modules', 'next', 'dist', 'lib', 'download-swc.js',
  ));
  localDownloader = normalize(filename);
  localNextRoot = path.resolve(path.dirname(filename), '..', '..');
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
const routeWatcherParent = normalize(path.join(localNextRoot, 'dist', 'server', 'lib', 'router-utils', 'setup-dev-bundler.js'));
const routeWatcherModule = normalize(path.join(localNextRoot, 'dist', 'compiled', 'watchpack', 'watchpack.js'));

function watcherContractError() {
  const error = new Error(WATCHER_MESSAGE);
  error.code = WATCHER_CODE;
  error.stack = WATCHER_MESSAGE;
  return error;
}

function sameIdentity(first, second) {
  return first.dev === second.dev && first.ino === second.ino && first.mode === second.mode;
}

function unchanged(first, second) {
  return sameIdentity(first, second) && first.size === second.size
    && first.mtimeMs === second.mtimeMs && first.ctimeMs === second.ctimeMs;
}

function verifiedWatcherPaths() {
  try {
    const workspace = process.env.SBOM_DEV_FRONTEND_WORKSPACE;
    const source = process.env.SBOM_DEV_FRONTEND_SOURCE;
    if (typeof workspace !== 'string' || typeof source !== 'string'
        || /[\x00-\x1f\x7f]/.test(workspace + source)
        || !path.isAbsolute(workspace) || !path.isAbsolute(source)
        || normalize(path.resolve(workspace)) !== normalize(workspace)
        || normalize(path.resolve(source)) !== normalize(source)
        || normalize(process.cwd()) !== normalize(workspace)) return null;
    const workspaceInfo = fs.lstatSync(workspace);
    const sourceInfo = fs.lstatSync(source);
    if (!workspaceInfo.isDirectory() || workspaceInfo.isSymbolicLink()
        || !sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()
        || normalize(fs.realpathSync(workspace)) !== normalize(workspace)
        || normalize(fs.realpathSync(source)) !== normalize(source)) return null;
    const linkedSource = path.join(workspace, 'src');
    const linkInfo = fs.lstatSync(linkedSource);
    if (!linkInfo.isSymbolicLink() || normalize(fs.realpathSync(linkedSource)) !== normalize(source)
        || !unchanged(linkInfo, fs.lstatSync(linkedSource))
        || !sameIdentity(sourceInfo, fs.lstatSync(source))
        || !sameIdentity(workspaceInfo, fs.lstatSync(workspace))) return null;
    return { workspace, linkedSource };
  } catch {
    return null;
  }
}

function adaptRouteWatcher(Watchpack) {
  if (typeof Watchpack !== 'function' || !Watchpack.prototype || typeof Watchpack.prototype.watch !== 'function') {
    throw watcherContractError();
  }
  const originalWatch = Watchpack.prototype.watch;
  // Only the route-discovery importer receives this class. The cached original
  // export/prototype and Webpack's independent watcher are never modified.
  return class WorkspaceRouteWatchpack extends Watchpack {
    watch(...args) {
      const verified = verifiedWatcherPaths();
      const options = args[0];
      let supported = false;
      try {
        supported = Boolean(verified && args.length === 1 && options
          && Object.getPrototypeOf(options) === Object.prototype
          && Object.keys(options).sort().join(',') === 'directories,startTime'
          && Object.getOwnPropertySymbols(options).length === 0
          && Array.isArray(options.directories) && options.directories.length === 1
          && typeof options.directories[0] === 'string'
          && normalize(options.directories[0]) === normalize(verified.workspace)
          && options.startTime === 0);
      } catch { /* Unknown option objects receive the fixed contract error below. */ }
      if (!supported) throw watcherContractError();
      // Next watches only dir. Watchpack classifies a linked src entry as a
      // file, so watch the verified lexical src path itself as another root.
      // Real source paths would fail Next's workspace/app prefix checks.
      return Reflect.apply(originalWatch, this, [{
        directories: [verified.workspace, verified.linkedSource],
        startTime: 0,
      }]);
    }
  };
}

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
    if (parent && normalize(parent.filename || '') === routeWatcherParent && request === 'next/dist/compiled/watchpack') {
      throw watcherContractError();
    }
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
    if (parent && normalize(parent.filename || '') === routeWatcherParent
        && (request === 'next/dist/compiled/watchpack' || filename === routeWatcherModule)) {
      if (filename !== routeWatcherModule) throw watcherContractError();
      return adaptRouteWatcher(Reflect.apply(originalLoad, this, arguments));
    }
  }
  return Reflect.apply(originalLoad, this, arguments);
};
