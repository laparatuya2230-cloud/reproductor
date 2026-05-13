const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const DATA_DIR = process.env.SR_DATA_DIR || path.join(__dirname, "..", "data");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const BACKUP_EXT = ".srbackup";
const FORMAT_VERSION = 1;
const RETRYABLE_FS_CODES = new Set(["EBUSY", "EPERM", "EACCES", "ENOTEMPTY"]);
const VOLATILE_ROOT_DIRS = [
  "cache",
  "code cache",
  "gpucache",
  "dawncache",
  "grshadercache",
  "graphitedawncache",
  "blob_storage",
  "network",
  "service worker",
  "session storage",
  "crashpad",
  "partitions",
];
const DEFAULT_PRESERVE_DIRS = ["backups"];

function isRetryableFsError(error) {
  return Boolean(error && RETRYABLE_FS_CODES.has(error.code));
}

function sleepSync(ms) {
  const waitMs = Math.max(0, Number(ms) || 0);
  if (!waitMs) return;
  const end = Date.now() + waitMs;
  while (Date.now() < end) {}
}

function withRetrySync(fn, options = {}) {
  const retries = Math.max(0, Number(options.retries) || 0);
  const delayMs = Math.max(1, Number(options.delayMs) || 25);
  let attempt = 0;
  while (true) {
    try {
      return fn();
    } catch (error) {
      if (!isRetryableFsError(error) || attempt >= retries) {
        throw error;
      }
      attempt += 1;
      sleepSync(delayMs * attempt);
    }
  }
}

function readFileSyncWithRetry(absPath) {
  return withRetrySync(() => fs.readFileSync(absPath), { retries: 8, delayMs: 40 });
}

function rmSyncWithRetry(absPath, options) {
  return withRetrySync(() => fs.rmSync(absPath, options), { retries: 8, delayMs: 50 });
}

function readdirSyncWithRetry(absPath, options) {
  return withRetrySync(() => fs.readdirSync(absPath, options), { retries: 8, delayMs: 35 });
}

function copyFileSyncWithRetry(srcPath, dstPath) {
  return withRetrySync(() => fs.copyFileSync(srcPath, dstPath), { retries: 8, delayMs: 40 });
}

function isVolatileLockFile(relPath) {
  const normalized = toPosix(relPath).toLowerCase();
  if (!normalized.includes("wa_session/")) return false;
  return (
    normalized.includes("singleton") ||
    normalized.includes(".lock") ||
    normalized.endsWith("lock") ||
    normalized.endsWith(".tmp") ||
    normalized.endsWith(".journal")
  );
}

function getRootSegmentLower(relPath) {
  const normalized = toPosix(relPath || "");
  const firstSegment = normalized.split("/")[0] || "";
  return firstSegment.toLowerCase();
}

function isVolatileRuntimePath(relPath) {
  return VOLATILE_ROOT_DIRS.includes(getRootSegmentLower(relPath));
}

function buildPreserveDirSet(preserveDirs = []) {
  const userDirs = Array.isArray(preserveDirs) ? preserveDirs : [];
  const set = new Set();
  [...DEFAULT_PRESERVE_DIRS, ...userDirs].forEach((dirName) => {
    if (!dirName) return;
    set.add(String(dirName));
  });
  VOLATILE_ROOT_DIRS.forEach((dirName) => set.add(dirName));
  return set;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function toPosix(relPath) {
  return String(relPath || "").replace(/\\/g, "/");
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function timestampNow() {
  const d = new Date();
  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    "_" +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function isSafeRelativePath(relPath) {
  const normalized = toPosix(relPath);
  if (!normalized || normalized.startsWith("/") || normalized.includes("\0")) {
    return false;
  }
  if (normalized === "." || normalized === "..") return false;
  if (normalized.startsWith("../") || normalized.includes("/../")) return false;
  return true;
}

function assertInsideDataDir(absPath) {
  const root = path.resolve(DATA_DIR) + path.sep;
  const target = path.resolve(absPath);
  if (!target.startsWith(root)) {
    throw new Error("Ruta fuera del directorio de datos.");
  }
}

function collectFiles(rootDir, options = {}) {
  const includeBackups = options.includeBackups === true;
  const output = [];

  function walk(currentDir) {
    const entries = readdirSyncWithRetry(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const absPath = path.join(currentDir, entry.name);
      const relPath = toPosix(path.relative(rootDir, absPath));
      if (!relPath) continue;

      if (entry.isDirectory()) {
        if (!includeBackups && relPath === "backups") continue;
        if (isVolatileRuntimePath(relPath)) continue;
        walk(absPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!isSafeRelativePath(relPath)) continue;
      if (isVolatileRuntimePath(relPath)) continue;
      output.push({
        absPath,
        relPath,
      });
    }
  }

  if (fs.existsSync(rootDir)) {
    walk(rootDir);
  }

  return output;
}

function listBackupFiles() {
  ensureDir(BACKUP_DIR);
  return fs
    .readdirSync(BACKUP_DIR)
    .filter((name) => name.toLowerCase().endsWith(BACKUP_EXT))
    .map((name) => {
      const absPath = path.join(BACKUP_DIR, name);
      const stat = fs.statSync(absPath);
      return {
        name,
        absPath,
        sizeBytes: stat.size,
        modifiedAt: new Date(stat.mtimeMs).toISOString(),
        mtimeMs: stat.mtimeMs,
      };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
}

function pruneBackups(maxCount = 30) {
  const files = listBackupFiles();
  const toDelete = files.slice(Math.max(0, Number(maxCount) || 30));
  for (const file of toDelete) {
    try {
      assertInsideDataDir(file.absPath);
      fs.unlinkSync(file.absPath);
    } catch (_) {}
  }
}

function createBackupArchive(options = {}) {
  const includeBackups = options.includeBackups === true;
  const destinationDir = options.destinationDir
    ? path.resolve(String(options.destinationDir))
    : BACKUP_DIR;
  const requestedName = String(options.fileName || "").trim();
  const baseName = requestedName
    ? requestedName.replace(new RegExp(`${BACKUP_EXT}$`, "i"), "")
    : `sr_backup_${timestampNow()}`;
  const fileName = `${baseName}${BACKUP_EXT}`;
  const filePath = path.join(destinationDir, fileName);

  if (typeof options.beforeCreate === "function") {
    options.beforeCreate();
  }

  ensureDir(DATA_DIR);
  ensureDir(destinationDir);

  const files = collectFiles(DATA_DIR, { includeBackups });
  const payloadFiles = [];
  const skippedLockedFiles = [];
  let totalBytes = 0;

  for (const item of files) {
    let buffer = null;
    try {
      buffer = readFileSyncWithRetry(item.absPath);
    } catch (error) {
      if (options.allowPartialOnLock && isRetryableFsError(error)) {
        const reason = isVolatileLockFile(item.relPath)
          ? `${item.relPath} (volatile-lock)`
          : `${item.relPath} (${error.code || "lock"})`;
        skippedLockedFiles.push(reason);
        continue;
      }
      throw error;
    }
    totalBytes += buffer.length;
    payloadFiles.push({
      path: item.relPath,
      sizeBytes: buffer.length,
      sha256: sha256(buffer),
      dataBase64: buffer.toString("base64"),
    });
  }

  const manifest = {
    format: "srbackup",
    version: FORMAT_VERSION,
    createdAt: new Date().toISOString(),
    dataDirectory: DATA_DIR,
    includeBackups,
    fileCount: payloadFiles.length,
    totalBytes,
    checksumAlgorithm: "sha256",
    skippedLockedFiles,
  };

  const payload = {
    manifest,
    files: payloadFiles,
  };

  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  const compressed = zlib.gzipSync(raw, { level: 9 });
  fs.writeFileSync(filePath, compressed);

  return {
    filePath,
    fileName,
    sizeBytes: compressed.length,
    archiveSha256: sha256(compressed),
    manifest,
  };
}

function readBackupPayload(backupPath) {
  const filePath = path.resolve(String(backupPath || "").trim());
  if (!filePath) throw new Error("Ruta de backup vacia.");
  if (!fs.existsSync(filePath)) throw new Error("El archivo de backup no existe.");
  const buffer = readFileSyncWithRetry(filePath);
  const raw = zlib.gunzipSync(buffer).toString("utf8");
  const payload = JSON.parse(raw);
  return { filePath, buffer, payload };
}

function validatePayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Backup invalido: estructura no reconocida.");
  }
  if (!payload.manifest || payload.manifest.format !== "srbackup") {
    throw new Error("Backup invalido: manifest no reconocido.");
  }
  if (!Array.isArray(payload.files)) {
    throw new Error("Backup invalido: lista de archivos no encontrada.");
  }
}

function verifyBackupArchive(backupPath) {
  const { filePath, buffer, payload } = readBackupPayload(backupPath);
  validatePayload(payload);

  let totalBytes = 0;
  for (const entry of payload.files) {
    if (!entry || typeof entry !== "object") {
      throw new Error("Backup invalido: entrada corrupta.");
    }
    if (!isSafeRelativePath(entry.path)) {
      throw new Error(`Backup invalido: ruta insegura (${entry.path}).`);
    }
    const dataBuffer = Buffer.from(String(entry.dataBase64 || ""), "base64");
    const digest = sha256(dataBuffer);
    if (digest !== entry.sha256) {
      throw new Error(`Checksum invalido en ${entry.path}.`);
    }
    if (Number(entry.sizeBytes) !== dataBuffer.length) {
      throw new Error(`Tamano invalido en ${entry.path}.`);
    }
    totalBytes += dataBuffer.length;
  }

  return {
    ok: true,
    filePath,
    archiveSha256: sha256(buffer),
    manifest: payload.manifest,
    fileCount: payload.files.length,
    totalBytes,
  };
}

function copyDirectoryContent(srcDir, targetDir) {
  const entries = readdirSyncWithRetry(srcDir, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(targetDir, entry.name);
    if (entry.isDirectory()) {
      const relPath = toPosix(path.relative(srcDir, srcPath));
      if (isVolatileRuntimePath(relPath)) continue;
      fs.mkdirSync(dstPath, { recursive: true });
      copyDirectoryContent(srcPath, dstPath);
      continue;
    }
    if (entry.isFile()) {
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      copyFileSyncWithRetry(srcPath, dstPath);
    }
  }
}

function clearDataDirectory(options = {}) {
  ensureDir(DATA_DIR);
  const preserveDirs = buildPreserveDirSet(options.preserveDirs);
  const skippedLockedEntries = [];
  const entries = readdirSyncWithRetry(DATA_DIR, { withFileTypes: true });
  for (const entry of entries) {
    const lowerName = String(entry.name || "").toLowerCase();
    if (preserveDirs.has(entry.name) || preserveDirs.has(lowerName)) continue;
    const absPath = path.join(DATA_DIR, entry.name);
    assertInsideDataDir(absPath);
    try {
      rmSyncWithRetry(absPath, { recursive: true, force: true });
    } catch (error) {
      if (options.allowPartialOnLock && isRetryableFsError(error)) {
        skippedLockedEntries.push(`${entry.name} (${error.code || "lock"})`);
        continue;
      }
      throw error;
    }
  }
  return { skippedLockedEntries };
}

function restoreBackupArchive(backupPath, options = {}) {
  const { payload } = readBackupPayload(backupPath);
  validatePayload(payload);
  verifyBackupArchive(backupPath);

  if (typeof options.beforeRestore === "function") {
    options.beforeRestore();
  }

  ensureDir(DATA_DIR);
  const tempDir = path.join(DATA_DIR, `.restore_tmp_${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    const skippedVolatilePaths = [];
    for (const entry of payload.files) {
      if (!isSafeRelativePath(entry.path)) {
        throw new Error(`Ruta insegura detectada en backup: ${entry.path}`);
      }
      if (isVolatileRuntimePath(entry.path)) {
        skippedVolatilePaths.push(entry.path);
        continue;
      }
      const targetPath = path.join(tempDir, entry.path);
      assertInsideDataDir(targetPath);
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.writeFileSync(targetPath, Buffer.from(entry.dataBase64, "base64"));
    }

    const preserveDirs = [...(options.preserveDirs || ["backups"]), path.basename(tempDir)];
    const clearResult = clearDataDirectory({
      preserveDirs,
      allowPartialOnLock: true,
    });
    copyDirectoryContent(tempDir, DATA_DIR);
    return {
      ok: true,
      restoredFiles: payload.files.length,
      manifest: payload.manifest,
      skippedVolatilePaths,
      skippedLockedEntries: clearResult.skippedLockedEntries || [],
    };
  } finally {
    if (fs.existsSync(tempDir)) {
      assertInsideDataDir(tempDir);
      rmSyncWithRetry(tempDir, { recursive: true, force: true });
    }
  }
}

module.exports = {
  DATA_DIR,
  BACKUP_DIR,
  BACKUP_EXT,
  createBackupArchive,
  verifyBackupArchive,
  restoreBackupArchive,
  clearDataDirectory,
  listBackupFiles,
  pruneBackups,
};
