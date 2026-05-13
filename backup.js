const { checkpointDb } = require("./db");
const { createBackupArchive, listBackupFiles, pruneBackups } = require("./services/backup-manager");
const { readBackupConfig } = require("./services/backup-config");

const CHECK_INTERVAL_MS = 30 * 1000;
let scheduler = null;
let lastScheduleKey = null;
let backupInProgress = false;

function pad(value) {
  return String(value).padStart(2, "0");
}

function buildScheduleKey(now, cfg) {
  const dateKey = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
  const hm = `${pad(cfg.hour)}${pad(cfg.minute)}`;
  return `${cfg.frequency}:${dateKey}:${hm}`;
}

function isScheduleDue(now, cfg) {
  if (!cfg.enabled) return false;
  if (now.getHours() !== cfg.hour || now.getMinutes() !== cfg.minute) return false;
  if (cfg.frequency === "weekly" && now.getDay() !== cfg.weekday) return false;
  return true;
}

function runBackup(options = {}) {
  if (backupInProgress) {
    return null;
  }
  backupInProgress = true;
  const cfg = readBackupConfig();
  const retention = Number(options.retention) || cfg.retention;
  try {
    const result = createBackupArchive({
      includeBackups: false,
      beforeCreate: checkpointDb,
      allowPartialOnLock: true,
    });
    pruneBackups(retention);
    return result;
  } catch (error) {
    console.error("[backup] Error al crear backup:", error.message);
    return null;
  } finally {
    backupInProgress = false;
  }
}

function tickScheduler() {
  const cfg = readBackupConfig();
  const now = new Date();
  const scheduleKey = buildScheduleKey(now, cfg);
  if (!isScheduleDue(now, cfg)) return;
  if (lastScheduleKey === scheduleKey) return;

  const result = runBackup({ retention: cfg.retention });
  if (result) {
    lastScheduleKey = scheduleKey;
    console.log(`[backup] Backup automatico creado: ${result.fileName}`);
  }
}

function startAutoBackup() {
  const cfg = readBackupConfig();
  if (cfg.enabled && listBackupFiles().length === 0) {
    runBackup({ retention: cfg.retention });
  }

  stopAutoBackup();
  scheduler = setInterval(tickScheduler, CHECK_INTERVAL_MS);

  console.log(
    `[backup] Auto-backup activo (${cfg.frequency}) ${pad(cfg.hour)}:${pad(cfg.minute)} retencion=${cfg.retention}`
  );
}

function stopAutoBackup() {
  if (!scheduler) return;
  clearInterval(scheduler);
  scheduler = null;
}

module.exports = { startAutoBackup, stopAutoBackup, runBackup, tickScheduler };
