const fs = require("fs");
const path = require("path");

const DATA_DIR = process.env.SR_DATA_DIR || path.join(__dirname, "..", "data");
const CONFIG_PATH = path.join(DATA_DIR, "backup-config.json");

const DEFAULT_BACKUP_CONFIG = {
  enabled: true,
  frequency: "daily", // daily | weekly
  hour: 2,
  minute: 0,
  weekday: 1, // 0=domingo ... 6=sabado
  retention: 30,
};

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function normalizeConfig(raw) {
  const source = raw || {};
  const frequency = source.frequency === "weekly" ? "weekly" : "daily";
  return {
    enabled: source.enabled !== false,
    frequency,
    hour: clampInt(source.hour, 0, 23, DEFAULT_BACKUP_CONFIG.hour),
    minute: clampInt(source.minute, 0, 59, DEFAULT_BACKUP_CONFIG.minute),
    weekday: clampInt(source.weekday, 0, 6, DEFAULT_BACKUP_CONFIG.weekday),
    retention: clampInt(source.retention, 1, 365, DEFAULT_BACKUP_CONFIG.retention),
  };
}

function readBackupConfig() {
  ensureDataDir();
  if (!fs.existsSync(CONFIG_PATH)) {
    return { ...DEFAULT_BACKUP_CONFIG };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
    return normalizeConfig(raw);
  } catch (_) {
    return { ...DEFAULT_BACKUP_CONFIG };
  }
}

function saveBackupConfig(nextConfig) {
  ensureDataDir();
  const normalized = normalizeConfig(nextConfig);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(normalized, null, 2), "utf8");
  return normalized;
}

module.exports = {
  CONFIG_PATH,
  DEFAULT_BACKUP_CONFIG,
  readBackupConfig,
  saveBackupConfig,
  normalizeConfig,
};

