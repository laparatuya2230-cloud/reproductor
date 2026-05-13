const fs = require("fs");
const path = require("path");

const DATA_DIR = process.env.SR_DATA_DIR || path.join(__dirname, "..", "data");
const SETUP_STATE_PATH = path.join(DATA_DIR, "setup-state.json");

const DEFAULT_STATE = {
  initialized: false,
  mode: null,
  initializedAt: null,
  restoredFrom: null,
};

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readSetupState() {
  ensureDataDir();
  if (!fs.existsSync(SETUP_STATE_PATH)) {
    return { ...DEFAULT_STATE };
  }
  try {
    const raw = fs.readFileSync(SETUP_STATE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return {
      ...DEFAULT_STATE,
      ...parsed,
      initialized: parsed.initialized === true,
    };
  } catch (_) {
    return { ...DEFAULT_STATE };
  }
}

function isSetupCompleted() {
  return readSetupState().initialized === true;
}

function saveSetupState(state) {
  ensureDataDir();
  fs.writeFileSync(SETUP_STATE_PATH, JSON.stringify(state, null, 2), "utf8");
}

function markCleanInstall() {
  const state = {
    initialized: true,
    mode: "clean",
    initializedAt: new Date().toISOString(),
    restoredFrom: null,
  };
  saveSetupState(state);
  return state;
}

function markRestoredInstall(backupPath) {
  const state = {
    initialized: true,
    mode: "restored",
    initializedAt: new Date().toISOString(),
    restoredFrom: String(backupPath || ""),
  };
  saveSetupState(state);
  return state;
}

module.exports = {
  DATA_DIR,
  SETUP_STATE_PATH,
  readSetupState,
  isSetupCompleted,
  markCleanInstall,
  markRestoredInstall,
};

