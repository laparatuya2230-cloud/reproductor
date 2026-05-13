const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const DATA_DIR = process.env.SR_DATA_DIR || path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "sr_reparaciones.db");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

const REPAIR_STATES = [
  "esperando su turno",
  "revision",
  "en reparacion",
  "esperando piezas",
  "no confirmada",
  "confirmada",
  "reparada",
  "entregado",
];

function ensureColumn(tableName, columnName, sqlDefinition) {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const exists = columns.some((column) => column.name === columnName);
  if (!exists) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${sqlDefinition}`);
  }
}

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS equipments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL UNIQUE,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      equipment_name TEXT NOT NULL,
      issue_details TEXT,
      status TEXT NOT NULL DEFAULT 'revision',
      received_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      is_closed INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS status_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      equipment_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      comment TEXT,
      changed_at TEXT NOT NULL,
      FOREIGN KEY (equipment_id) REFERENCES equipments(id)
    );

    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      part_name TEXT NOT NULL,
      part_code TEXT,
      quantity INTEGER NOT NULL DEFAULT 0,
      unit_cost REAL NOT NULL DEFAULT 0,
      sale_price REAL NOT NULL DEFAULT 0,
      supplier TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS quotes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quote_number TEXT NOT NULL UNIQUE,
      equipment_id INTEGER NOT NULL,
      labor_cost REAL NOT NULL DEFAULT 0,
      discount_amount REAL NOT NULL DEFAULT 0,
      subtotal REAL NOT NULL DEFAULT 0,
      total REAL NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pendiente',
      notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (equipment_id) REFERENCES equipments(id)
    );

    CREATE TABLE IF NOT EXISTS quote_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quote_id INTEGER NOT NULL,
      description TEXT NOT NULL,
      quantity REAL NOT NULL,
      unit_price REAL NOT NULL,
      line_total REAL NOT NULL,
      FOREIGN KEY (quote_id) REFERENCES quotes(id)
    );

    CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      invoice_number TEXT NOT NULL UNIQUE,
      equipment_id INTEGER NOT NULL,
      quote_id INTEGER,
      subtotal REAL NOT NULL DEFAULT 0,
      total REAL NOT NULL DEFAULT 0,
      paid_at TEXT,
      delivered_at TEXT,
      notes TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (equipment_id) REFERENCES equipments(id),
      FOREIGN KEY (quote_id) REFERENCES quotes(id)
    );

    CREATE TABLE IF NOT EXISTS invoice_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      invoice_id INTEGER NOT NULL,
      description TEXT NOT NULL,
      quantity REAL NOT NULL,
      unit_price REAL NOT NULL,
      line_total REAL NOT NULL,
      FOREIGN KEY (invoice_id) REFERENCES invoices(id)
    );

    CREATE TABLE IF NOT EXISTS cash_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_date TEXT NOT NULL,
      employee_name TEXT NOT NULL,
      opening_amount REAL NOT NULL DEFAULT 0,
      opened_at TEXT NOT NULL,
      closed_at TEXT,
      total_invoices REAL NOT NULL DEFAULT 0,
      expected_closing_amount REAL,
      counted_amount REAL,
      difference REAL,
      status TEXT NOT NULL DEFAULT 'abierta',
      notes TEXT
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_part_code
    ON inventory(part_code)
    WHERE part_code IS NOT NULL AND part_code <> '';

    CREATE INDEX IF NOT EXISTS idx_eq_status      ON equipments(status, is_closed);
    CREATE INDEX IF NOT EXISTS idx_eq_updated     ON equipments(updated_at);
    CREATE INDEX IF NOT EXISTS idx_sh_equipment   ON status_history(equipment_id);
    CREATE INDEX IF NOT EXISTS idx_inv_equipment  ON invoices(equipment_id);
    CREATE INDEX IF NOT EXISTS idx_inv_delivered  ON invoices(delivered_at);
    CREATE INDEX IF NOT EXISTS idx_quotes_equip   ON quotes(equipment_id);
    CREATE INDEX IF NOT EXISTS idx_qi_quote       ON quote_items(quote_id);
  `);

  ensureColumn("invoices",     "session_id",    "INTEGER");
  ensureColumn("invoices",     "cash_received", "REAL");
  ensureColumn("invoices",     "change_given",  "REAL");
  ensureColumn("quote_items",  "inventory_id",  "INTEGER");

  // Este índice usa session_id que se agrega con ensureColumn — debe ir después
  db.exec(`CREATE INDEX IF NOT EXISTS idx_inv_session ON invoices(session_id, delivered_at);`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'tecnico',
      full_name TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS login_security (
      username TEXT PRIMARY KEY,
      failed_count INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      details TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_login_locked_until ON login_security(locked_until);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
  `);

  // Migración: eliminar UNIQUE en session_date para permitir múltiples cajas por día
  try {
    const indexes = db.prepare("PRAGMA index_list('cash_sessions')").all();
    const uniqueIdx = indexes.find((idx) => {
      if (!idx.unique) return false;
      const cols = db.prepare(`PRAGMA index_info('${idx.name}')`).all();
      return cols.some((c) => c.name === "session_date");
    });
    if (uniqueIdx) {
      db.exec(`
        CREATE TABLE cash_sessions_v2 (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_date TEXT NOT NULL,
          employee_name TEXT NOT NULL,
          opening_amount REAL NOT NULL DEFAULT 0,
          opened_at TEXT NOT NULL,
          closed_at TEXT,
          total_invoices REAL NOT NULL DEFAULT 0,
          expected_closing_amount REAL,
          counted_amount REAL,
          difference REAL,
          status TEXT NOT NULL DEFAULT 'abierta',
          notes TEXT
        );
        INSERT INTO cash_sessions_v2
          SELECT id, session_date, employee_name, opening_amount, opened_at,
                 closed_at, total_invoices, expected_closing_amount, counted_amount,
                 difference, status, notes
          FROM cash_sessions;
        DROP TABLE cash_sessions;
        ALTER TABLE cash_sessions_v2 RENAME TO cash_sessions;
      `);
    }
  } catch (_) {}
}

function getNowIso() {
  return new Date().toISOString();
}

function getNextCode(prefix, table, column) {
  const year = new Date().getFullYear();
  const likeValue = `${prefix}-${year}-%`;
  const row = db
    .prepare(
      `SELECT ${column} AS current_code
       FROM ${table}
       WHERE ${column} LIKE ?
       ORDER BY id DESC
       LIMIT 1`
    )
    .get(likeValue);

  let nextSequence = 1;
  if (row?.current_code) {
    const sections = String(row.current_code).split("-");
    const lastValue = Number(sections[sections.length - 1]);
    if (Number.isFinite(lastValue)) {
      nextSequence = lastValue + 1;
    }
  }
  return `${prefix}-${year}-${String(nextSequence).padStart(4, "0")}`;
}

function nextEquipmentCode() {
  return getNextCode("SRA", "equipments", "code");
}

function nextQuoteNumber() {
  return getNextCode("COT", "quotes", "quote_number");
}

function nextInvoiceNumber() {
  return getNextCode("FAC", "invoices", "invoice_number");
}

function getUserByUsername(username) {
  return db.prepare("SELECT * FROM users WHERE username = ? AND is_active = 1").get(username);
}

function getAllUsers() {
  return db.prepare(`
    SELECT
      u.id,
      u.username,
      u.role,
      u.full_name,
      u.created_at,
      u.is_active,
      COALESCE(ls.failed_count, 0) AS failed_count,
      ls.locked_until
    FROM users u
    LEFT JOIN login_security ls ON ls.username = u.username
    ORDER BY u.id
  `).all();
}

function checkpointDb() {
  try {
    db.pragma("wal_checkpoint(TRUNCATE)");
  } catch (_) {}
}

function closeDb() {
  checkpointDb();
  try {
    db.close();
  } catch (_) {}
}

module.exports = {
  db,
  DATA_DIR,
  DB_PATH,
  REPAIR_STATES,
  initDb,
  getNowIso,
  nextEquipmentCode,
  nextQuoteNumber,
  nextInvoiceNumber,
  getUserByUsername,
  getAllUsers,
  checkpointDb,
  closeDb,
};
