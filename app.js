const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const bwipjs = require("bwip-js");
const {
  db,
  DATA_DIR,
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
} = require("./db");
const { startAutoBackup, stopAutoBackup, tickScheduler } = require("./backup");
const wa = require("./services/whatsapp");
const {
  BACKUP_DIR,
  createBackupArchive,
  verifyBackupArchive,
  restoreBackupArchive,
  listBackupFiles,
  pruneBackups,
} = require("./services/backup-manager");
const { readBackupConfig, saveBackupConfig } = require("./services/backup-config");

initDb();
startAutoBackup();

// Eliminar rol técnico si existe (migración)
db.prepare("DELETE FROM users WHERE role = 'tecnico'").run();

// Crear usuarios por defecto si no existe ninguno
(function seedDefaultUsers() {
  const count = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  if (count === 0) {
    const now = new Date().toISOString();
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash, role, full_name, created_at) VALUES (?, ?, ?, ?, ?)"
    );
    insert.run("admin",     bcrypt.hashSync("admin123", 10), "admin",     "Administrador", now);
    insert.run("empleado",  bcrypt.hashSync("emple123", 10), "empleado",  "Empleado",      now);
  }
})();

const app = express();
const PORT = process.env.PORT || 3000;
const WORKFLOW_STATES = REPAIR_STATES.filter((state) => state !== "entregado");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true, limit: "80mb" }));
app.use(express.json({ limit: "80mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  secret: "sr-santiago-2025-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.session.returnTo = req.originalUrl;
    return res.redirect("/admin/login");
  }
  next();
}

function hasAnyRole(userRole, allowedRoles) {
  const role = String(userRole || "").toLowerCase();
  const normalizedAllowed = allowedRoles.map((r) => String(r || "").toLowerCase());
  if (normalizedAllowed.includes(role)) return true;
  if (role === "recepcion" && normalizedAllowed.includes("empleado")) return true;
  if (role === "empleado" && normalizedAllowed.includes("recepcion")) return true;
  return false;
}

function requireRole(...roles) {
  return [
    requireAuth,
    (req, res, next) => {
      if (!hasAnyRole(req.session.user.role, roles)) {
        return res.status(403).render("admin/403", { title: "Acceso denegado", active: "" });
      }
      next();
    },
  ];
}

app.locals.formatMoney = (value) =>
  new Intl.NumberFormat("es-DO", {
    style: "currency",
    currency: "DOP",
    maximumFractionDigits: 2,
  }).format(Number(value || 0));

app.locals.formatDate = (value) =>
  value ? new Date(value).toLocaleString("es-DO") : "-";

app.locals.workflowStates = WORKFLOW_STATES;
app.locals.backupDir = BACKUP_DIR;

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let idx = 0;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx += 1;
  }
  return `${size.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function resolveBackupPath(inputPath) {
  const value = String(inputPath || "").trim();
  if (!value) {
    throw new Error("Debes indicar la ruta del archivo .srbackup.");
  }
  return path.resolve(value);
}

function renderBackupPage(res, extra = {}) {
  const backupConfig = readBackupConfig();
  const backupFiles = listBackupFiles().map((file) => ({
    ...file,
    sizeLabel: formatBytes(file.sizeBytes),
  }));
  return res.render("admin/backup", {
    title: "Backup y Restauracion",
    active: "backup",
    backupFiles,
    backupDir: BACKUP_DIR,
    dataDir: DATA_DIR,
    backupConfig,
    error: null,
    success: null,
    verifyResult: null,
    ...extra,
  });
}

function auditLog({ req = null, userId = null, username = null, action, entityType = null, entityId = null, details = null }) {
  try {
    const sessionUser = req?.session?.user || null;
    const resolvedUserId = userId || sessionUser?.id || null;
    const resolvedUsername = String(
      username || sessionUser?.username || "system"
    ).trim();
    db.prepare(
      `
        INSERT INTO audit_log (user_id, username, action, entity_type, entity_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    ).run(
      resolvedUserId,
      resolvedUsername,
      String(action || "unknown"),
      entityType ? String(entityType) : null,
      entityId != null ? String(entityId) : null,
      details ? JSON.stringify(details) : null,
      getNowIso()
    );
  } catch (_) {}
}

const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_MINUTES = 15;

function getLoginSecurity(username) {
  return db
    .prepare("SELECT username, failed_count, locked_until, updated_at FROM login_security WHERE username = ?")
    .get(username);
}

function clearLoginSecurity(username) {
  db.prepare("DELETE FROM login_security WHERE username = ?").run(username);
}

function registerFailedLogin(username) {
  const now = new Date();
  const row = getLoginSecurity(username);
  let failedCount = row ? Number(row.failed_count || 0) + 1 : 1;
  let lockedUntil = null;

  if (failedCount >= LOGIN_MAX_ATTEMPTS) {
    lockedUntil = new Date(now.getTime() + LOGIN_LOCK_MINUTES * 60 * 1000).toISOString();
    failedCount = 0;
  }

  if (row) {
    db.prepare(
      `
        UPDATE login_security
        SET failed_count = ?, locked_until = ?, updated_at = ?
        WHERE username = ?
      `
    ).run(failedCount, lockedUntil, getNowIso(), username);
  } else {
    db.prepare(
      `
        INSERT INTO login_security (username, failed_count, locked_until, updated_at)
        VALUES (?, ?, ?, ?)
      `
    ).run(username, failedCount, lockedUntil, getNowIso());
  }

  return {
    failedCount,
    lockedUntil,
    remainingAttempts: Math.max(0, LOGIN_MAX_ATTEMPTS - failedCount),
  };
}

function activeLockInfo(row) {
  if (!row || !row.locked_until) return null;
  const until = new Date(row.locked_until);
  if (!Number.isFinite(until.getTime())) return null;
  const diffMs = until.getTime() - Date.now();
  if (diffMs <= 0) return null;
  return {
    untilIso: until.toISOString(),
    minutesLeft: Math.max(1, Math.ceil(diffMs / 60000)),
  };
}

function escapeCsvValue(value) {
  const raw = value == null ? "" : String(value);
  if (/[",\n\r]/.test(raw)) {
    return `"${raw.replace(/"/g, '""')}"`;
  }
  return raw;
}

function sendCsv(res, filename, headers, rows) {
  const headerLine = headers.map((h) => escapeCsvValue(h.label)).join(",");
  const bodyLines = rows.map((row) =>
    headers.map((h) => escapeCsvValue(row[h.key])).join(",")
  );
  const csv = [headerLine, ...bodyLines].join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  return res.send("\ufeff" + csv);
}

function getEquipmentById(id) {
  return db.prepare("SELECT * FROM equipments WHERE id = ?").get(id);
}

function addStatusHistory(equipmentId, status, comment = "") {
  db.prepare(
    `
      INSERT INTO status_history (equipment_id, status, comment, changed_at)
      VALUES (?, ?, ?, ?)
    `
  ).run(equipmentId, status, comment, getNowIso());
}

function buildWaMessageForStatus(status, equipmentName, code) {
  const normalizedStatus = String(status || "").trim().toLowerCase();
  const template =
    WA_MESSAGES[normalizedStatus] ||
    "Hola, su equipo *{equipo}* (Codigo: *{code}*) cambio al estado *{estado}*. - Santiago Reparaciones";
  return template
    .replace("{equipo}", equipmentName || "su equipo")
    .replace("{code}", code || "-")
    .replace("{estado}", normalizedStatus || "actualizado");
}

function sendStatusWhatsApp(phone, equipmentName, code, status) {
  const normalizedPhone = String(phone || "").trim();
  if (!normalizedPhone) return;
  const msg = buildWaMessageForStatus(status, equipmentName, code);
  wa.sendMessage(normalizedPhone, msg).catch((err) => {
    console.error("[WA] Error enviando notificacion de estado:", err.message);
  });
}

function toArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    return [value];
  }
  return [];
}

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase();
}

const WA_MESSAGES = {
  "esperando su turno":
    "📋 Hola, le informamos que su equipo *{equipo}* (Código: *{code}*) fue recibido correctamente y está en lista de espera. Le avisaremos cuando iniciemos la revisión. — Santiago Reparaciones 🔧",
  "revision":
    "🔍 Hola, su equipo *{equipo}* (Código: *{code}*) está siendo revisado por nuestros técnicos. En breve le tendremos novedades. — Santiago Reparaciones 🔧",
  "en reparacion":
    "🔧 Hola, le informamos que su equipo *{equipo}* (Código: *{code}*) ya está en proceso de reparación. Pronto estará listo. — Santiago Reparaciones 🔧",
  "esperando piezas":
    "⏳ Hola, su equipo *{equipo}* (Código: *{code}*) está en espera de piezas para continuar la reparación. Le avisaremos en cuanto lleguen. — Santiago Reparaciones 🔧",
  "no confirmada":
    "⚠️ Hola, necesitamos su confirmación para continuar con la reparación del equipo *{equipo}* (Código: *{code}*). Por favor comuníquese con nosotros. — Santiago Reparaciones 🔧",
  "confirmada":
    "✅ Hola, el diagnóstico de su equipo *{equipo}* (Código: *{code}*) fue confirmado. Pronto iniciamos la reparación. — Santiago Reparaciones 🔧",
  "reparada":
    "✅ Hola, ¡buenas noticias! Su equipo *{equipo}* (Código: *{code}*) ya está listo para ser retirado. Por favor coordine la entrega con nosotros. — Santiago Reparaciones 🔧",
};

function buildWaLink(phone, equipmentName, code, status) {
  const digits = String(phone || "").replace(/\D/g, "");
  const waPhone =
    digits.length === 10 && /^(809|829|849)/.test(digits)
      ? "1" + digits
      : digits.length === 11 && digits.startsWith("1")
      ? digits
      : digits;
  const template = WA_MESSAGES[status] || "Hola, le contactamos de Santiago Reparaciones sobre su equipo *{equipo}* (Código: *{code}*).";
  const text = template
    .replace("{equipo}", equipmentName)
    .replace("{code}", code);
  return `https://wa.me/${waPhone}?text=${encodeURIComponent(text)}`;
}

app.locals.buildWaLink = buildWaLink;

function toPositiveNumber(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }
  return parsed;
}

function getBusinessDate(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Santo_Domingo",
  }).format(date);
}

function getTodaySession() {
  const today = getBusinessDate();
  const session = db
    .prepare(
      `
        SELECT *
        FROM cash_sessions
        WHERE session_date = ? AND status = 'abierta'
        LIMIT 1
      `
    )
    .get(today);
  return { today, session };
}

function getInvoicesForSession(sessionId) {
  return db
    .prepare(
      `
        SELECT
          i.id,
          i.invoice_number,
          i.total,
          i.cash_received,
          i.change_given,
          i.delivered_at,
          e.code AS equipment_code,
          e.customer_name,
          e.equipment_name
        FROM invoices i
        INNER JOIN equipments e ON e.id = i.equipment_id
        WHERE i.session_id = ? AND i.delivered_at IS NOT NULL
        ORDER BY i.delivered_at ASC
      `
    )
    .all(sessionId);
}

function mapQuoteStatusToEquipmentStatus(status) {
  if (status === "aprobada" || status === "facturada") {
    return "confirmada";
  }
  return "no confirmada";
}

function syncEquipmentStatusFromLatestQuote(equipmentId) {
  const equipment = getEquipmentById(equipmentId);
  if (!equipment) return;

  const latestQuote = db
    .prepare(
      `
        SELECT status
        FROM quotes
        WHERE equipment_id = ?
        ORDER BY id DESC
        LIMIT 1
      `
    )
    .get(equipmentId);

  if (!latestQuote) {
    if (String(equipment.status || "").trim().toLowerCase() === "revision") {
      return;
    }
    db.prepare("UPDATE equipments SET status = ?, updated_at = ? WHERE id = ?").run(
      "revision",
      getNowIso(),
      equipmentId
    );
    addStatusHistory(equipmentId, "revision", "Sin cotizaciones activas");
    sendStatusWhatsApp(
      equipment.customer_phone,
      equipment.equipment_name,
      equipment.code,
      "revision"
    );
    return;
  }

  const newStatus = mapQuoteStatusToEquipmentStatus(latestQuote.status);
  if (String(equipment.status || "").trim().toLowerCase() === newStatus) {
    return;
  }
  db.prepare("UPDATE equipments SET status = ?, updated_at = ? WHERE id = ?").run(
    newStatus,
    getNowIso(),
    equipmentId
  );
  addStatusHistory(equipmentId, newStatus, "Estado sincronizado por cambio de cotizacion");
  sendStatusWhatsApp(
    equipment.customer_phone,
    equipment.equipment_name,
    equipment.code,
    newStatus
  );
}

function buildQuoteFormData(body = {}) {
  const discountPercentRaw = toPositiveNumber(body.discount_percent);
  const discountPercent = Math.min(100, discountPercentRaw);
  return {
    equipment_code: normalizeCode(body.equipment_code),
    labor_cost: toPositiveNumber(body.labor_cost),
    discount_percent: discountPercent,
    notes: (body.notes || "").trim(),
    item_part_code: toArray(body.item_part_code).map((code) => normalizeCode(code)),
    item_quantity: toArray(body.item_quantity).map((qty) => toPositiveNumber(qty)),
  };
}

function parsePartCodeFromDescription(description) {
  const value = String(description || "");
  const [possibleCode] = value.split(" - ");
  return normalizeCode(possibleCode);
}

function renderQuotesPage(req, res, options = {}) {
  const { error = null, formData = null, statusCode = 200, success = null } = options;

  const preparedForm = formData || {
    equipment_code: "",
    labor_cost: 0,
    discount_percent: 0,
    notes: "",
    item_part_code: [""],
    item_quantity: [1],
  };

  if (preparedForm.item_part_code.length === 0) {
    preparedForm.item_part_code = [""];
  }
  if (preparedForm.item_quantity.length === 0) {
    preparedForm.item_quantity = [1];
  }

  const quotes = db
    .prepare(
      `
        SELECT
          q.*,
          e.code AS equipment_code,
          e.customer_name,
          e.equipment_name
        FROM quotes q
        INNER JOIN equipments e ON e.id = q.equipment_id
        ORDER BY q.id DESC
      `
    )
    .all();

  const getItems = db
    .prepare(
      `
        SELECT description, quantity, unit_price, line_total
        FROM quote_items
        WHERE quote_id = ?
        ORDER BY id ASC
      `
    );

  const quotesWithItems = quotes.map((quote) => ({
    ...quote,
    items: getItems.all(quote.id),
  }));

  const inventoryCatalog = db
    .prepare(
      `
        SELECT part_code, part_name, sale_price
        FROM inventory
        WHERE part_code IS NOT NULL AND part_code <> ''
        ORDER BY part_code ASC
      `
    )
    .all();

  const equipmentPreview = preparedForm.equipment_code
    ? db
        .prepare(
          `
            SELECT id, code, customer_name, customer_phone, equipment_name, status, is_closed
            FROM equipments
            WHERE code = ?
            LIMIT 1
          `
        )
        .get(preparedForm.equipment_code)
    : null;

  return res.status(statusCode).render("admin/quotes", {
    title: "Cotizaciones",
    active: "quotes",
    quotes: quotesWithItems,
    inventoryCatalog,
    formData: preparedForm,
    equipmentPreview,
    error,
    success,
  });
}

// ── Login / Logout ──────────────────────────────────────────
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function shutdownRuntimeForDataOps() {
  stopAutoBackup();
  await wa.disconnect({ timeoutMs: 7000 });
  try {
    checkpointDb();
  } catch (_) {}
  try {
    closeDb();
  } catch (_) {}
  await sleep(250);
}

function tryCreateSafetyBackup({ fileName, destinationDir = BACKUP_DIR, includeBackups = false } = {}) {
  try {
    const result = createBackupArchive({
      includeBackups,
      fileName,
      destinationDir,
      allowPartialOnLock: true,
    });
    return { result, warning: null };
  } catch (error) {
    auditLog({
      action: "safety_backup_skip",
      username: "system",
      entityType: "backup",
      details: { fileName, reason: error.message },
    });
    return {
      result: null,
      warning: `No se pudo crear respaldo de seguridad (${error.message}). Se continuo con la operacion.`,
    };
  }
}

app.use("/setup", (_req, res) => {
  if (res.locals.currentUser) return res.redirect("/admin/dashboard");
  return res.redirect("/admin/login");
});

app.get("/admin/login", (req, res) => {
  if (req.session.user) return res.redirect("/admin/dashboard");
  res.render("admin/login", { title: "Iniciar sesión", error: null });
});

app.post("/admin/login", (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const password = req.body.password || "";
  const lock = activeLockInfo(getLoginSecurity(username));
  if (lock) {
    auditLog({
      action: "login_blocked",
      username,
      entityType: "auth",
      details: { until: lock.untilIso, minutesLeft: lock.minutesLeft },
    });
    return res.render("admin/login", {
      title: "Iniciar sesion",
      error: `Cuenta bloqueada temporalmente. Intenta de nuevo en ${lock.minutesLeft} minuto(s).`,
    });
  }

  const user = getUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    const failed = registerFailedLogin(username);
    const afterLock = failed.lockedUntil
      ? ` Cuenta bloqueada por ${LOGIN_LOCK_MINUTES} minutos.`
      : ` Intentos restantes: ${failed.remainingAttempts}.`;
    auditLog({
      action: "login_failed",
      username,
      entityType: "auth",
      details: { remainingAttempts: failed.remainingAttempts, lockedUntil: failed.lockedUntil },
    });
    return res.render("admin/login", {
      title: "Iniciar sesion",
      error: `Usuario o contrasena incorrectos.${afterLock}`,
    });
  }

  clearLoginSecurity(username);
  req.session.user = { id: user.id, username: user.username, role: user.role, full_name: user.full_name };
  auditLog({ req, action: "login_success", entityType: "auth", entityId: user.id });
  const returnTo = req.session.returnTo || "/admin/dashboard";
  delete req.session.returnTo;
  return res.redirect(returnTo);
});

app.post("/admin/logout", (req, res) => {
  auditLog({ req, action: "logout", entityType: "auth" });
  req.session.destroy(() => res.redirect("/admin/login"));
});

// ── Protección global de todas las rutas /admin/* ────────────
app.use("/admin", (req, res, next) => {
  if (req.path === "/login") return next();
  if (!req.session.user) {
    req.session.returnTo = req.originalUrl;
    return res.redirect("/admin/login");
  }
  next();
});

// ── Gestión de usuarios (solo admin) ────────────────────────
app.get("/admin/backup", ...requireRole("admin"), (_req, res) => {
  renderBackupPage(res);
});

app.post("/admin/backup/config", ...requireRole("admin"), (req, res) => {
  try {
    const saved = saveBackupConfig({
      enabled: req.body.enabled === "on",
      frequency: req.body.frequency,
      hour: req.body.hour,
      minute: req.body.minute,
      weekday: req.body.weekday,
      retention: req.body.retention,
    });
    tickScheduler();
    auditLog({
      req,
      action: "backup_config_update",
      entityType: "backup",
      details: saved,
    });
    return renderBackupPage(res, {
      success: "Configuracion de backup guardada correctamente.",
    });
  } catch (error) {
    return renderBackupPage(res, {
      error: `No se pudo guardar la configuracion: ${error.message}`,
    });
  }
});

app.post("/admin/backup/crear", ...requireRole("admin"), (req, res) => {
  try {
    checkpointDb();
    const destinationInput = String(req.body.destination_dir || "").trim();
    const destinationDir = destinationInput ? path.resolve(destinationInput) : BACKUP_DIR;
    const result = createBackupArchive({
      includeBackups: false,
      destinationDir,
      allowPartialOnLock: true,
    });
    const skipped = Array.isArray(result?.manifest?.skippedLockedFiles)
      ? result.manifest.skippedLockedFiles
      : [];
    const cfg = readBackupConfig();
    if (cfg.retention) {
      pruneBackups(cfg.retention);
    }
    auditLog({
      req,
      action: "backup_create_manual",
      entityType: "backup",
      entityId: result.fileName,
      details: { path: result.filePath },
    });
    return renderBackupPage(res, {
      success:
        skipped.length > 0
          ? `Backup creado: ${result.filePath}. Archivos bloqueados omitidos: ${skipped.join(", ")}`
          : `Backup creado: ${result.filePath}`,
    });
  } catch (error) {
    return renderBackupPage(res, {
      error: `No se pudo crear el backup: ${error.message}`,
    });
  }
});

app.post("/admin/backup/verificar", ...requireRole("admin"), (req, res) => {
  try {
    const backupPath = resolveBackupPath(req.body.backup_path);
    const result = verifyBackupArchive(backupPath);
    auditLog({
      req,
      action: "backup_verify",
      entityType: "backup",
      entityId: path.basename(result.filePath),
      details: { filePath: result.filePath, fileCount: result.fileCount },
    });
    return renderBackupPage(res, {
      success: "Backup verificado correctamente.",
      verifyResult: {
        filePath: result.filePath,
        fileCount: result.fileCount,
        totalBytes: formatBytes(result.totalBytes),
        createdAt: result.manifest.createdAt || "-",
        version: result.manifest.version,
      },
    });
  } catch (error) {
    return renderBackupPage(res, {
      error: `No se pudo verificar el backup: ${error.message}`,
    });
  }
});

app.post("/admin/backup/restaurar", ...requireRole("admin"), async (req, res) => {
  try {
    const confirmation = String(req.body.confirm_restore || "").trim().toUpperCase();
    if (confirmation !== "SI") {
      return renderBackupPage(res, {
        error: "Debes escribir SI para confirmar la restauracion.",
      });
    }

    const backupPath = resolveBackupPath(req.body.backup_path);
    verifyBackupArchive(backupPath);
    auditLog({
      req,
      action: "backup_restore",
      entityType: "backup",
      entityId: path.basename(backupPath),
      details: { backupPath, stage: "starting" },
    });

    await shutdownRuntimeForDataOps();

    const safetyBackup = tryCreateSafetyBackup({
      includeBackups: false,
      fileName: `pre_restore_${Date.now()}`,
      destinationDir: BACKUP_DIR,
    });

    const restoreResult = restoreBackupArchive(backupPath, { preserveDirs: ["backups"] });

    const backupMessage = safetyBackup.result
      ? `Respaldo previo guardado en: ${safetyBackup.result.filePath}`
      : (safetyBackup.warning || "No se pudo crear respaldo previo.");
    const restoreWarning =
      restoreResult &&
      Array.isArray(restoreResult.skippedLockedEntries) &&
      restoreResult.skippedLockedEntries.length
        ? ` Entradas bloqueadas omitidas: ${restoreResult.skippedLockedEntries.join(", ")}.`
        : "";

    renderBackupPage(res, {
      success:
        "Restauracion aplicada correctamente. La aplicacion se cerrara para cargar los nuevos datos. " +
        backupMessage + restoreWarning,
    });
    setTimeout(() => process.exit(0), 1200);
  } catch (error) {
    try { initDb(); } catch (_) {}
    startAutoBackup();
    renderBackupPage(res, {
      error: `No se pudo restaurar: ${error.message}`,
    });
  }
});

app.get("/admin/usuarios", ...requireRole("admin"), (_req, res) => {
  res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), success: null, error: null });
});

app.post("/admin/usuarios/nuevo", ...requireRole("admin"), (req, res) => {
  const username  = (req.body.username  || "").trim().toLowerCase();
  const full_name = (req.body.full_name || "").trim();
  const role      = req.body.role || "empleado";
  const password  = req.body.password || "";
  const validRoles = ["admin", "recepcion", "empleado"];
  if (!username || !password || !validRoles.includes(role)) {
    return res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), error: "Datos incompletos o rol inválido.", success: null });
  }
  try {
    db.prepare("INSERT INTO users (username, password_hash, role, full_name, created_at) VALUES (?,?,?,?,?)")
      .run(username, bcrypt.hashSync(password, 10), role, full_name, new Date().toISOString());
    auditLog({
      req,
      action: "user_create",
      entityType: "user",
      entityId: username,
      details: { role, full_name },
    });
    res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), success: "Usuario creado.", error: null });
  } catch (e) {
    const msg = String(e.message).includes("UNIQUE") ? "Ese nombre de usuario ya existe." : "No se pudo crear el usuario.";
    res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), error: msg, success: null });
  }
});

app.post("/admin/usuarios/:id/password", ...requireRole("admin"), (req, res) => {
  const password = req.body.password || "";
  if (password.length < 4) {
    return res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), error: "La contrasena debe tener al menos 4 caracteres.", success: null });
  }
  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(req.params.id);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .run(bcrypt.hashSync(password, 10), req.params.id);
  auditLog({
    req,
    action: "user_password_reset",
    entityType: "user",
    entityId: req.params.id,
    details: { username: user?.username || null },
  });
  res.render("admin/users", { title: "Usuarios", active: "users", users: getAllUsers(), success: "Contrasena actualizada.", error: null });
});

app.post("/admin/usuarios/:id/toggle", ...requireRole("admin"), (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (user && user.role !== "admin") {
    db.prepare("UPDATE users SET is_active = ? WHERE id = ?").run(user.is_active ? 0 : 1, user.id);
    auditLog({
      req,
      action: "user_toggle_active",
      entityType: "user",
      entityId: user.id,
      details: { username: user.username, is_active: user.is_active ? 0 : 1 },
    });
  }
  res.redirect("/admin/usuarios");
});

app.post("/admin/usuarios/:id/desbloquear", ...requireRole("admin"), (req, res) => {
  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(req.params.id);
  if (user?.username) {
    clearLoginSecurity(user.username);
    auditLog({
      req,
      action: "user_unlock",
      entityType: "user",
      entityId: req.params.id,
      details: { username: user.username },
    });
  }
  res.redirect("/admin/usuarios");
});

// ── Redirección raíz ─────────────────────────────────────────
app.get("/", (_req, res) => {
  res.redirect("/admin/dashboard");
});

app.get("/admin/dashboard", (_req, res) => {
  const { today, session } = getTodaySession();
  const metrics = {
    activeEquipments:
      db.prepare("SELECT COUNT(*) AS total FROM equipments WHERE is_closed = 0").get()
        .total || 0,
    repairedPendingPickup:
      db
        .prepare(
          "SELECT COUNT(*) AS total FROM equipments WHERE status = 'reparada' AND is_closed = 0"
        )
        .get().total || 0,
    completedDeliveries:
      db.prepare("SELECT COUNT(*) AS total FROM equipments WHERE is_closed = 1").get().total ||
      0,
    inventoryPieces:
      db.prepare("SELECT COALESCE(SUM(quantity), 0) AS total FROM inventory").get().total || 0,
    pendingQuotes:
      db.prepare("SELECT COUNT(*) AS total FROM quotes WHERE status = 'pendiente'").get().total ||
      0,
    unpaidInvoices:
      db.prepare("SELECT COUNT(*) AS total FROM invoices WHERE paid_at IS NULL").get().total || 0,
    lowStockParts:
      db.prepare(`SELECT COUNT(*) AS total FROM inventory WHERE quantity <= ${LOW_STOCK_THRESHOLD}`).get().total || 0,
    staleEquipments:
      db.prepare(`SELECT COUNT(*) AS total FROM equipments WHERE is_closed = 0 AND updated_at <= datetime('now','-7 days')`).get().total || 0,
  };

  const recentEquipments = db
    .prepare(
      `
        SELECT id, code, customer_name, equipment_name, status, received_at
        FROM equipments
        ORDER BY id DESC
        LIMIT 8
      `
    )
    .all();

  const statusRows = db
    .prepare(
      `
        SELECT status, COUNT(*) AS cnt
        FROM equipments
        WHERE is_closed = 0
        GROUP BY status
      `
    )
    .all();

  const revenueRows = db
    .prepare(
      `
        SELECT strftime('%Y-%m', delivered_at) AS ym,
               ROUND(SUM(total), 0)            AS total
        FROM   invoices
        WHERE  delivered_at IS NOT NULL
        GROUP  BY ym
        ORDER  BY ym DESC
        LIMIT  6
      `
    )
    .all()
    .reverse();

  const repairsPerMonth = db
    .prepare(
      `
        SELECT strftime('%Y-%m', received_at) AS ym,
               COUNT(*)                       AS cnt
        FROM   equipments
        WHERE  received_at >= datetime('now', '-12 months')
        GROUP  BY ym
        ORDER  BY ym ASC
      `
    )
    .all();

  const topBrands = db
    .prepare(
      `
        SELECT UPPER(TRIM(SUBSTR(equipment_name, 1,
                 CASE WHEN INSTR(equipment_name,' ') > 0
                      THEN INSTR(equipment_name,' ') - 1
                      ELSE LENGTH(equipment_name) END
               ))) AS brand,
               COUNT(*) AS cnt
        FROM   equipments
        GROUP  BY brand
        ORDER  BY cnt DESC
        LIMIT  8
      `
    )
    .all();

  res.render("admin/dashboard", {
    title: "Panel Principal",
    active: "dashboard",
    metrics,
    recentEquipments,
    todayDate: today,
    todaySession: session,
    statusRows,
    revenueRows,
    repairsPerMonth,
    topBrands,
  });
});

app.get("/admin/equipos/nuevo", (_req, res) => {
  const nowLocal = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "America/Santo_Domingo",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  }).format(new Date()).replace(" ", "T");
  res.render("admin/new-equipment", {
    title: "Registrar Nuevo Equipo",
    active: "new-equipment",
    generatedCode: nextEquipmentCode(),
    formData: { status: "esperando su turno", received_at: nowLocal },
    error: null,
  });
});

app.post("/admin/equipos/nuevo", (req, res) => {
  const customerName = (req.body.customer_name || "").trim();
  const customerPhone = (req.body.customer_phone || "").trim();
  const equipmentName = (req.body.equipment_name || "").trim();
  const issueDetails = (req.body.issue_details || "").trim();
  const status = String(req.body.status || "esperando su turno").trim().toLowerCase();
  const customCode = normalizeCode(req.body.code);
  const code = customCode || nextEquipmentCode();

  if (!customerName || !customerPhone || !equipmentName) {
    return res.status(400).render("admin/new-equipment", {
      title: "Registrar Nuevo Equipo",
        active: "new-equipment",
        generatedCode: nextEquipmentCode(),
        formData: { ...req.body, status },
        error: "Nombre, numero y nombre del equipo son obligatorios.",
      });
    }

  if (!WORKFLOW_STATES.includes(status)) {
    return res.status(400).render("admin/new-equipment", {
      title: "Registrar Nuevo Equipo",
      active: "new-equipment",
      generatedCode: nextEquipmentCode(),
      formData: { ...req.body, status: "esperando su turno" },
      error: "Selecciona un estado valido.",
    });
  }

  try {
    const now = getNowIso();
    const rawReceivedAt = (req.body.received_at || "").trim();
    const receivedAt = rawReceivedAt ? new Date(rawReceivedAt).toISOString() : now;
    const result = db
      .prepare(
        `
          INSERT INTO equipments
          (code, customer_name, customer_phone, equipment_name, issue_details, status, received_at, updated_at, is_closed)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        `
      )
      .run(code, customerName, customerPhone, equipmentName, issueDetails, status, receivedAt, now);
    addStatusHistory(Number(result.lastInsertRowid), status, "Equipo registrado");
    auditLog({
      req,
      action: "equipment_create",
      entityType: "equipment",
      entityId: result.lastInsertRowid,
      details: { code, status, customerName, equipmentName },
    });
    return res.redirect(`/admin/ticket/${result.lastInsertRowid}?print=1`);
  } catch (error) {
    const duplicated = String(error.message || "").includes("UNIQUE");
    return res.status(400).render("admin/new-equipment", {
      title: "Registrar Nuevo Equipo",
      active: "new-equipment",
      generatedCode: nextEquipmentCode(),
      formData: { ...req.body, status },
      error: duplicated
        ? "El codigo unico ya existe. Usa otro codigo o deja el campo vacio para autogenerarlo."
        : "No se pudo registrar el equipo. Intenta nuevamente.",
    });
  }
});

app.get("/admin/equipos", (req, res) => {
  const showClosed = req.query.show_closed === "1";
  const search = (req.query.q || "").trim();

  const query = `
    SELECT id, code, customer_name, customer_phone, equipment_name, status, received_at, is_closed
    FROM equipments
    WHERE (? = 1 OR is_closed = 0)
      AND (
        ? = ''
        OR code LIKE ?
        OR customer_name LIKE ?
        OR customer_phone LIKE ?
        OR equipment_name LIKE ?
      )
    ORDER BY id DESC
  `;

  const likeSearch = `%${search}%`;
  const equipments = db
    .prepare(query)
    .all(showClosed ? 1 : 0, search, likeSearch, likeSearch, likeSearch, likeSearch);

  res.render("admin/equipments", {
    title: "Equipos Registrados",
    active: "equipments",
    equipments,
    showClosed,
    search,
  });
});

app.get("/admin/estados", (req, res) => {
  const search = (req.query.q || "").trim();
  const likeSearch = `%${search}%`;

  const equipments = db
    .prepare(
      `
        SELECT id, code, customer_name, customer_phone, equipment_name, status, updated_at
        FROM equipments
        WHERE is_closed = 0 AND status <> 'entregado'
          AND (? = '' OR code LIKE ? OR customer_name LIKE ? OR customer_phone LIKE ?)
        ORDER BY updated_at DESC
      `
    )
    .all(search, likeSearch, likeSearch, likeSearch);

  res.render("admin/statuses", {
    title: "Estados de Reparacion",
    active: "statuses",
    equipments,
    workflowStates: WORKFLOW_STATES,
    search,
  });
});

app.post("/admin/estados/:id", (req, res) => {
  const id = Number(req.params.id);
  const status = (req.body.status || "").trim().toLowerCase();
  const comment = (req.body.comment || "").trim();

  if (!WORKFLOW_STATES.includes(status)) {
    return res.status(400).send("Estado invalido.");
  }

  const equipment = getEquipmentById(id);
  if (!equipment || Number(equipment.is_closed) === 1) {
    return res.status(404).send("Equipo no encontrado o ya cerrado.");
  }

  db.prepare("UPDATE equipments SET status = ?, updated_at = ? WHERE id = ?").run(
    status,
    getNowIso(),
    id
  );
  addStatusHistory(id, status, comment || "Estado actualizado");
  auditLog({
    req,
    action: "equipment_status_update",
    entityType: "equipment",
    entityId: id,
    details: { previousStatus: equipment.status, newStatus: status, comment },
  });

  // Notificación WhatsApp automática
  sendStatusWhatsApp(
    equipment.customer_phone,
    equipment.equipment_name,
    equipment.code,
    status
  );

  res.redirect("/admin/estados");
});

const LOW_STOCK_THRESHOLD = 3;

function renderInventory(res, extra = {}) {
  const parts = db.prepare("SELECT * FROM inventory ORDER BY id DESC").all();
  const lowStockCount = parts.filter(p => p.quantity <= LOW_STOCK_THRESHOLD).length;
  return res.render("admin/inventory", {
    title: "Inventario",
    active: "inventory",
    parts,
    lowStockCount,
    LOW_STOCK_THRESHOLD,
    error: null,
    success: null,
    ...extra,
  });
}

app.get("/admin/inventario", (_req, res) => {
  renderInventory(res);
});

app.post("/admin/inventario", ...requireRole("admin", "recepcion", "empleado"), (req, res) => {
  const partName = (req.body.part_name || "").trim();
  const partCode = normalizeCode(req.body.part_code);
  const quantity = toPositiveNumber(req.body.quantity);
  const unitCost = toPositiveNumber(req.body.unit_cost);
  const salePrice = toPositiveNumber(req.body.sale_price);
  const supplier = (req.body.supplier || "").trim();

  if (!partName || !partCode) {
    return renderInventory(res, { error: "El nombre y el código de pieza son obligatorios." });
  }

  try {
    const now = getNowIso();
    db.prepare(
      `INSERT INTO inventory (part_name, part_code, quantity, unit_cost, sale_price, supplier, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(partName, partCode, quantity, unitCost, salePrice, supplier, now, now);
    auditLog({
      req,
      action: "inventory_create",
      entityType: "inventory",
      entityId: partCode,
      details: { partName, quantity, salePrice },
    });
  } catch (error) {
    const msg = String(error.message || "").includes("UNIQUE")
      ? "Ese código de pieza ya existe en el inventario."
      : "No se pudo guardar la pieza. Intenta de nuevo.";
    return renderInventory(res, { error: msg });
  }

  return renderInventory(res, { success: "Pieza guardada correctamente." });
});

app.post("/admin/inventario/:id/actualizar", ...requireRole("admin", "recepcion", "empleado"), (req, res) => {
  const id = Number(req.params.id);
  const partName = (req.body.part_name || "").trim();
  const partCode = normalizeCode(req.body.part_code);
  const quantity = toPositiveNumber(req.body.quantity);
  const unitCost = toPositiveNumber(req.body.unit_cost);
  const salePrice = toPositiveNumber(req.body.sale_price);
  const supplier = (req.body.supplier || "").trim();

  if (!partName || !partCode) {
    return renderInventory(res, { error: "El nombre y el código de pieza son obligatorios." });
  }

  try {
    db.prepare(
      `UPDATE inventory
       SET part_name = ?, part_code = ?, quantity = ?, unit_cost = ?, sale_price = ?, supplier = ?, updated_at = ?
       WHERE id = ?`
    ).run(partName, partCode, quantity, unitCost, salePrice, supplier, getNowIso(), id);
    auditLog({
      req,
      action: "inventory_update",
      entityType: "inventory",
      entityId: id,
      details: { partCode, partName, quantity, salePrice },
    });
  } catch (error) {
    const msg = String(error.message || "").includes("UNIQUE")
      ? "Ese código ya pertenece a otra pieza."
      : "No se pudo actualizar la pieza. Intenta de nuevo.";
    return renderInventory(res, { error: msg });
  }

  return renderInventory(res, { success: "Pieza actualizada correctamente." });
});

app.get("/api/inventario/por-codigo/:code", (req, res) => {
  const code = normalizeCode(req.params.code);
  const part = db
    .prepare(
      `
        SELECT part_code, part_name, quantity, unit_cost, sale_price, supplier
        FROM inventory
        WHERE part_code = ?
        LIMIT 1
      `
    )
    .get(code);

  if (!part) {
    return res.status(404).json({
      ok: false,
      message: "Pieza no registrada.",
    });
  }

  res.json({
    ok: true,
    data: part,
  });
});

app.get("/api/equipos/por-codigo/:code", (req, res) => {
  const code = normalizeCode(req.params.code);
  const equipment = db
    .prepare(
      `
        SELECT id, code, customer_name, customer_phone, equipment_name, status, is_closed
        FROM equipments
        WHERE code = ?
        LIMIT 1
      `
    )
    .get(code);

  if (!equipment) {
    return res.status(404).json({
      ok: false,
      message: "Codigo no encontrado.",
    });
  }

  if (Number(equipment.is_closed) === 1) {
    return res.status(400).json({
      ok: false,
      message: "Este equipo ya fue entregado y cerrado.",
    });
  }

  res.json({
    ok: true,
    data: equipment,
  });
});

app.get("/admin/cotizaciones", (req, res) => {
  const success = req.query.ok === "1" ? "Cotizacion guardada correctamente." : null;
  const error = String(req.query.err || "").trim() || null;
  return renderQuotesPage(req, res, { success, error });
});

app.post("/admin/cotizaciones", (req, res) => {
  const formData = buildQuoteFormData(req.body);
  const laborCost = toPositiveNumber(formData.labor_cost);
  const discountPercent = Math.min(100, toPositiveNumber(formData.discount_percent));

  const equipment = db
    .prepare(
      `
        SELECT id, code, customer_name, customer_phone, equipment_name, is_closed
        FROM equipments
        WHERE code = ?
        LIMIT 1
      `
    )
    .get(formData.equipment_code);

  if (!equipment) {
    return renderQuotesPage(req, res, {
      statusCode: 400,
      error: "No existe un equipo con ese codigo unico.",
      formData,
    });
  }

  if (Number(equipment.is_closed) === 1) {
    return renderQuotesPage(req, res, {
      statusCode: 400,
      error: "Ese equipo ya fue entregado y cerrado, no se puede cotizar.",
      formData,
    });
  }

  const items = [];
  const missingPartCodes = [];
  const partCodes = formData.item_part_code;
  const quantities = formData.item_quantity;

  for (let i = 0; i < partCodes.length; i += 1) {
    const partCode = normalizeCode(partCodes[i]);
    const quantity = toPositiveNumber(quantities[i]);

    if (!partCode) {
      continue;
    }

    if (quantity <= 0) {
      return renderQuotesPage(req, res, {
        statusCode: 400,
        error: `Cantidad invalida para la pieza ${partCode}.`,
        formData,
      });
    }

    const part = db
      .prepare(
        `
          SELECT id, part_name, part_code, sale_price
          FROM inventory
          WHERE part_code = ?
          LIMIT 1
        `
      )
      .get(partCode);

    if (!part) {
      missingPartCodes.push(partCode);
      continue;
    }

    const price = toPositiveNumber(part.sale_price);
    const lineTotal = quantity * price;
    items.push({
      inventoryId: part.id,
      partCode: part.part_code,
      partName: part.part_name,
      quantity,
      unitPrice: price,
      lineTotal,
    });
  }

  if (missingPartCodes.length > 0) {
    return renderQuotesPage(req, res, {
      statusCode: 400,
      error: `La pieza ${missingPartCodes.join(", ")} no esta registrada en inventario.`,
      formData,
    });
  }

  if (items.length === 0 && laborCost <= 0) {
    return renderQuotesPage(req, res, {
      statusCode: 400,
      error: "Agrega al menos una pieza por codigo o un costo de mano de obra.",
      formData,
    });
  }

  const subtotal = items.reduce((acc, item) => acc + item.lineTotal, 0) + laborCost;
  const discountAmount = subtotal * (discountPercent / 100);
  const total = Math.max(0, subtotal - discountAmount);
  const now = getNowIso();

  const transaction = db.transaction(() => {
    const quoteResult = db
      .prepare(
        `
          INSERT INTO quotes
          (quote_number, equipment_id, labor_cost, discount_amount, subtotal, total, status, notes, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, 'pendiente', ?, ?, ?)
        `
      )
      .run(
        nextQuoteNumber(),
        equipment.id,
        laborCost,
        discountAmount,
        subtotal,
        total,
        formData.notes,
        now,
        now
      );
    const quoteId = Number(quoteResult.lastInsertRowid);
    const insertItem = db.prepare(
      `
        INSERT INTO quote_items
        (quote_id, description, quantity, unit_price, line_total, inventory_id)
        VALUES (?, ?, ?, ?, ?, ?)
      `
    );
    for (const item of items) {
      insertItem.run(
        quoteId,
        `${item.partCode} - ${item.partName}`,
        item.quantity,
        item.unitPrice,
        item.lineTotal,
        item.inventoryId || null
      );
    }

    db.prepare("UPDATE equipments SET status = 'no confirmada', updated_at = ? WHERE id = ?").run(
      now,
      equipment.id
    );
    addStatusHistory(equipment.id, "no confirmada", "Cotizacion creada pendiente de aprobacion");
    sendStatusWhatsApp(
      equipment.customer_phone,
      equipment.equipment_name,
      equipment.code,
      "no confirmada"
    );
  });

  transaction();
  auditLog({
    req,
    action: "quote_create",
    entityType: "quote",
    entityId: equipment.id,
    details: { equipmentCode: equipment.code, subtotal, total, items: items.length },
  });
  return res.redirect("/admin/cotizaciones?ok=1");
});

app.get("/admin/cotizaciones/:id/editar", (req, res) => {
  const id = Number(req.params.id);
  const quote = db.prepare("SELECT * FROM quotes WHERE id = ?").get(id);
  if (!quote) {
    return res.status(404).send("Cotizacion no encontrada.");
  }
  if (quote.status === "facturada") {
    return res.redirect(
      "/admin/cotizaciones?err=" + encodeURIComponent("No puedes editar una cotizacion facturada.")
    );
  }

  const equipment = db.prepare("SELECT id, code, customer_name, equipment_name FROM equipments WHERE id = ?").get(
    quote.equipment_id
  );
  const items = db
    .prepare(
      `
        SELECT description, quantity
        FROM quote_items
        WHERE quote_id = ?
        ORDER BY id ASC
      `
    )
    .all(id);

  const inventoryCatalog = db
    .prepare(
      `
        SELECT part_code, part_name, sale_price
        FROM inventory
        WHERE part_code IS NOT NULL AND part_code <> ''
        ORDER BY part_code ASC
      `
    )
    .all();

  const formData = {
    equipment_code: equipment?.code || "",
    labor_cost: toPositiveNumber(quote.labor_cost),
    discount_percent:
      toPositiveNumber(quote.subtotal) > 0
        ? Math.min(100, (toPositiveNumber(quote.discount_amount) / toPositiveNumber(quote.subtotal)) * 100)
        : 0,
    notes: quote.notes || "",
    item_part_code: items.map((item) => parsePartCodeFromDescription(item.description)),
    item_quantity: items.map((item) => toPositiveNumber(item.quantity) || 1),
  };

  if (formData.item_part_code.length === 0) {
    formData.item_part_code = [""];
    formData.item_quantity = [1];
  }

  return res.render("admin/quote-edit", {
    title: `Editar ${quote.quote_number}`,
    active: "quotes",
    quote,
    equipment,
    formData,
    inventoryCatalog,
    error: null,
    success: null,
  });
});

app.post("/admin/cotizaciones/:id/editar", (req, res) => {
  const id = Number(req.params.id);
  const quote = db.prepare("SELECT * FROM quotes WHERE id = ?").get(id);
  if (!quote) {
    return res.status(404).send("Cotizacion no encontrada.");
  }
  if (quote.status === "facturada") {
    return res.redirect(
      "/admin/cotizaciones?err=" +
        encodeURIComponent("No puedes editar una cotizacion que ya fue facturada.")
    );
  }

  const formData = buildQuoteFormData(req.body);
  const laborCost = toPositiveNumber(formData.labor_cost);
  const discountPercent = Math.min(100, toPositiveNumber(formData.discount_percent));
  const equipment = db
    .prepare(
      `
        SELECT id, code, customer_name, customer_phone, equipment_name, is_closed
        FROM equipments
        WHERE code = ?
        LIMIT 1
      `
    )
    .get(formData.equipment_code);

  if (!equipment || Number(equipment.is_closed) === 1) {
    return res.status(400).render("admin/quote-edit", {
      title: `Editar ${quote.quote_number}`,
      active: "quotes",
      quote,
      equipment: equipment || null,
      formData,
      inventoryCatalog: db
        .prepare(
          `
            SELECT part_code, part_name, sale_price
            FROM inventory
            WHERE part_code IS NOT NULL AND part_code <> ''
            ORDER BY part_code ASC
          `
        )
        .all(),
      error: "Debes usar un equipo activo por codigo unico.",
      success: null,
    });
  }

  const items = [];
  const missingPartCodes = [];
  for (let i = 0; i < formData.item_part_code.length; i += 1) {
    const partCode = normalizeCode(formData.item_part_code[i]);
    const quantity = toPositiveNumber(formData.item_quantity[i]);
    if (!partCode) {
      continue;
    }
    if (quantity <= 0) {
      missingPartCodes.push(partCode);
      continue;
    }
    const part = db
      .prepare("SELECT part_code, part_name, sale_price FROM inventory WHERE part_code = ? LIMIT 1")
      .get(partCode);
    if (!part) {
      missingPartCodes.push(partCode);
      continue;
    }
    const price = toPositiveNumber(part.sale_price);
    items.push({
      description: `${part.part_code} - ${part.part_name}`,
      quantity,
      unitPrice: price,
      lineTotal: quantity * price,
    });
  }

  if (missingPartCodes.length > 0) {
    return res.status(400).render("admin/quote-edit", {
      title: `Editar ${quote.quote_number}`,
      active: "quotes",
      quote,
      equipment,
      formData,
      inventoryCatalog: db
        .prepare(
          `
            SELECT part_code, part_name, sale_price
            FROM inventory
            WHERE part_code IS NOT NULL AND part_code <> ''
            ORDER BY part_code ASC
          `
        )
        .all(),
      error: `Hay piezas invalidas o no registradas: ${missingPartCodes.join(", ")}`,
      success: null,
    });
  }

  if (items.length === 0 && laborCost <= 0) {
    return res.status(400).render("admin/quote-edit", {
      title: `Editar ${quote.quote_number}`,
      active: "quotes",
      quote,
      equipment,
      formData,
      inventoryCatalog: db
        .prepare(
          `
            SELECT part_code, part_name, sale_price
            FROM inventory
            WHERE part_code IS NOT NULL AND part_code <> ''
            ORDER BY part_code ASC
          `
        )
        .all(),
      error: "Agrega al menos una pieza o mano de obra.",
      success: null,
    });
  }

  const subtotal = items.reduce((acc, item) => acc + item.lineTotal, 0) + laborCost;
  const discountAmount = subtotal * (discountPercent / 100);
  const total = Math.max(0, subtotal - discountAmount);
  const now = getNowIso();
  const oldEquipmentId = quote.equipment_id;

  const transaction = db.transaction(() => {
    db.prepare(
      `
        UPDATE quotes
        SET equipment_id = ?, labor_cost = ?, discount_amount = ?, subtotal = ?, total = ?, notes = ?, status = 'pendiente', updated_at = ?
        WHERE id = ?
      `
    ).run(equipment.id, laborCost, discountAmount, subtotal, total, formData.notes, now, id);

    db.prepare("DELETE FROM quote_items WHERE quote_id = ?").run(id);
    const insertItem = db.prepare(
      `
        INSERT INTO quote_items
        (quote_id, description, quantity, unit_price, line_total)
        VALUES (?, ?, ?, ?, ?)
      `
    );
    for (const item of items) {
      insertItem.run(id, item.description, item.quantity, item.unitPrice, item.lineTotal);
    }

    db.prepare("UPDATE equipments SET status = 'no confirmada', updated_at = ? WHERE id = ?").run(
      now,
      equipment.id
    );
    addStatusHistory(equipment.id, "no confirmada", "Cotizacion editada, requiere reconfirmacion");
    sendStatusWhatsApp(
      equipment.customer_phone,
      equipment.equipment_name,
      equipment.code,
      "no confirmada"
    );
    if (oldEquipmentId !== equipment.id) {
      syncEquipmentStatusFromLatestQuote(oldEquipmentId);
    }
  });

  transaction();
  auditLog({
    req,
    action: "quote_update",
    entityType: "quote",
    entityId: id,
    details: { equipmentCode: equipment.code, subtotal, total, items: items.length },
  });
  return res.redirect(
    "/admin/cotizaciones?ok=1"
  );
});

app.post("/admin/cotizaciones/:id/eliminar", (req, res) => {
  const id = Number(req.params.id);
  const quote = db.prepare("SELECT * FROM quotes WHERE id = ?").get(id);
  if (!quote) {
    return res.status(404).send("Cotizacion no encontrada.");
  }
  if (quote.status === "facturada") {
    return res.redirect(
      "/admin/cotizaciones?err=" +
        encodeURIComponent("No puedes eliminar una cotizacion que ya fue facturada.")
    );
  }

  const transaction = db.transaction(() => {
    db.prepare("DELETE FROM quote_items WHERE quote_id = ?").run(id);
    db.prepare("DELETE FROM quotes WHERE id = ?").run(id);
    syncEquipmentStatusFromLatestQuote(quote.equipment_id);
  });
  transaction();
  auditLog({
    req,
    action: "quote_delete",
    entityType: "quote",
    entityId: id,
    details: { equipment_id: quote.equipment_id, status: quote.status },
  });

  return res.redirect(
    "/admin/cotizaciones?ok=1"
  );
});

app.post("/admin/cotizaciones/:id/estado", (req, res) => {
  const id = Number(req.params.id);
  const status = (req.body.status || "").trim().toLowerCase();
  const validStatuses = ["pendiente", "aprobada", "rechazada"];
  if (!validStatuses.includes(status)) {
    return res.status(400).send("Estado de cotizacion invalido.");
  }

  const quote = db.prepare("SELECT * FROM quotes WHERE id = ?").get(id);
  if (!quote) {
    return res.status(404).send("Cotizacion no encontrada.");
  }

  const now = getNowIso();
  db.prepare("UPDATE quotes SET status = ?, updated_at = ? WHERE id = ?").run(status, now, id);

  if (status === "aprobada") {
    db.prepare("UPDATE equipments SET status = 'confirmada', updated_at = ? WHERE id = ?").run(
      now,
      quote.equipment_id
    );
    addStatusHistory(quote.equipment_id, "confirmada", "Cotizacion aprobada por el cliente");
    const eq = getEquipmentById(quote.equipment_id);
    if (eq) {
      sendStatusWhatsApp(eq.customer_phone, eq.equipment_name, eq.code, "confirmada");
    }
  }

  if (status === "rechazada") {
    db.prepare("UPDATE equipments SET status = 'no confirmada', updated_at = ? WHERE id = ?").run(
      now,
      quote.equipment_id
    );
    addStatusHistory(quote.equipment_id, "no confirmada", "Cotizacion rechazada por el cliente");
    const eq = getEquipmentById(quote.equipment_id);
    if (eq) {
      sendStatusWhatsApp(eq.customer_phone, eq.equipment_name, eq.code, "no confirmada");
    }
  }

  auditLog({
    req,
    action: "quote_status_update",
    entityType: "quote",
    entityId: id,
    details: { status, equipment_id: quote.equipment_id },
  });
  res.redirect("/admin/cotizaciones");
});

app.post("/admin/cotizaciones/:id/facturar", (req, res) => {
  const id = Number(req.params.id);
  const quote = db.prepare("SELECT * FROM quotes WHERE id = ?").get(id);
  if (!quote) {
    return res.status(404).send("Cotizacion no encontrada.");
  }

  const invoiceExists = db
    .prepare("SELECT id FROM invoices WHERE quote_id = ? LIMIT 1")
    .get(id);
  if (invoiceExists) {
    return res.redirect("/admin/facturas");
  }

  const quoteItems = db
    .prepare(
      `
        SELECT description, quantity, unit_price, line_total, inventory_id
        FROM quote_items
        WHERE quote_id = ?
      `
    )
    .all(id);

  const now = getNowIso();
  const transaction = db.transaction(() => {
    const invoiceResult = db
      .prepare(
        `
          INSERT INTO invoices
          (invoice_number, equipment_id, quote_id, subtotal, total, notes, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        nextInvoiceNumber(),
        quote.equipment_id,
        quote.id,
        quote.subtotal,
        quote.total,
        quote.notes || "",
        now
      );

    const invoiceId = Number(invoiceResult.lastInsertRowid);
    const addItem = db.prepare(
      `
        INSERT INTO invoice_items
        (invoice_id, description, quantity, unit_price, line_total)
        VALUES (?, ?, ?, ?, ?)
      `
    );

    for (const item of quoteItems) {
      addItem.run(invoiceId, item.description, item.quantity, item.unit_price, item.line_total);
      if (item.inventory_id) {
        db.prepare(
          "UPDATE inventory SET quantity = MAX(0, quantity - ?), updated_at = ? WHERE id = ?"
        ).run(item.quantity, now, item.inventory_id);
      }
    }

    db.prepare("UPDATE quotes SET status = 'facturada', updated_at = ? WHERE id = ?").run(now, id);
  });

  transaction();
  auditLog({
    req,
    action: "quote_invoiced",
    entityType: "quote",
    entityId: id,
    details: { equipment_id: quote.equipment_id, total: quote.total },
  });
  res.redirect("/admin/facturas");
});

app.get("/admin/facturas", (_req, res) => {
  const { session } = getTodaySession();
  const message = String(_req.query.msg || "").trim();
  const error = String(_req.query.err || "").trim();

  const invoices = db
    .prepare(
      `
        SELECT
          i.*,
          e.code AS equipment_code,
          e.customer_name,
          e.customer_phone,
          e.equipment_name,
          q.quote_number
        FROM invoices i
        INNER JOIN equipments e ON e.id = i.equipment_id
        LEFT JOIN quotes q ON q.id = i.quote_id
        ORDER BY i.id DESC
      `
    )
    .all();

  const itemsStmt = db
    .prepare(
      `
        SELECT description, quantity, unit_price, line_total
        FROM invoice_items
        WHERE invoice_id = ?
        ORDER BY id ASC
      `
    );

  const invoicesWithItems = invoices.map((invoice) => ({
    ...invoice,
    items: itemsStmt.all(invoice.id),
  }));

  res.render("admin/invoices", {
    title: "Facturas",
    active: "invoices",
    invoices: invoicesWithItems,
    todaySession: session,
    message: message || null,
    error: error || null,
  });
});

app.post("/admin/facturas/:id/entregar", (req, res) => {
  const id = Number(req.params.id);
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ?").get(id);
  if (!invoice) {
    return res.status(404).send("Factura no encontrada.");
  }
  const deliveredEquipment = getEquipmentById(invoice.equipment_id);

  const { session } = getTodaySession();
  if (!session || session.status !== "abierta") {
    return res.redirect(
      "/admin/facturas?err=" +
        encodeURIComponent("Primero debes hacer apertura de caja para poder entregar equipos.")
    );
  }

  const cashReceived = toPositiveNumber(req.body.cash_received);
  const total = toPositiveNumber(invoice.total);
  if (cashReceived < total) {
    return res.redirect(
      "/admin/facturas?err=" +
        encodeURIComponent("El monto recibido no puede ser menor al total de la factura.")
    );
  }

  const changeGiven = cashReceived - total;
  const soldInSession =
    db
      .prepare(
        `
          SELECT COALESCE(SUM(total), 0) AS total
          FROM invoices
          WHERE session_id = ? AND delivered_at IS NOT NULL
        `
      )
      .get(session.id).total || 0;
  const availableCash = toPositiveNumber(session.opening_amount) + toPositiveNumber(soldInSession);
  if (changeGiven > availableCash) {
    return res.redirect(
      "/admin/facturas?err=" +
        encodeURIComponent(
          "No hay efectivo suficiente en caja para devolver ese cambio. Revisa apertura o monto recibido."
        )
    );
  }

  const now = getNowIso();
  const transaction = db.transaction(() => {
    db.prepare(
      `
        UPDATE invoices
        SET paid_at = ?, delivered_at = ?, session_id = ?, cash_received = ?, change_given = ?
        WHERE id = ?
      `
    ).run(now, now, session.id, cashReceived, changeGiven, id);
    db.prepare(
      "UPDATE equipments SET is_closed = 1, status = 'entregado', updated_at = ? WHERE id = ?"
    ).run(now, invoice.equipment_id);
    addStatusHistory(invoice.equipment_id, "entregado", "Factura pagada y equipo entregado");
    if (deliveredEquipment) {
      sendStatusWhatsApp(
        deliveredEquipment.customer_phone,
        deliveredEquipment.equipment_name,
        deliveredEquipment.code,
        "entregado"
      );
    }
  });

  transaction();
  auditLog({
    req,
    action: "invoice_delivered",
    entityType: "invoice",
    entityId: id,
    details: { equipment_id: invoice.equipment_id, cashReceived, changeGiven },
  });
  const msg = `Entrega registrada. Recibido ${cashReceived.toFixed(2)} | Cambio ${changeGiven.toFixed(2)}.`;
  res.redirect("/admin/facturas?msg=" + encodeURIComponent(msg));
});

app.get("/admin/caja", (req, res) => {
  const today = getBusinessDate();
  const message = String(req.query.msg || "").trim();
  const error = String(req.query.err || "").trim();

  // Sesion actualmente abierta (si existe)
  const openSession = db
    .prepare("SELECT * FROM cash_sessions WHERE session_date = ? AND status = 'abierta' LIMIT 1")
    .get(today);

  // Ultima sesion del dia (para mostrar resumen si esta cerrada)
  const lastSession = db
    .prepare("SELECT * FROM cash_sessions WHERE session_date = ? ORDER BY id DESC LIMIT 1")
    .get(today) || null;

  // La sesion "activa" para la pagina es la abierta; si no hay, se muestra el formulario de apertura
  const session = openSession || null;

  let deliveredInvoices = [];
  let invoicesTotal = 0;
  let expectedClosing = 0;
  let openingAmount = 0;

  // Mostrar facturas de la sesion abierta, o de la ultima sesion si esta cerrada
  const sessionForInvoices = openSession || lastSession;
  if (sessionForInvoices) {
    deliveredInvoices = getInvoicesForSession(sessionForInvoices.id);
    invoicesTotal = deliveredInvoices.reduce((acc, item) => acc + toPositiveNumber(item.total), 0);
    openingAmount = toPositiveNumber(sessionForInvoices.opening_amount);
    expectedClosing = openingAmount + invoicesTotal;
  }

  res.render("admin/cash-session", {
    title: "Caja - Apertura y Cierre",
    active: "cash",
    todayDate: today,
    session: session || lastSession,
    lastSession,
    deliveredInvoices,
    invoicesTotal,
    openingAmount,
    expectedClosing,
    message: message || null,
    error: error || null,
  });
});

app.post("/admin/caja/apertura", (req, res) => {
  const employeeName = (req.body.employee_name || "").trim();
  const openingAmount = toPositiveNumber(req.body.opening_amount);
  const today = getBusinessDate();

  const openSession = db
    .prepare("SELECT id FROM cash_sessions WHERE session_date = ? AND status = 'abierta' LIMIT 1")
    .get(today);

  if (openSession) {
    return res.redirect(
      "/admin/caja?err=" + encodeURIComponent("Ya hay una caja abierta para hoy.")
    );
  }

  if (!employeeName) {
    return res.redirect(
      "/admin/caja?err=" + encodeURIComponent("El nombre del empleado es obligatorio para apertura.")
    );
  }

  db.prepare(
    `
      INSERT INTO cash_sessions
      (session_date, employee_name, opening_amount, opened_at, status)
      VALUES (?, ?, ?, ?, 'abierta')
    `
  ).run(today, employeeName, openingAmount, getNowIso());
  auditLog({
    req,
    action: "cash_open",
    entityType: "cash_session",
    details: { session_date: today, employee_name: employeeName, opening_amount: openingAmount },
  });

  return res.redirect(
    "/admin/caja?msg=" + encodeURIComponent("Apertura de caja registrada correctamente.")
  );
});

app.post("/admin/caja/cierre", (req, res) => {
  const { session } = getTodaySession();
  if (!session || session.status !== "abierta") {
    return res.redirect(
      "/admin/caja?err=" + encodeURIComponent("No hay caja abierta para cerrar hoy.")
    );
  }

  const countedAmount = toPositiveNumber(req.body.counted_amount);
  const notes = (req.body.notes || "").trim();
  const deliveredInvoices = getInvoicesForSession(session.id);
  const invoicesTotal = deliveredInvoices.reduce((acc, item) => acc + toPositiveNumber(item.total), 0);
  const openingAmount = toPositiveNumber(session.opening_amount);
  const expectedClosing = openingAmount + invoicesTotal;
  const difference = countedAmount - expectedClosing;

  db.prepare(
    `
      UPDATE cash_sessions
      SET
        closed_at = ?,
        total_invoices = ?,
        expected_closing_amount = ?,
        counted_amount = ?,
        difference = ?,
        status = 'cerrada',
        notes = ?
      WHERE id = ?
    `
  ).run(getNowIso(), invoicesTotal, expectedClosing, countedAmount, difference, notes, session.id);
  auditLog({
    req,
    action: "cash_close",
    entityType: "cash_session",
    entityId: session.id,
    details: { countedAmount, expectedClosing, difference },
  });

  let resultMessage = "Cierre realizado.";
  if (difference < 0) {
    resultMessage += ` Faltante: ${Math.abs(difference).toFixed(2)}.`;
  } else if (difference > 0) {
    resultMessage += ` Sobrante: ${difference.toFixed(2)}.`;
  } else {
    resultMessage += " Caja exacta.";
  }

  return res.redirect("/admin/caja?msg=" + encodeURIComponent(resultMessage));
});

app.get("/admin/ticket/:id", (req, res) => {
  const equipment = getEquipmentById(Number(req.params.id));
  if (!equipment) {
    return res.status(404).send("Equipo no encontrado.");
  }
  res.render("admin/ticket", {
    title: `Ticket ${equipment.code}`,
    active: "none",
    equipment,
    autoPrint: req.query.print === "1",
  });
});

app.get("/barcode/:text", async (req, res) => {
  try {
    const png = await bwipjs.toBuffer({
      bcid: "code128",
      text: String(req.params.text || "").toUpperCase(),
      scale: 3,
      height: 12,
      includetext: false,
      backgroundcolor: "FFFFFF",
    });
    res.type("png");
    res.send(png);
  } catch (_error) {
    res.status(400).send("No se pudo generar el codigo de barras.");
  }
});

app.get("/cliente", (req, res) => {
  const code = String(req.query.code || "").trim().toUpperCase();
  let equipment = null;
  let history = [];
  let invoice = null;

  if (code) {
    equipment = db.prepare("SELECT * FROM equipments WHERE code = ?").get(code) || null;
    if (equipment) {
      history = db
        .prepare(
          `
            SELECT status, comment, changed_at
            FROM status_history
            WHERE equipment_id = ?
            ORDER BY id DESC
          `
        )
        .all(equipment.id);
      invoice = db
        .prepare(
          `
            SELECT invoice_number, total, paid_at, delivered_at, created_at
            FROM invoices
            WHERE equipment_id = ?
            ORDER BY id DESC
            LIMIT 1
          `
        )
        .get(equipment.id);
    }
  }

  res.render("client/status-check", {
    title: "Consulta de Estado",
    active: "client",
    queryCode: code,
    equipment,
    history,
    invoice,
  });
});

app.get("/api/estado/:code", (req, res) => {
  const code = String(req.params.code || "").trim().toUpperCase();
  const equipment = db.prepare("SELECT * FROM equipments WHERE code = ?").get(code);
  if (!equipment) {
    return res.status(404).json({
      ok: false,
      message: "Codigo no encontrado.",
    });
  }

  const history = db
    .prepare(
      `
        SELECT status, comment, changed_at
        FROM status_history
        WHERE equipment_id = ?
        ORDER BY id DESC
      `
    )
    .all(equipment.id);

  const invoice = db
    .prepare(
      `
        SELECT invoice_number, total, paid_at, delivered_at, created_at
        FROM invoices
        WHERE equipment_id = ?
        ORDER BY id DESC
        LIMIT 1
      `
    )
    .get(equipment.id);

  res.json({
    ok: true,
    data: {
      code: equipment.code,
      customerName: equipment.customer_name,
      equipmentName: equipment.equipment_name,
      status: equipment.status,
      isClosed: Boolean(equipment.is_closed),
      updatedAt: equipment.updated_at,
      history,
      invoice: invoice || null,
    },
  });
});

// ── REPORTES EXCEL ──────────────────────────────────────────
const ExcelJS = require("exceljs");

function xlsHeader(sheet, columns) {
  sheet.columns = columns;
  const header = sheet.getRow(1);
  header.font = { bold: true, color: { argb: "FFFFFFFF" } };
  header.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFCC0014" } };
  header.alignment = { vertical: "middle", horizontal: "center" };
  header.height = 20;
}

app.get("/admin/reportes", requireAuth, (_req, res) => {
  const years = db.prepare(
    "SELECT DISTINCT strftime('%Y', created_at) AS y FROM invoices ORDER BY y DESC"
  ).all().map(r => r.y);
  res.render("admin/reports", { title: "Reportes", active: "reports", years });
});

// Ingresos (facturas)
app.get("/admin/reportes/ingresos.xlsx", requireAuth, async (req, res) => {
  const year  = req.query.year  || new Date().getFullYear();
  const month = req.query.month || "";
  const where = month
    ? `strftime('%Y-%m', i.created_at) = '${year}-${String(month).padStart(2,"0")}'`
    : `strftime('%Y', i.created_at) = '${year}'`;

  const rows = db.prepare(`
    SELECT i.invoice_number, e.code AS equipo_code, e.customer_name, e.customer_phone,
           e.equipment_name, i.subtotal, i.total,
           i.created_at, i.paid_at, i.delivered_at, i.notes
    FROM invoices i
    JOIN equipments e ON e.id = i.equipment_id
    WHERE ${where}
    ORDER BY i.id DESC
  `).all();

  const wb = new ExcelJS.Workbook();
  wb.creator = "Santiago Reparaciones";
  const ws = wb.addWorksheet("Ingresos");
  xlsHeader(ws, [
    { header: "Factura",      key: "invoice_number", width: 18 },
    { header: "Cod. Equipo",  key: "equipo_code",    width: 16 },
    { header: "Cliente",      key: "customer_name",  width: 24 },
    { header: "Teléfono",     key: "customer_phone", width: 16 },
    { header: "Equipo",       key: "equipment_name", width: 26 },
    { header: "Subtotal",     key: "subtotal",       width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Total",        key: "total",          width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Fecha",        key: "created_at",     width: 20 },
    { header: "Pagada",       key: "paid_at",        width: 20 },
    { header: "Entregada",    key: "delivered_at",   width: 20 },
    { header: "Notas",        key: "notes",          width: 30 },
  ]);

  let totalSum = 0;
  rows.forEach(r => { ws.addRow(r); totalSum += Number(r.total) || 0; });

  const totRow = ws.addRow({ invoice_number: "TOTAL", total: totalSum });
  totRow.font = { bold: true };
  totRow.getCell("total").numFmt = '#,##0.00';

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="ingresos_${year}${month ? '-'+month : ''}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
});

app.get("/admin/reportes/ingresos.csv", requireAuth, (req, res) => {
  const year = req.query.year || new Date().getFullYear();
  const month = req.query.month || "";
  const where = month
    ? `strftime('%Y-%m', i.created_at) = '${year}-${String(month).padStart(2, "0")}'`
    : `strftime('%Y', i.created_at) = '${year}'`;
  const rows = db.prepare(`
    SELECT i.invoice_number, e.code AS equipo_code, e.customer_name, e.customer_phone,
           e.equipment_name, i.subtotal, i.total, i.created_at, i.paid_at, i.delivered_at, i.notes
    FROM invoices i
    JOIN equipments e ON e.id = i.equipment_id
    WHERE ${where}
    ORDER BY i.id DESC
  `).all();
  return sendCsv(
    res,
    `ingresos_${year}${month ? "-" + month : ""}.csv`,
    [
      { key: "invoice_number", label: "Factura" },
      { key: "equipo_code", label: "Codigo equipo" },
      { key: "customer_name", label: "Cliente" },
      { key: "customer_phone", label: "Telefono" },
      { key: "equipment_name", label: "Equipo" },
      { key: "subtotal", label: "Subtotal" },
      { key: "total", label: "Total" },
      { key: "created_at", label: "Fecha" },
      { key: "paid_at", label: "Pagada" },
      { key: "delivered_at", label: "Entregada" },
      { key: "notes", label: "Notas" },
    ],
    rows
  );
});

// Caja
app.get("/admin/reportes/caja.xlsx", requireAuth, async (req, res) => {
  const year = req.query.year || new Date().getFullYear();
  const rows = db.prepare(`
    SELECT session_date, employee_name, opening_amount, total_invoices,
           expected_closing_amount, counted_amount, difference, status,
           opened_at, closed_at, notes
    FROM cash_sessions
    WHERE strftime('%Y', session_date) = ?
    ORDER BY id DESC
  `).all(String(year));

  const wb = new ExcelJS.Workbook();
  wb.creator = "Santiago Reparaciones";
  const ws = wb.addWorksheet("Caja");
  xlsHeader(ws, [
    { header: "Fecha",         key: "session_date",           width: 14 },
    { header: "Empleado",      key: "employee_name",          width: 20 },
    { header: "Apertura",      key: "opening_amount",         width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Facturas",      key: "total_invoices",         width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Esperado",      key: "expected_closing_amount",width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Contado",       key: "counted_amount",         width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Diferencia",    key: "difference",             width: 14, style: { numFmt: '#,##0.00' } },
    { header: "Estado",        key: "status",                 width: 12 },
    { header: "Abierta",       key: "opened_at",              width: 20 },
    { header: "Cerrada",       key: "closed_at",              width: 20 },
    { header: "Notas",         key: "notes",                  width: 28 },
  ]);
  rows.forEach(r => ws.addRow(r));

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="caja_${year}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
});

// Inventario
app.get("/admin/reportes/inventario.xlsx", requireAuth, async (req, res) => {
  const rows = db.prepare(
    "SELECT part_name, part_code, quantity, unit_cost, sale_price, supplier, updated_at FROM inventory ORDER BY part_name"
  ).all();

  const wb = new ExcelJS.Workbook();
  wb.creator = "Santiago Reparaciones";
  const ws = wb.addWorksheet("Inventario");
  xlsHeader(ws, [
    { header: "Pieza",          key: "part_name",   width: 30 },
    { header: "Código",         key: "part_code",   width: 16 },
    { header: "Cantidad",       key: "quantity",    width: 12 },
    { header: "Costo unitario", key: "unit_cost",   width: 16, style: { numFmt: '#,##0.00' } },
    { header: "Precio venta",   key: "sale_price",  width: 16, style: { numFmt: '#,##0.00' } },
    { header: "Valor en stock", key: "stock_value", width: 16, style: { numFmt: '#,##0.00' } },
    { header: "Suplidor",       key: "supplier",    width: 22 },
    { header: "Actualizado",    key: "updated_at",  width: 20 },
  ]);

  let totalVal = 0;
  rows.forEach(r => {
    const val = Number(r.unit_cost) * Number(r.quantity);
    totalVal += val;
    ws.addRow({ ...r, stock_value: val });
  });
  const totRow = ws.addRow({ part_name: "TOTAL VALOR EN STOCK", stock_value: totalVal });
  totRow.font = { bold: true };
  totRow.getCell("stock_value").numFmt = '#,##0.00';

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="inventario.xlsx"');
  await wb.xlsx.write(res);
  res.end();
});

// Equipos
app.get("/admin/reportes/equipos.xlsx", requireAuth, async (req, res) => {
  const rows = db.prepare(`
    SELECT code, customer_name, customer_phone, equipment_name,
           status, received_at, updated_at,
           CASE is_closed WHEN 1 THEN 'Cerrado' ELSE 'Activo' END AS estado_registro
    FROM equipments
    ORDER BY id DESC
  `).all();

  const wb = new ExcelJS.Workbook();
  wb.creator = "Santiago Reparaciones";
  const ws = wb.addWorksheet("Equipos");
  xlsHeader(ws, [
    { header: "Código",      key: "code",             width: 18 },
    { header: "Cliente",     key: "customer_name",    width: 26 },
    { header: "Teléfono",    key: "customer_phone",   width: 16 },
    { header: "Equipo",      key: "equipment_name",   width: 28 },
    { header: "Estado",      key: "status",           width: 20 },
    { header: "Registro",    key: "estado_registro",  width: 12 },
    { header: "Recibido",    key: "received_at",      width: 20 },
    { header: "Actualizado", key: "updated_at",       width: 20 },
  ]);
  rows.forEach(r => ws.addRow(r));

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="equipos.xlsx"');
  await wb.xlsx.write(res);
  res.end();
});

// ── EQUIPOS SIN MOVIMIENTO ───────────────────────────────────
app.get("/admin/reportes/equipos.csv", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT code, customer_name, customer_phone, equipment_name, status, received_at, updated_at,
           CASE is_closed WHEN 1 THEN 'Cerrado' ELSE 'Activo' END AS estado_registro
    FROM equipments
    ORDER BY id DESC
  `).all();
  return sendCsv(
    res,
    "equipos.csv",
    [
      { key: "code", label: "Codigo" },
      { key: "customer_name", label: "Cliente" },
      { key: "customer_phone", label: "Telefono" },
      { key: "equipment_name", label: "Equipo" },
      { key: "status", label: "Estado" },
      { key: "estado_registro", label: "Registro" },
      { key: "received_at", label: "Recibido" },
      { key: "updated_at", label: "Actualizado" },
    ],
    rows
  );
});

app.get("/admin/reportes/estados.csv", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      e.code AS codigo_equipo,
      e.customer_name AS cliente,
      e.equipment_name AS equipo,
      sh.status,
      sh.comment,
      sh.changed_at
    FROM status_history sh
    INNER JOIN equipments e ON e.id = sh.equipment_id
    ORDER BY sh.id DESC
  `).all();
  return sendCsv(
    res,
    "historial_estados.csv",
    [
      { key: "codigo_equipo", label: "Codigo" },
      { key: "cliente", label: "Cliente" },
      { key: "equipo", label: "Equipo" },
      { key: "status", label: "Estado" },
      { key: "comment", label: "Comentario" },
      { key: "changed_at", label: "Fecha cambio" },
    ],
    rows
  );
});

app.get("/admin/reportes/inventario.csv", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT part_name, part_code, quantity, unit_cost, sale_price, supplier, updated_at
    FROM inventory
    ORDER BY part_name
  `).all();
  return sendCsv(
    res,
    "inventario.csv",
    [
      { key: "part_name", label: "Pieza" },
      { key: "part_code", label: "Codigo" },
      { key: "quantity", label: "Cantidad" },
      { key: "unit_cost", label: "Costo unitario" },
      { key: "sale_price", label: "Precio venta" },
      { key: "supplier", label: "Suplidor" },
      { key: "updated_at", label: "Actualizado" },
    ],
    rows
  );
});

app.get("/admin/reportes/caja.csv", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT session_date, employee_name, opening_amount, total_invoices,
           expected_closing_amount, counted_amount, difference, status,
           opened_at, closed_at, notes
    FROM cash_sessions
    ORDER BY id DESC
  `).all();
  return sendCsv(
    res,
    "caja.csv",
    [
      { key: "session_date", label: "Fecha" },
      { key: "employee_name", label: "Empleado" },
      { key: "opening_amount", label: "Apertura" },
      { key: "total_invoices", label: "Facturas" },
      { key: "expected_closing_amount", label: "Esperado" },
      { key: "counted_amount", label: "Contado" },
      { key: "difference", label: "Diferencia" },
      { key: "status", label: "Estado" },
      { key: "opened_at", label: "Abierta" },
      { key: "closed_at", label: "Cerrada" },
      { key: "notes", label: "Notas" },
    ],
    rows
  );
});

app.get("/admin/reportes/auditoria.csv", ...requireRole("admin"), (req, res) => {
  const rows = db.prepare(`
    SELECT username, action, entity_type, entity_id, details, created_at
    FROM audit_log
    ORDER BY id DESC
  `).all();
  return sendCsv(
    res,
    "auditoria.csv",
    [
      { key: "username", label: "Usuario" },
      { key: "action", label: "Accion" },
      { key: "entity_type", label: "Tipo" },
      { key: "entity_id", label: "ID" },
      { key: "details", label: "Detalles" },
      { key: "created_at", label: "Fecha" },
    ],
    rows
  );
});

app.get("/admin/sin-movimiento", requireAuth, (req, res) => {
  const days = Math.max(1, Number(req.query.days) || 7);
  const rows = db.prepare(`
    SELECT id, code, customer_name, equipment_name, status, received_at, updated_at
    FROM equipments
    WHERE is_closed = 0
      AND updated_at <= datetime('now', ? )
    ORDER BY updated_at ASC
  `).all(`-${days} days`);
  res.render("admin/stale-equipment", {
    title: "Sin movimiento",
    active: "stale",
    rows,
    days,
  });
});

// ── WHATSAPP ─────────────────────────────────────────────────
app.get("/admin/whatsapp", requireAuth, (_req, res) => {
  res.render("admin/whatsapp", {
    title: "WhatsApp",
    active: "whatsapp",
    waStatus: wa.getStatus(),
    waQR: wa.getLastQR(),
  });
});

app.post("/admin/whatsapp/iniciar", requireAuth, (req, res) => {
  wa.init();
  auditLog({ req, action: "whatsapp_connect_attempt", entityType: "whatsapp" });
  res.redirect("/admin/whatsapp");
});

app.post("/admin/whatsapp/desconectar", requireAuth, async (req, res) => {
  await wa.disconnect({ timeoutMs: 5000 });
  auditLog({ req, action: "whatsapp_disconnect", entityType: "whatsapp" });
  res.redirect("/admin/whatsapp");
});

// SSE: stream del QR en tiempo real
app.get("/admin/whatsapp/qr-stream", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  // Enviar el QR actual si ya existe
  const current = wa.getLastQR();
  if (current) res.write(`data: ${JSON.stringify({ qr: current })}\n\n`);

  wa.subscribeQR(res);
  req.on("close", () => wa.unsubscribeQR(res));
});

// ── ARRANQUE ─────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Sistema SR activo en http://localhost:${PORT}`);
  });
} else {
  module.exports = { app, PORT };
}
