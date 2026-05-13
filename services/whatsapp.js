const { Client, LocalAuth } = require("whatsapp-web.js");
const qrcode = require("qrcode");
const path   = require("path");

let client   = null;
let status   = "disconnected"; // disconnected | qr | connecting | ready
let lastQR   = null;           // base64 data URL
let qrSubs   = [];             // SSE response objects waiting for QR
let pendingMessages = [];      // cola temporal mientras WhatsApp se conecta

function getStatus()  { return status; }
function getLastQR()  { return lastQR; }

function subscribeQR(res) { qrSubs.push(res); }
function unsubscribeQR(res) {
  qrSubs = qrSubs.filter(r => r !== res);
}
function broadcastQR(dataUrl) {
  qrSubs.forEach(r => {
    try { r.write(`data: ${JSON.stringify({ qr: dataUrl })}\n\n`); } catch (_) {}
  });
}

async function flushPendingMessages() {
  if (status !== "ready" || !client || pendingMessages.length === 0) return;
  const queue = pendingMessages.splice(0);
  for (const item of queue) {
    try {
      await sendMessage(item.phone, item.message, { allowQueue: false });
    } catch (_) {}
  }
}

function init() {
  if (client) return;

  status = "connecting";
  client = new Client({
    authStrategy: new LocalAuth({ dataPath: path.join(process.env.SR_DATA_DIR || path.join(__dirname, "..", "data"), "wa_session") }),
    puppeteer: {
      headless: true,
      pipe: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    },
  });

  client.on("qr", async (qr) => {
    status = "qr";
    try {
      lastQR = await qrcode.toDataURL(qr);
      broadcastQR(lastQR);
    } catch (_) {}
  });

  client.on("authenticated", () => {
    status = "connecting";
    lastQR = null;
  });

  client.on("ready", () => {
    status = "ready";
    lastQR = null;
    console.log("[WA] Cliente WhatsApp listo.");
    flushPendingMessages().catch(() => {});
  });

  client.on("disconnected", (reason) => {
    console.log("[WA] Desconectado:", reason);
    status = "disconnected";
    lastQR = null;
    client = null;
  });

  client.initialize().catch(err => {
    console.error("[WA] Error al inicializar:", err.message);
    status = "disconnected";
    client = null;
  });
}

async function sendMessage(phone, message, options = {}) {
  const allowQueue = options.allowQueue !== false;
  if (status !== "ready" || !client) {
    if (allowQueue) {
      pendingMessages.push({ phone, message });
      if (!client) init();
      console.warn("[WA] Mensaje en cola: WhatsApp aun no esta listo.");
      return true;
    }
    return false;
  }
  try {
    const digits = String(phone || "").replace(/\D/g, "");
    const candidates = [];
    if (!digits) return false;
    if (digits.length === 10 && /^(809|829|849)/.test(digits)) {
      candidates.push("1" + digits);
    }
    candidates.push(digits);
    if (digits.length === 11 && digits.startsWith("1")) {
      candidates.push(digits.slice(1));
    }

    for (const candidate of candidates) {
      const numberId = await client.getNumberId(candidate);
      if (!numberId) continue;
      await client.sendMessage(numberId._serialized, message);
      return true;
    }

    // Ultimo intento directo por ID construido.
    await client.sendMessage(candidates[0] + "@c.us", message);
    return true;
  } catch (err) {
    console.error("[WA] Error enviando mensaje:", err.message);
    return false;
  }
}

async function disconnect(options = {}) {
  const currentClient = client;
  client = null;
  status = "disconnected";
  lastQR = null;
  pendingMessages = [];

  if (!currentClient) return;

  const timeoutMs = Math.max(1000, Number(options.timeoutMs) || 5000);
  let timer = null;
  try {
    const destroyPromise = Promise.resolve(currentClient.destroy());
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("WA destroy timeout")), timeoutMs);
    });
    await Promise.race([destroyPromise, timeoutPromise]);
  } catch (_) {
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = { init, sendMessage, getStatus, getLastQR, subscribeQR, unsubscribeQR, disconnect };
