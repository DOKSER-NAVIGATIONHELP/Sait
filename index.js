// ============================================================
// TIERS CLUB — Express API (для Render)
// Портировано с Cloudflare Worker
// ============================================================

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Render (и любой хостинг за обратным прокси) отдаёт реальный IP клиента
// в заголовке X-Forwarded-For. Без этой строчки req.ip всегда будет IP
// прокси-сервера — и rate-limit будет считать всех посетителей одним "IP".
app.set('trust proxy', 1);

// Базовые security-заголовки (X-Content-Type-Options, HSTS и т.д.)
app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '15mb' })); // файлы чеков идут как base64 в JSON

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // требуется для Render Postgres
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  statement_timeout: 15_000,
  query_timeout: 15_000,
  max: 20,
});

pool.on('error', (e) => {
  console.error('Postgres pool error:', e.message);
});

// ── СЧЁТЧИК "АКТИВНЫХ ПОДПИСОК" ──────────────────────────
// Общий для всех посетителей (хранится в БД, а не в localStorage браузера)
const SUBS_COUNTER_BASE = 240;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET не задан в переменных окружения!');
}

// ── CORS ─────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function ok(res, data = {}) { res.json({ ok: true, ...data }); }
function err(res, msg, status = 400) { res.status(status).json({ error: msg }); }

// Express 4 не ловит автоматически отклонённые промисы из async-хендлеров
function ah(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((e) => {
      console.error('Unhandled route error:', e);
      if (!res.headersSent) err(res, 'Внутренняя ошибка сервера', 500);
    });
  };
}

function bodyOf(req) {
  const b = req.body;
  return (b && typeof b === 'object' && !Array.isArray(b)) ? b : {};
}

function isStr(v, maxLen = 500) {
  return typeof v === 'string' && v.length > 0 && v.length <= maxLen;
}

function toNum(v, fallback = 0, min = 0, max = 1_000_000_000) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

// ── ПОЛУЧЕНИЕ IP ─────────────────────────────────────────
// BUG FIX: req.ip может возвращать IPv6-mapped IPv4 вида "::ffff:1.2.3.4"
// Нормализуем до чистого IPv4 где возможно
function getClientIp(req) {
  const raw = req.ip || req.connection?.remoteAddress || 'unknown';
  // Убираем IPv6-mapped IPv4 префикс
  return raw.replace(/^::ffff:/, '');
}

// ── ЛОГИРОВАНИЕ ПОСЕЩЕНИЙ ────────────────────────────────
// Асинхронное, не блокирует запрос даже при ошибке БД
async function logVisit(req, eventType = 'visit', extra = {}) {
  try {
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers['referer'] || req.headers['referrer'] || '';
    const path = req.originalUrl || req.url || '';
    const method = req.method || 'GET';
    const country = req.headers['cf-ipcountry'] || req.headers['x-country'] || '';
    const extraJson = Object.keys(extra).length ? JSON.stringify(extra) : null;

    await pool.query(
      `INSERT INTO site_logs (ip, user_agent, referer, path, method, country, event_type, extra, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [ip, userAgent.slice(0, 500), referer.slice(0, 500), path.slice(0, 300), method, country.slice(0, 10), eventType, extraJson, new Date().toISOString()]
    );
  } catch (e) {
    // Логирование не должно ронять запрос
    console.error('Log write error:', e.message);
  }
}

// ── TELEGRAM УВЕДОМЛЕНИЯ ─────────────────────────────────
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT  = '-1004331867058';

const TG_EVENT_LABELS = {
  admin_login_ok:   '🟢 Вход в админку',
  admin_login_fail: '🔴 Неудачный вход в админку',
  order_submit:     '📦 Новая заявка',
  visit:            '👁 Визит',
  request:          '🌐 Запрос',
};

async function sendTelegram(text) {
  if (!TG_TOKEN) return; // переменная не задана — молча пропускаем
  try {
    await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        chat_id:    TG_CHAT,
        text:       text.slice(0, 4096),
        parse_mode: 'HTML',
      }),
    });
  } catch (e) {
    console.error('Telegram send error:', e.message);
  }
}

// Отправляем в Telegram только важные события (не каждый request)
const TG_IMPORTANT = new Set(['admin_login_ok', 'admin_login_fail', 'order_submit', 'visit']);

async function logVisitAndNotify(req, eventType, extra = {}) {
  await logVisit(req, eventType, extra);
  if (!TG_IMPORTANT.has(eventType)) return;

  const ip    = getClientIp(req);
  const ua    = (req.headers['user-agent'] || '—').slice(0, 120);
  const label = TG_EVENT_LABELS[eventType] || eventType;
  const now   = new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' });

  let lines = [
    `<b>${label}</b>`,
    `🕐 ${now} МСК`,
    `🌐 IP: <code>${ip}</code>`,
    `📱 UA: ${ua}`,
  ];

  if (eventType === 'order_submit' && extra) {
    lines.push(`📋 Тариф: ${extra.tierName || '—'}`);
    lines.push(`💳 Способ: ${extra.methodId || '—'}`);
    lines.push(`📞 Контакт: ${extra.contact || '—'}`);
    lines.push(`🆔 ID заявки: <code>${extra.orderId || '—'}</code>`);
  }

  sendTelegram(lines.join('\n'));
}

// Middleware: логируем каждый публичный запрос (не API-служебные)
app.use((req, res, next) => {
  const skip = req.path.startsWith('/api/admin') || req.method === 'OPTIONS';
  if (!skip) {
    // Реальный визит человека на страницу сайта (не служебный API-запрос) —
    // логируем И шлём в Telegram. Остальные (API-запросы вроде /api/tiers) —
    // логируем в базу как 'request', но НЕ спамим Telegram.
    const isPageVisit = req.method === 'GET' && !req.path.startsWith('/api/');
    if (isPageVisit) {
      logVisitAndNotify(req, 'visit');
    } else {
      logVisit(req, 'request');
    }
  }
  next();
});

// ── ЗАЩИТА ОТ DOS / БРУТФОРСА ────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много запросов. Попробуйте позже.' },
});
app.use('/api/', generalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Слишком много попыток входа. Попробуйте через 15 минут.' },
});

const ordersPerIpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много заявок с вашего IP. Попробуйте через час.' },
});

let globalOrdersWindowStart = Date.now();
let globalOrdersCount = 0;
const GLOBAL_ORDERS_WINDOW_MS = 60 * 60 * 1000;
const GLOBAL_ORDERS_MAX = 30;

function globalOrdersLimiter(req, res, next) {
  const now = Date.now();
  if (now - globalOrdersWindowStart >= GLOBAL_ORDERS_WINDOW_MS) {
    globalOrdersWindowStart = now;
    globalOrdersCount = 0;
  }
  if (globalOrdersCount >= GLOBAL_ORDERS_MAX) {
    return err(res, 'Достигнут общий лимит заявок за этот час. Попробуйте позже.', 429);
  }
  globalOrdersCount++;
  next();
}

// ── Токен (HMAC-SHA256) ──────────────────────────────────
function signToken(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64');
  return `${data}.${sig}`;
}

function verifyToken(token, secret) {
  try {
    const [data, sig] = token.split('.');
    if (!data || !sig) return null;
    const expected = crypto.createHmac('sha256', secret).update(data).digest('base64');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ── Пароли (PBKDF2) ──────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 200000, 32, 'sha256');
  return `pbkdf2:${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [, saltHex, hashHex] = stored.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const hash = crypto.pbkdf2Sync(password, salt, 200000, 32, 'sha256');
    return hash.toString('hex') === hashHex;
  } catch { return false; }
}

// ── Auth middleware ──────────────────────────────────────
function requireAuth(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  // BUG FIX: JWT_SECRET может быть undefined — передаём пустую строку как крайний случай
  return verifyToken(token, JWT_SECRET || '');
}

function requireAdmin(req, res, next) {
  const payload = requireAuth(req);
  if (!payload) return err(res, 'Не авторизован', 401);
  req.admin = payload;
  next();
}

// ── PUBLIC ROUTES ────────────────────────────────────────

// GET /api/tiers
app.get('/api/tiers', ah(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tiers ORDER BY sort_order ASC');
  const tiers = rows.map(t => {
    let features = [];
    try { features = JSON.parse(t.features || '[]'); } catch { features = []; }
    if (!Array.isArray(features)) features = [];
    return { ...t, features, highlight: t.highlight === 1 };
  });
  ok(res, { tiers });
}));

// GET /api/requisites
app.get('/api/requisites', ah(async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'req_%'");
  const req_ = {};
  rows.forEach(r => { req_[r.key.replace('req_', '')] = r.value; });
  ok(res, { requisites: req_ });
}));

// POST /api/orders
app.post('/api/orders', ordersPerIpLimiter, globalOrdersLimiter, ah(async (req, res) => {
  const body = bodyOf(req);
  const { tierName, methodId, methodName, amount, contact, fileName, fileType, fileData } = body;

  if (!isStr(tierName, 200) || !isStr(methodId, 100) || !isStr(contact, 200) ||
      !isStr(fileName, 200) || !isStr(fileData, 11_000_000)) {
    return err(res, 'Не все поля заполнены корректно');
  }
  if (methodName !== undefined && !isStr(methodName, 200)) {
    return err(res, 'Некорректное имя способа оплаты');
  }
  // BUG FIX: amount может быть числом, приводим к строке перед isStr
  if (amount !== undefined && !isStr(String(amount), 100)) {
    return err(res, 'Некорректная сумма');
  }
  if (fileData.length > 11_000_000) return err(res, 'Файл слишком большой');

  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (!isStr(fileType, 100) || !allowedTypes.includes(fileType)) {
    return err(res, 'Недопустимый тип файла');
  }

  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f"]/.test(fileName)) {
    return err(res, 'Недопустимое имя файла');
  }

  const rawB64 = fileData.includes(',') ? fileData.split(',')[1] : fileData;
  if (!rawB64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(rawB64)) {
    return err(res, 'Файл повреждён или в неверном формате');
  }

  const id = crypto.randomUUID();
  const ip = getClientIp(req);
  const userAgent = (req.headers['user-agent'] || '').slice(0, 500);

  await pool.query(
    `INSERT INTO orders (id, tier_name, method_id, method_name, amount, contact, file_name, file_type, file_data, status, created_at, client_ip, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id, tierName, methodId, methodName || methodId, String(amount ?? ''), contact, fileName, fileType, fileData, 'pending', new Date().toISOString(), ip, userAgent]
  );

  // Логируем событие отправки заявки + уведомление в Telegram
  await logVisitAndNotify(req, 'order_submit', { orderId: id, tierName, methodId, contact: contact.slice(0, 50) });

  // BUG FIX: счётчик "активных подписок" теперь общий для всех (хранится в БД),
  // а не в localStorage браузера. Увеличиваем при КАЖДОЙ заявке, даже неодобренной.
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('subs_counter', $1)
     ON CONFLICT (key) DO UPDATE SET value = (CAST(settings.value AS INTEGER) + 1)::TEXT`,
    [String(SUBS_COUNTER_BASE + 1)]
  );

  ok(res, { id });
}));

// GET /api/subs-count — общий счётчик "активных подписок", виден всем одинаково
app.get('/api/subs-count', ah(async (req, res) => {
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'subs_counter'");
  const n = rows[0] ? parseInt(rows[0].value, 10) : SUBS_COUNTER_BASE;
  ok(res, { count: Number.isFinite(n) && n >= SUBS_COUNTER_BASE ? n : SUBS_COUNTER_BASE });
}));

// ── ADMIN AUTH ───────────────────────────────────────────

app.post('/api/admin/login', loginLimiter, ah(async (req, res) => {
  const { password } = bodyOf(req);
  if (!isStr(password, 500)) return err(res, 'Пароль обязателен', 401);

  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  const row = rows[0];

  if (!row) {
    return err(res, 'Пароль администратора ещё не настроен. Проверьте переменные окружения сервера.', 500);
  }

  const ip = getClientIp(req);
  const ok_ = verifyPassword(password, row.value);

  // Логируем попытки входа + уведомление в Telegram
  await logVisitAndNotify(req, ok_ ? 'admin_login_ok' : 'admin_login_fail', { ip });

  if (!ok_) return err(res, 'Неверный пароль', 401);

  // BUG FIX: JWT_SECRET может быть undefined при отсутствии env — защита
  if (!JWT_SECRET) return err(res, 'JWT_SECRET не настроен на сервере', 500);

  const token = signToken({ role: 'admin', exp: Date.now() + 12 * 60 * 60 * 1000 }, JWT_SECRET);
  ok(res, { token });
}));

// ── ADMIN PROTECTED ROUTES ───────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(v) { return typeof v === 'string' && UUID_RE.test(v); }

app.get('/api/admin/orders', requireAdmin, ah(async (req, res) => {
  const statusParam = req.query.status;
  const allowedStatus = ['all', 'pending', 'approved', 'rejected'];
  const status = (typeof statusParam === 'string' && allowedStatus.includes(statusParam)) ? statusParam : 'all';
  let query = 'SELECT id, tier_name, method_id, method_name, amount, contact, file_name, file_type, status, created_at, client_ip, user_agent FROM orders';
  const params = [];
  if (status !== 'all') { query += ' WHERE status = $1'; params.push(status); }
  query += ' ORDER BY created_at DESC LIMIT 500';
  const { rows } = await pool.query(query, params);
  ok(res, { orders: rows });
}));

app.get('/api/admin/orders/:id/file', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { rows } = await pool.query(
    'SELECT file_data, file_type, file_name FROM orders WHERE id = $1',
    [req.params.id]
  );
  const row = rows[0];
  if (!row) return err(res, 'Не найдено', 404);
  const raw = row.file_data.includes(',') ? row.file_data.split(',')[1] : row.file_data;
  let binary;
  try {
    binary = Buffer.from(raw, 'base64');
  } catch {
    return err(res, 'Файл повреждён', 500);
  }
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  const safeType = allowedTypes.includes(row.file_type) ? row.file_type : 'application/octet-stream';
  // eslint-disable-next-line no-control-regex
  const safeName = String(row.file_name || 'file').replace(/[\x00-\x1f\x7f"]/g, '_');
  res.set({
    'Content-Type': safeType,
    'Content-Disposition': `inline; filename="${safeName}"`,
    'X-Content-Type-Options': 'nosniff',
  });
  res.send(binary);
}));

app.put('/api/admin/orders/:id', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { status } = bodyOf(req);
  if (!['pending', 'approved', 'rejected'].includes(status)) return err(res, 'Неверный статус');
  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
  ok(res);
}));

app.delete('/api/admin/orders/:id', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
  ok(res);
}));

app.get('/api/admin/tiers', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tiers ORDER BY sort_order ASC');
  ok(res, {
    tiers: rows.map(t => {
      let features = [];
      try { features = JSON.parse(t.features || '[]'); } catch { features = []; }
      if (!Array.isArray(features)) features = [];
      return { ...t, features, highlight: t.highlight === 1 };
    }),
  });
}));

app.post('/api/admin/tiers', requireAdmin, ah(async (req, res) => {
  const body = bodyOf(req);
  const id = crypto.randomUUID();
  const { rows: last } = await pool.query('SELECT MAX(sort_order) as m FROM tiers');
  const order = (last[0]?.m ?? 0) + 1;
  const features = Array.isArray(body.features) ? body.features.filter(f => typeof f === 'string').slice(0, 100) : [];
  await pool.query(
    `INSERT INTO tiers (id, name, flag, highlight, price_rub, price_usdt, price_uah, price_stars, period, description, features, cta_text, sort_order)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id,
     isStr(body.name, 200) ? body.name : '',
     isStr(body.flag, 100) ? body.flag : '',
     body.highlight ? 1 : 0,
     toNum(body.priceRub, 0), toNum(body.priceUsdt, 0), toNum(body.priceUah, 0), toNum(body.priceStars, 0),
     isStr(body.period, 50) ? body.period : '/ месяц',
     isStr(body.description, 2000) ? body.description : '',
     JSON.stringify(features),
     isStr(body.ctaText, 100) ? body.ctaText : 'Оформить',
     order]
  );
  ok(res, { id });
}));

app.put('/api/admin/tiers/:id', requireAdmin, ah(async (req, res) => {
  if (!isStr(req.params.id, 100)) return err(res, 'Не найдено', 404);
  const body = bodyOf(req);
  const features = Array.isArray(body.features) ? body.features.filter(f => typeof f === 'string').slice(0, 100) : [];
  await pool.query(
    `UPDATE tiers SET name=$1, flag=$2, highlight=$3, price_rub=$4, price_usdt=$5, price_uah=$6, price_stars=$7, period=$8, description=$9, features=$10, cta_text=$11 WHERE id=$12`,
    [isStr(body.name, 200) ? body.name : '',
     isStr(body.flag, 100) ? body.flag : '',
     body.highlight ? 1 : 0,
     toNum(body.priceRub, 0), toNum(body.priceUsdt, 0), toNum(body.priceUah, 0), toNum(body.priceStars, 0),
     isStr(body.period, 50) ? body.period : '/ месяц',
     isStr(body.description, 2000) ? body.description : '',
     JSON.stringify(features),
     isStr(body.ctaText, 100) ? body.ctaText : 'Оформить',
     req.params.id]
  );
  ok(res);
}));

app.delete('/api/admin/tiers/:id', requireAdmin, ah(async (req, res) => {
  if (!isStr(req.params.id, 100)) return err(res, 'Не найдено', 404);
  await pool.query('DELETE FROM tiers WHERE id = $1', [req.params.id]);
  ok(res);
}));

app.put('/api/admin/tiers/:id/move', requireAdmin, ah(async (req, res) => {
  if (!isStr(req.params.id, 100)) return err(res, 'Не найдено', 404);
  const { direction } = bodyOf(req);
  if (direction !== 'up' && direction !== 'down') return err(res, 'Некорректное направление');

  const { rows: cur } = await pool.query('SELECT id, sort_order FROM tiers WHERE id = $1', [req.params.id]);
  const current = cur[0];
  if (!current) return err(res, 'Не найдено', 404);

  const neighborQuery = direction === 'up'
    ? 'SELECT id, sort_order FROM tiers WHERE sort_order < $1 ORDER BY sort_order DESC LIMIT 1'
    : 'SELECT id, sort_order FROM tiers WHERE sort_order > $1 ORDER BY sort_order ASC LIMIT 1';
  const { rows: nb } = await pool.query(neighborQuery, [current.sort_order]);
  const neighbor = nb[0];
  if (!neighbor) return ok(res);

  await pool.query('UPDATE tiers SET sort_order=$1 WHERE id=$2', [neighbor.sort_order, current.id]);
  await pool.query('UPDATE tiers SET sort_order=$1 WHERE id=$2', [current.sort_order, neighbor.id]);
  ok(res);
}));

app.get('/api/admin/requisites', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'req_%'");
  const req_ = {};
  rows.forEach(r => { req_[r.key.replace('req_', '')] = r.value; });
  ok(res, { requisites: req_ });
}));

app.put('/api/admin/requisites', requireAdmin, ah(async (req, res) => {
  const body = bodyOf(req);
  const allowed = ['rubBank', 'rubCard', 'rubCardsAccepted', 'uahBank', 'uahCard', 'uahCardsAccepted', 'tonAddress', 'trcAddress', 'starsNote'];
  for (const key of allowed) {
    if (body[key] !== undefined && isStr(String(body[key]), 2000)) {
      await pool.query(
        `INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        ['req_' + key, String(body[key])]
      );
    }
  }
  ok(res);
}));

app.put('/api/admin/password', requireAdmin, ah(async (req, res) => {
  const { currentPassword, newPassword } = bodyOf(req);
  if (!isStr(newPassword, 200) || newPassword.length < 8) return err(res, 'Пароль должен быть от 8 до 200 символов');

  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  const row = rows[0];
  if (row) {
    if (!isStr(currentPassword) || !verifyPassword(currentPassword, row.value)) {
      return err(res, 'Неверный текущий пароль', 401);
    }
  }
  const hash = hashPassword(newPassword);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [hash]
  );
  ok(res);
}));

app.get('/api/admin/stats', requireAdmin, ah(async (req, res) => {
  const pending  = await pool.query("SELECT COUNT(*) as c FROM orders WHERE status='pending'");
  const approved = await pool.query("SELECT COUNT(*) as c FROM orders WHERE status='approved'");
  const total    = await pool.query('SELECT COUNT(*) as c FROM orders');
  const tiers    = await pool.query('SELECT COUNT(*) as c FROM tiers');
  // BUG FIX: добавляем счётчик логов в stats
  let logsCount = 0;
  try {
    const logs = await pool.query('SELECT COUNT(*) as c FROM site_logs');
    logsCount = Number(logs.rows[0].c);
  } catch { /* таблица может ещё не существовать */ }

  ok(res, {
    stats: {
      pending:  Number(pending.rows[0].c),
      approved: Number(approved.rows[0].c),
      total:    Number(total.rows[0].c),
      tiers:    Number(tiers.rows[0].c),
      logs:     logsCount,
    }
  });
}));

// ── ADMIN LOGS ROUTES ────────────────────────────────────

// GET /api/admin/logs — получить список логов с фильтрацией и пагинацией
app.get('/api/admin/logs', requireAdmin, ah(async (req, res) => {
  const allowedTypes = ['all', 'visit', 'request', 'order_submit', 'admin_login_ok', 'admin_login_fail'];
  const typeParam = req.query.type;
  const eventType = (typeParam && allowedTypes.includes(typeParam)) ? typeParam : 'all';

  // BUG FIX: limit/offset нужно приводить к числу безопасно
  const limit  = Math.min(toNum(req.query.limit, 100, 1, 500), 500);
  const offset = toNum(req.query.offset, 0, 0, 1_000_000);

  let query  = 'SELECT id, ip, user_agent, referer, path, method, country, event_type, extra, created_at FROM site_logs';
  let countQ = 'SELECT COUNT(*) as c FROM site_logs';
  const params = [];

  if (eventType !== 'all') {
    query  += ' WHERE event_type = $1';
    countQ += ' WHERE event_type = $1';
    params.push(eventType);
  }
  query += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;

  const [{ rows }, { rows: countRows }] = await Promise.all([
    pool.query(query, params),
    pool.query(countQ, params),
  ]);

  ok(res, {
    logs:  rows,
    total: Number(countRows[0].c),
    limit,
    offset,
  });
}));

// DELETE /api/admin/logs — очистить все логи
app.delete('/api/admin/logs', requireAdmin, ah(async (req, res) => {
  await pool.query('DELETE FROM site_logs');
  ok(res);
}));

// GET /api/admin/logs/stats — агрегированная статистика
app.get('/api/admin/logs/stats', requireAdmin, ah(async (req, res) => {
  const [byType, byIp, byDay] = await Promise.all([
    pool.query(`SELECT event_type, COUNT(*) as c FROM site_logs GROUP BY event_type ORDER BY c DESC`),
    pool.query(`SELECT ip, COUNT(*) as c FROM site_logs GROUP BY ip ORDER BY c DESC LIMIT 20`),
    pool.query(`SELECT DATE(created_at) as day, COUNT(*) as c FROM site_logs GROUP BY day ORDER BY day DESC LIMIT 30`),
  ]);

  ok(res, {
    byType: byType.rows,
    topIps: byIp.rows,
    byDay:  byDay.rows,
  });
}));

// ── 404 / GLOBAL ERROR HANDLER ───────────────────────────
app.use((req, res) => err(res, 'Not found', 404));

app.use((error, req, res, next) => {
  console.error('Express error handler:', error && error.message);
  if (res.headersSent) return next(error);
  err(res, 'Внутренняя ошибка сервера', 500);
});

const PORT = process.env.PORT || 3000;

async function ensureAdminPasswordBootstrap() {
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  if (rows[0]) return;

  const envPassword = process.env.ADMIN_INITIAL_PASSWORD;
  let initialPassword;
  if (isStr(envPassword) && envPassword.length >= 8) {
    initialPassword = envPassword;
    console.log('🔐 Пароль администратора установлен из переменной окружения ADMIN_INITIAL_PASSWORD.');
  } else {
    initialPassword = crypto.randomBytes(9).toString('base64url');
    console.log('🔐 ADMIN_INITIAL_PASSWORD не задан — сгенерирован случайный пароль администратора.');
    console.log(`🔐 ОДНОРАЗОВЫЙ ПАРОЛЬ ДЛЯ ВХОДА: ${initialPassword}`);
    console.log('🔐 Сохраните его сейчас и смените через раздел настроек сразу после входа.');
  }

  const hash = hashPassword(initialPassword);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO NOTHING`,
    [hash]
  );
}

// BUG FIX: создаём таблицу логов и колонки если их нет (миграция без пересоздания)
async function runMigrations() {
  // Таблица логов посетителей
  await pool.query(`
    CREATE TABLE IF NOT EXISTS site_logs (
      id          SERIAL PRIMARY KEY,
      ip          TEXT,
      user_agent  TEXT,
      referer     TEXT,
      path        TEXT,
      method      TEXT DEFAULT 'GET',
      country     TEXT DEFAULT '',
      event_type  TEXT DEFAULT 'visit',
      extra       TEXT,
      created_at  TEXT NOT NULL
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_logs_event  ON site_logs(event_type)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_logs_ip     ON site_logs(ip)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_logs_created ON site_logs(created_at DESC)`);

  // Добавляем колонки IP и UserAgent к orders если нет (для старых БД)
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS client_ip   TEXT DEFAULT '';
  `).catch(() => {});
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_agent  TEXT DEFAULT '';
  `).catch(() => {});

  // Инициализируем счётчик подписок базовым значением, если ещё не задан
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('subs_counter', $1) ON CONFLICT (key) DO NOTHING`,
    [String(SUBS_COUNTER_BASE)]
  );

  console.log('✅ Миграции выполнены.');
}

Promise.all([
  ensureAdminPasswordBootstrap(),
  runMigrations(),
]).catch((e) => {
  console.error('Ошибка при инициализации:', e);
}).finally(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});