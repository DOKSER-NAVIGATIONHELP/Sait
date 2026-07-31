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
// в заголовке X-Forwarded-For. Без этой настройки req.ip будет IP
// прокси-сервера — и rate-limit будет считать всех посетителей одним "IP".
// BUG FIX: на Render несколько прокси-хопов, поэтому 'trust proxy', 1
// (доверять только одному ближнему хопу) брал внутренний адрес
// инфраструктуры вместо настоящего IP клиента. 'trust proxy', true говорит
// Express взять САМЫЙ ПЕРВЫЙ адрес в X-Forwarded-For — это и есть клиент.
app.set('trust proxy', true);

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

// Доверие устройства для входа в админку без пароля живёт 30 дней,
// затем автоматически сгорает и нужно снова 3 раза войти паролем.
const TRUSTED_DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET не задан в переменных окружения!');
}

// ── CORS ─────────────────────────────────────────────────
// SECURITY FIX: раньше был полностью открыт (Access-Control-Allow-Origin: *)
// без реальной необходимости. Ужесточаем: разрешаем только явно заданные
// источники через ALLOWED_ORIGIN(S) в переменных окружения; если не заданы —
// откатываемся к '*', но НЕ передаём Allow-Credentials с wildcard-origin
// (это запрещено спецификацией и браузерами всё равно проигнорируется).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.length) {
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Credentials', 'true');
    }
  } else {
    // Совместимость, если ALLOWED_ORIGINS не настроен — прежнее поведение
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── COOKIES (без внешней зависимости cookie-parser) ──────
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

const DEVICE_COOKIE_NAME = 'admin_device';

function setDeviceCookie(res, deviceId) {
  const isProd = process.env.NODE_ENV === 'production';
  // ВАЖНО: фронтенд и API живут на разных доменах (см. API_BASE на клиенте),
  // поэтому для кросс-доменной cookie обязательны SameSite=None и Secure —
  // иначе браузер её просто не отправит обратно. В dev (http, не prod)
  // SameSite=None без Secure браузеры блокируют, поэтому там используем Lax
  // (кросс-доменное доверие устройства в dev всё равно не нужно).
  const parts = [
    `${DEVICE_COOKIE_NAME}=${encodeURIComponent(deviceId)}`,
    'HttpOnly',
    'Path=/api/admin',
    `Max-Age=${Math.floor(TRUSTED_DEVICE_TTL_MS / 1000)}`,
  ];
  if (isProd) {
    parts.push('Secure', 'SameSite=None');
  } else {
    parts.push('SameSite=Lax');
  }
  res.append('Set-Cookie', parts.join('; '));
}

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

const UUID_RE_GLOBAL = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuidLike(v) { return typeof v === 'string' && UUID_RE_GLOBAL.test(v); }

const CLIENT_ID_RE = /^[a-zA-Z0-9_-]{8,100}$/;
function isClientId(v) { return typeof v === 'string' && CLIENT_ID_RE.test(v); }

function toNum(v, fallback = 0, min = 0, max = 1_000_000_000) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

// ── ПОЛУЧЕНИЕ IP ─────────────────────────────────────────
// BUG FIX: на Render (и похожих хостингах) запрос проходит через НЕСКОЛЬКО
// прокси-хопов, поэтому req.ip с trust proxy:1 брал предпоследний адрес из
// цепочки X-Forwarded-For — а это внутренний адрес инфраструктуры хостинга
// (10.x.x.x), а не настоящий IP посетителя. Реальный IP клиента — это ВСЕГДА
// первый адрес в списке X-Forwarded-For (браузер -> ... -> наш сервер).
// Поэтому читаем заголовок напрямую, а не полагаемся на req.ip.
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  let raw;
  if (xff) {
    // X-Forwarded-For может быть строкой "клиент, прокси1, прокси2, ..."
    raw = String(xff).split(',')[0].trim();
  } else {
    raw = req.ip || req.connection?.remoteAddress || 'unknown';
  }
  // Убираем IPv6-mapped IPv4 префикс, а также localhost IPv6 (::1) -> 127.0.0.1 для читаемости
  raw = raw.replace(/^::ffff:/, '');
  if (raw === '::1') raw = '127.0.0.1';
  return raw || 'unknown';
}

// ── ЧИСЛОВОЙ ID ПОЛЬЗОВАТЕЛЯ (1, 2, 3, ...) ──────────────
// Каждому браузеру/устройству выдаётся простой числовой ID при первом
// обращении. Используется вместо длинной случайной строки, чтобы в логах
// и в Telegram было сразу видно "Пользователь #7 нажал ...".
// clientKey — это старый строковый localStorage-идентификатор (или IP+UA
// как запасной вариант), по которому мы находим/создаём числовой ID.
async function getOrCreateNumericUserId(clientKey, req) {
  const key = isStr(clientKey, 200) ? clientKey : null;
  const ip = getClientIp(req);
  const ua = (req.headers['user-agent'] || '').slice(0, 300);

  if (key) {
    const existing = await pool.query('SELECT numeric_id FROM client_registry WHERE client_key = $1', [key]);
    if (existing.rows[0]) {
      await pool.query('UPDATE client_registry SET last_seen_at = $1, ip = $2 WHERE client_key = $3',
        [new Date().toISOString(), ip, key]);
      return existing.rows[0].numeric_id;
    }
  }

  // Новый пользователь — выдаём следующий по порядку номер (1, 2, 3, ...)
  const now = new Date().toISOString();
  const effectiveKey = key || `anon:${ip}:${crypto.randomBytes(6).toString('hex')}`;
  const inserted = await pool.query(
    `INSERT INTO client_registry (client_key, ip, user_agent, created_at, last_seen_at)
     VALUES ($1,$2,$3,$4,$4)
     ON CONFLICT (client_key) DO UPDATE SET last_seen_at = $4
     RETURNING numeric_id`,
    [effectiveKey, ip, ua, now]
  );
  const numericId = inserted.rows[0].numeric_id;

  // Уведомляем о новом пользователе в системе
  sendTelegram(
    [
      `<b>🆕 Новый пользователь в системе</b>`,
      `🆔 Пользователь: <b>#${numericId}</b>`,
      `🌐 IP: <code>${escHtml(ip)}</code>`,
      `📱 UA: ${escHtml(ua.slice(0, 150)) || '—'}`,
      `🕐 ${new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`,
    ].join('\n')
  );

  return numericId;
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
    const userNumericId = extra && extra.userNumericId ? Number(extra.userNumericId) : null;
    const extraJson = Object.keys(extra).length ? JSON.stringify(extra) : null;

    await pool.query(
      `INSERT INTO site_logs (ip, user_agent, referer, path, method, country, event_type, extra, created_at, user_numeric_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [ip, userAgent.slice(0, 500), referer.slice(0, 500), path.slice(0, 300), method, country.slice(0, 10), eventType, extraJson, new Date().toISOString(), userNumericId]
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
  visit:            '👁 Визит на страницу',
  request:          '🌐 API-запрос',
  click:            '👆 Клик по кнопке',
};

// Экранируем спецсимволы HTML, чтобы Telegram (parse_mode=HTML) не падал
// и не ломал разметку, если пользователь ввёл в поле "<" или "&"
function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Простая очередь отправки в Telegram: сообщения шлём одно за другим с
// небольшой паузой между ними. Это защищает от лимитов самого Telegram
// (у бота в группе лимит порядка 20 сообщений/минуту в один чат) — если
// вдруг будет всплеск кликов/визитов, сообщения не потеряются, а встанут
// в очередь и уйдут по порядку, просто с небольшой задержкой.
const TG_QUEUE = [];
let tgQueueRunning = false;
const TG_SEND_INTERVAL_MS = 1200; // ~50 сообщений/минуту — с запасом от лимита Telegram
const TG_QUEUE_MAX = 500; // защита от неограниченного роста очереди при долгом падении сети

async function tgQueueWorker() {
  if (tgQueueRunning) return;
  tgQueueRunning = true;
  try {
    while (TG_QUEUE.length) {
      const text = TG_QUEUE.shift();
      await tgSendNow(text);
      if (TG_QUEUE.length) await new Promise((r) => setTimeout(r, TG_SEND_INTERVAL_MS));
    }
  } finally {
    tgQueueRunning = false;
  }
}

async function tgSendNow(text) {
  if (!TG_TOKEN) return; // переменная не задана — молча пропускаем
  try {
    const resp = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        chat_id:    TG_CHAT,
        text:       text.slice(0, 4096),
        parse_mode: 'HTML',
      }),
    });
    if (resp.status === 429) {
      // Telegram сам просит подождать — уважаем retry_after и возвращаем сообщение в очередь
      let retryAfterSec = 5;
      try {
        const data = await resp.json();
        if (data?.parameters?.retry_after) retryAfterSec = Number(data.parameters.retry_after) || 5;
      } catch { /* игнорируем, используем дефолт */ }
      TG_QUEUE.unshift(text);
      await new Promise((r) => setTimeout(r, retryAfterSec * 1000));
    }
  } catch (e) {
    console.error('Telegram send error:', e.message);
  }
}

function sendTelegram(text) {
  if (!TG_TOKEN) return;
  if (TG_QUEUE.length >= TG_QUEUE_MAX) {
    // Очередь переполнена (например, Telegram долго недоступен) — не даём ей расти бесконечно
    console.error('Telegram queue overflow, dropping oldest message');
    TG_QUEUE.shift();
  }
  TG_QUEUE.push(text);
  tgQueueWorker();
}

// ПОЛЬЗОВАТЕЛЬ ПОПРОСИЛ: слать в Telegram максимально подробно и вообще всё,
// трафик маленький — спама можно не бояться. Поэтому шлём каждое событие,
// а не только "важные". Если понадобится обратно приглушить — верните
// проверку по TG_IMPORTANT.
async function logVisitAndNotify(req, eventType, extra = {}) {
  await logVisit(req, eventType, extra);

  const ip    = getClientIp(req);
  const ua    = (req.headers['user-agent'] || '—').slice(0, 150);
  const label = TG_EVENT_LABELS[eventType] || eventType;
  const now   = new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' });
  const path  = req.originalUrl || req.url || '';
  const referer = req.headers['referer'] || req.headers['referrer'] || '';
  const userTag = extra && extra.userNumericId ? `#${extra.userNumericId}` : '—';

  let lines = [
    `<b>${label}</b>`,
    `🆔 Пользователь: <b>${userTag}</b>`,
    `🕐 ${now} МСК`,
    `🌐 IP: <code>${ip}</code>`,
    `📄 Страница: <code>${escHtml(path)}</code>`,
  ];
  if (referer) lines.push(`↩️ Пришёл с: ${escHtml(String(referer).slice(0, 150))}`);
  lines.push(`📱 UA: ${escHtml(ua)}`);

  if (eventType === 'click' && extra) {
    lines.push(`👆 Кнопка: <b>${escHtml(extra.label || extra.action || '—')}</b>`);
    if (extra.section)  lines.push(`📍 Раздел: ${escHtml(extra.section)}`);
    if (extra.value)    lines.push(`💬 Значение: ${escHtml(String(extra.value).slice(0, 200))}`);
    if (extra.pagePath) lines.push(`🔗 Где на сайте: ${escHtml(extra.pagePath)}`);
  }

  if (eventType === 'order_submit' && extra) {
    lines.push(`📋 Тариф: ${escHtml(extra.tierName || '—')}`);
    lines.push(`💳 Способ: ${escHtml(extra.methodId || '—')}`);
    lines.push(`📞 Контакт: ${escHtml(extra.contact || '—')}`);
    lines.push(`🆔 ID заявки: <code>${escHtml(extra.orderId || '—')}</code>`);
  }

  sendTelegram(lines.join('\n'));
}

// Middleware: логируем каждый публичный запрос (не API-служебные).
// В Telegram шлём ТОЛЬКО реальные визиты на страницы сайта (человек открыл
// сайт/раздел). Фоновые API-запросы (/api/tiers, /api/subs-count,
// /api/bonus, /api/notifications и т.д.) происходят при каждой загрузке
// страницы автоматически и не несут полезной информации — их пишем только
// в БД (event_type='request') для статистики, но НЕ спамим ими Telegram.
app.use((req, res, next) => {
  const skip = req.path.startsWith('/api/admin') || req.method === 'OPTIONS';
  if (!skip) {
    const isPageVisit = req.method === 'GET' && !req.path.startsWith('/api/');
    if (isPageVisit) {
      logVisitAndNotify(req, 'visit');
    } else {
      logVisit(req, 'request'); // только в БД, без Telegram
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

const supportMsgLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много сообщений. Подождите немного.' },
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

// GET /api/bonus — текст бонус-блока на публичной странице
app.get('/api/bonus', ah(async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'bonus_%'");
  const bonus = {};
  rows.forEach(r => { bonus[r.key.replace('bonus_', '')] = r.value; });
  ok(res, { bonus });
}));

// GET /api/orders/mine — статус заявок текущего посетителя (по clientId из localStorage)
// Отдаём только безопасные поля: без file_data, ip, user_agent, contact — чтобы не спалить чужие данные
// даже если кто-то подставит чужой clientId (он не секрет, но лучше не отдавать лишнее).
app.get('/api/orders/mine', ah(async (req, res) => {
  const clientId = req.query.clientId;
  if (!isClientId(clientId)) return ok(res, { orders: [] });
  const { rows } = await pool.query(
    'SELECT id, tier_name, method_name, amount, status, created_at FROM orders WHERE client_id = $1 ORDER BY created_at DESC LIMIT 20',
    [clientId]
  );
  ok(res, { orders: rows });
}));

// POST /api/orders
app.post('/api/orders', ordersPerIpLimiter, globalOrdersLimiter, ah(async (req, res) => {
  const body = bodyOf(req);
  const { tierName, methodId, methodName, amount, contact, fileName, fileType, fileData, clientId } = body;

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
  if (clientId !== undefined && !isStr(String(clientId), 150)) {
    return err(res, 'Некорректный ID клиента');
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
    `INSERT INTO orders (id, tier_name, method_id, method_name, amount, contact, file_name, file_type, file_data, status, created_at, client_ip, user_agent, client_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, tierName, methodId, methodName || methodId, String(amount ?? ''), contact, fileName, fileType, fileData, 'pending', new Date().toISOString(), ip, userAgent, clientId ? String(clientId) : '']
  );

  // Логируем событие отправки заявки + уведомление в Telegram (с номером пользователя)
  const orderUserNumericId = await getOrCreateNumericUserId(clientId, req);
  await logVisitAndNotify(req, 'order_submit', {
    orderId: id, tierName, methodId, contact: contact.slice(0, 50),
    userNumericId: orderUserNumericId,
  });

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

// GET /api/notifications?clientId=... — проверить, есть ли непрочитанное личное уведомление от админа
// (используется для показа всплывающего окна поверх сайта, даже если чат не открыт)
app.get('/api/notifications', ah(async (req, res) => {
  const clientId = req.query.clientId;
  if (!isClientId(clientId)) return err(res, 'Некорректный ID клиента');
  const { rows } = await pool.query(
    `SELECT id, title, text, created_at FROM client_notifications
     WHERE client_id = $1 AND delivered = 0 ORDER BY created_at ASC LIMIT 5`,
    [clientId]
  );
  ok(res, { notifications: rows });
}));

// POST /api/notifications/ack — клиент подтверждает, что увидел уведомление (закрыл окно)
app.post('/api/notifications/ack', ah(async (req, res) => {
  const { clientId, id } = bodyOf(req);
  if (!isClientId(clientId) || !isStr(id, 100)) return err(res, 'Некорректные параметры');
  await pool.query(
    `UPDATE client_notifications SET delivered = 1 WHERE id = $1 AND client_id = $2`,
    [id, clientId]
  );
  ok(res);
}));

// ── ЧИСЛОВОЙ ID ПОЛЬЗОВАТЕЛЯ ──────────────────────────────

// POST /api/client-id/register — получить/создать числовой ID (1, 2, 3, ...)
// Фронт передаёт свой старый строковый localStorage ключ (clientKey), чтобы
// один и тот же браузер всегда получал один и тот же номер.
app.post('/api/client-id/register', ah(async (req, res) => {
  const { clientKey } = bodyOf(req);
  const numericId = await getOrCreateNumericUserId(clientKey, req);
  ok(res, { numericId });
}));

// POST /api/track — подробный лог действия пользователя на сайте
// (какая кнопка нажата, в каком разделе, какое значение и т.д.)
// Шлём и в БД, и в Telegram — намеренно без фильтрации по важности.
app.post('/api/track', ah(async (req, res) => {
  const body = bodyOf(req);
  const { label, action, section, value, pagePath, clientId, clientNumericId } = body;

  if (!isStr(label, 200) && !isStr(action, 200)) {
    return err(res, 'Не указано действие');
  }

  let userNumericId = toNum(clientNumericId, 0, 0, 1_000_000_000) || null;
  if (!userNumericId) {
    // На случай, если фронт ещё не успел получить числовой ID —
    // определяем/создаём его прямо тут же по clientKey.
    userNumericId = await getOrCreateNumericUserId(clientId, req);
  }

  await logVisitAndNotify(req, 'click', {
    label: isStr(label, 200) ? label : (isStr(action, 200) ? action : ''),
    action: isStr(action, 200) ? action : '',
    section: isStr(section, 200) ? section : '',
    value: value !== undefined ? String(value).slice(0, 300) : '',
    pagePath: isStr(pagePath, 300) ? pagePath : '',
    userNumericId,
  });

  ok(res, { userNumericId });
}));

// ── ТЕХ.ПОДДЕРЖКА (ЧАТ) — ПУБЛИЧНЫЕ РОУТЫ ────────────────

// GET /api/support/ticket?clientId=... — найти существующий тикет клиента (без создания)
app.get('/api/support/ticket', ah(async (req, res) => {
  const clientId = req.query.clientId;
  if (!isClientId(clientId)) return err(res, 'Некорректный ID клиента');
  const { rows } = await pool.query(
    'SELECT id, ticket_number, status, created_at, unread_client FROM support_tickets WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1',
    [clientId]
  );
  ok(res, { ticket: rows[0] || null });
}));

// GET /api/support/messages?ticketId=...&clientId=... — сообщения тикета (для клиента)
app.get('/api/support/messages', ah(async (req, res) => {
  const { ticketId, clientId } = req.query;
  if (!isUuidLike(ticketId) || !isClientId(clientId)) return err(res, 'Некорректные параметры');
  const { rows: tRows } = await pool.query('SELECT id FROM support_tickets WHERE id = $1 AND client_id = $2', [ticketId, clientId]);
  if (!tRows[0]) return err(res, 'Тикет не найден', 404);
  const { rows } = await pool.query(
    'SELECT id, sender, text, created_at FROM support_messages WHERE ticket_id = $1 ORDER BY created_at ASC LIMIT 500',
    [ticketId]
  );
  // Сбрасываем счётчик непрочитанных для клиента
  await pool.query('UPDATE support_tickets SET unread_client = 0 WHERE id = $1', [ticketId]);
  ok(res, { messages: rows });
}));

// POST /api/support/messages — отправить сообщение от клиента (создаёт тикет при необходимости)
app.post('/api/support/messages', supportMsgLimiter, ah(async (req, res) => {
  const body = bodyOf(req);
  const { clientId, ticketId, text } = body;
  if (!isClientId(clientId)) return err(res, 'Некорректный ID клиента');
  if (!isStr(text, 3000)) return err(res, 'Сообщение пустое или слишком длинное');

  let finalTicketId = ticketId;
  let isNewTicket = false;

  if (finalTicketId) {
    const { rows } = await pool.query('SELECT id FROM support_tickets WHERE id = $1 AND client_id = $2', [finalTicketId, clientId]);
    if (!rows[0]) finalTicketId = null;
  }

  const now = new Date().toISOString();

  if (!finalTicketId) {
    finalTicketId = crypto.randomUUID();
    isNewTicket = true;
    await pool.query(
      `INSERT INTO support_tickets (id, client_id, status, created_at, last_message_at, unread_admin, unread_client)
       VALUES ($1,$2,'open',$3,$3,1,0)`,
      [finalTicketId, clientId, now]
    );
  } else {
    await pool.query(
      `UPDATE support_tickets SET last_message_at = $1, unread_admin = unread_admin + 1, status = 'open' WHERE id = $2`,
      [now, finalTicketId]
    );
  }

  const msgId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO support_messages (id, ticket_id, sender, text, created_at) VALUES ($1,$2,'client',$3,$4)`,
    [msgId, finalTicketId, text, now]
  );

  if (isNewTicket) {
    const { rows: numRows } = await pool.query('SELECT ticket_number FROM support_tickets WHERE id = $1', [finalTicketId]);
    const ip = getClientIp(req);
    const supportUserNumericId = await getOrCreateNumericUserId(clientId, req);
    sendTelegram(
      [
        `<b>🆘 Новое обращение в поддержку #${numRows[0]?.ticket_number ?? '?'}</b>`,
        `🆔 Пользователь: <b>#${supportUserNumericId}</b>`,
        `🌐 IP: <code>${ip}</code>`,
        `💬 ${escHtml(String(text).slice(0, 300))}`,
      ].join('\n')
    );
  }

  ok(res, { ticketId: finalTicketId, messageId: msgId });
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

  // SECURITY FIX: раньше deviceId присылал клиент и мы ему доверяли —
  // это позволяло подделать/скопировать идентификатор устройства и
  // получить "доверие" без реального пароля (см. разбор уязвимости).
  // Теперь deviceId генерирует ТОЛЬКО сервер и хранит его в httpOnly-cookie,
  // которую JS на странице прочитать не может и скопировать некуда.
  const cookies = parseCookies(req);
  let deviceId = cookies[DEVICE_COOKIE_NAME];
  if (!isStr(deviceId, 150) || !/^[a-zA-Z0-9_-]{8,150}$/.test(deviceId)) {
    deviceId = crypto.randomBytes(24).toString('base64url');
  }

  // Логируем попытки входа + уведомление в Telegram
  await logVisitAndNotify(req, ok_ ? 'admin_login_ok' : 'admin_login_fail', { ip });

  const now = new Date().toISOString();
  const ua = (req.headers['user-agent'] || '').slice(0, 200);
  if (ok_) {
    // Успешный вход — увеличиваем счётчик подряд идущих успешных входов.
    // На 3-м подряд успехе устройство становится доверенным на TRUSTED_DEVICE_TTL_MS.
    const expiresAt = new Date(Date.now() + TRUSTED_DEVICE_TTL_MS).toISOString();
    await pool.query(
      `INSERT INTO admin_trusted_devices (device_id, success_count, trusted, label, ip, created_at, last_login_at, expires_at)
       VALUES ($1, 1, 0, $2, $3, $4, $4, NULL)
       ON CONFLICT (device_id) DO UPDATE SET
         success_count = admin_trusted_devices.success_count + 1,
         trusted = CASE WHEN admin_trusted_devices.success_count + 1 >= 3 THEN 1 ELSE admin_trusted_devices.trusted END,
         expires_at = CASE WHEN admin_trusted_devices.success_count + 1 >= 3 THEN $5 ELSE admin_trusted_devices.expires_at END,
         label = $2,
         ip = $3,
         last_login_at = $4`,
      [deviceId, ua, ip, now, expiresAt]
    );
    setDeviceCookie(res, deviceId);
  } else {
    // Неверный пароль сбрасывает серию для этого устройства и снимает доверие
    await pool.query(
      `INSERT INTO admin_trusted_devices (device_id, success_count, trusted, label, ip, created_at, last_login_at, expires_at)
       VALUES ($1, 0, 0, $2, $3, $4, $4, NULL)
       ON CONFLICT (device_id) DO UPDATE SET success_count = 0, trusted = 0, expires_at = NULL, label = $2, ip = $3, last_login_at = $4`,
      [deviceId, ua, ip, now]
    );
  }

  if (!ok_) return err(res, 'Неверный пароль', 401);

  // BUG FIX: JWT_SECRET может быть undefined при отсутствии env — защита
  if (!JWT_SECRET) return err(res, 'JWT_SECRET не настроен на сервере', 500);

  const token = signToken({ role: 'admin', exp: Date.now() + 12 * 60 * 60 * 1000 }, JWT_SECRET);
  ok(res, { token });
}));

// POST /api/admin/login-device — вход без пароля для доверенного устройства
// (после 3 успешных входов подряд с одного браузера код больше не запрашивается,
// доверие живёт TRUSTED_DEVICE_TTL_MS и продлевается при каждом использовании)
// SECURITY FIX: deviceId теперь читаем ТОЛЬКО из httpOnly-cookie, которую
// выставляет сам сервер при /api/admin/login. Тело запроса больше не
// участвует — клиент физически не может подставить чужой/угаданный ID.
app.post('/api/admin/login-device', loginLimiter, ah(async (req, res) => {
  const cookies = parseCookies(req);
  const deviceId = cookies[DEVICE_COOKIE_NAME];
  if (!isStr(deviceId, 150) || !/^[a-zA-Z0-9_-]{8,150}$/.test(deviceId)) {
    return err(res, 'Устройство не распознано', 401);
  }

  const { rows } = await pool.query('SELECT trusted, expires_at FROM admin_trusted_devices WHERE device_id = $1', [deviceId]);
  const device = rows[0];
  if (!device || device.trusted !== 1) {
    return err(res, 'Устройство не подтверждено', 401);
  }
  if (!device.expires_at || new Date(device.expires_at).getTime() < Date.now()) {
    // Доверие истекло — сбрасываем полностью, придётся снова 3 раза войти по паролю
    await pool.query(
      'UPDATE admin_trusted_devices SET trusted = 0, success_count = 0, expires_at = NULL WHERE device_id = $1',
      [deviceId]
    );
    return err(res, 'Срок доверия устройства истёк, войдите паролем', 401);
  }

  if (!JWT_SECRET) return err(res, 'JWT_SECRET не настроен на сервере', 500);

  const ip = getClientIp(req);
  const newExpiresAt = new Date(Date.now() + TRUSTED_DEVICE_TTL_MS).toISOString();
  await pool.query(
    'UPDATE admin_trusted_devices SET last_login_at = $1, expires_at = $2, ip = $3 WHERE device_id = $4',
    [new Date().toISOString(), newExpiresAt, ip, deviceId]
  );
  setDeviceCookie(res, deviceId); // продлеваем и cookie на клиенте

  await logVisitAndNotify(req, 'admin_login_ok', { ip, viaTrustedDevice: true });

  const token = signToken({ role: 'admin', exp: Date.now() + 12 * 60 * 60 * 1000 }, JWT_SECRET);
  ok(res, { token });
}));

// GET /api/admin/trusted-devices — список доверенных/отслеживаемых устройств
app.get('/api/admin/trusted-devices', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT device_id, success_count, trusted, label, ip, created_at, last_login_at, expires_at
     FROM admin_trusted_devices ORDER BY last_login_at DESC LIMIT 200`
  );
  ok(res, { devices: rows });
}));

// DELETE /api/admin/trusted-devices/:deviceId — отозвать одно устройство
app.delete('/api/admin/trusted-devices/:deviceId', requireAdmin, ah(async (req, res) => {
  const { deviceId } = req.params;
  if (!isStr(deviceId, 150) || !/^[a-zA-Z0-9_-]{8,150}$/.test(deviceId)) {
    return err(res, 'Некорректный идентификатор устройства');
  }
  await pool.query('DELETE FROM admin_trusted_devices WHERE device_id = $1', [deviceId]);
  ok(res);
}));

// DELETE /api/admin/trusted-devices — отозвать все доверенные устройства разом
app.delete('/api/admin/trusted-devices', requireAdmin, ah(async (req, res) => {
  await pool.query('DELETE FROM admin_trusted_devices');
  ok(res);
}));

// ── ADMIN PROTECTED ROUTES ───────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(v) { return typeof v === 'string' && UUID_RE.test(v); }

app.get('/api/admin/orders', requireAdmin, ah(async (req, res) => {
  const statusParam = req.query.status;
  const allowedStatus = ['all', 'pending', 'approved', 'rejected'];
  const status = (typeof statusParam === 'string' && allowedStatus.includes(statusParam)) ? statusParam : 'all';
  let query = 'SELECT id, tier_name, method_id, method_name, amount, contact, file_name, file_type, status, created_at, client_ip, user_agent, client_id FROM orders';
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

// POST /api/admin/orders/:id/notify — отправить личное всплывающее уведомление
// клиенту, который оформлял эту заявку (кнопка "Написать" в списке заявок)
app.post('/api/admin/orders/:id/notify', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { text } = bodyOf(req);
  if (!isStr(text, 2000)) return err(res, 'Текст уведомления пустой или слишком длинный');

  const { rows } = await pool.query('SELECT client_id FROM orders WHERE id = $1', [req.params.id]);
  const order = rows[0];
  if (!order) return err(res, 'Заявка не найдена', 404);
  if (!order.client_id) return err(res, 'У этой заявки нет привязанного клиента сайта — уведомление некому доставить');

  const notifId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO client_notifications (id, client_id, title, text, created_at, delivered)
     VALUES ($1,$2,$3,$4,$5,0)`,
    [notifId, order.client_id, 'Произошла ошибка', String(text), new Date().toISOString()]
  );
  ok(res, { id: notifId });
}));

// ── ТЕХ.ПОДДЕРЖКА (ЧАТ) — АДМИНСКИЕ РОУТЫ ────────────────

// GET /api/admin/support/tickets — список всех тикетов, новые сверху
app.get('/api/admin/support/tickets', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, ticket_number, client_id, status, created_at, last_message_at, unread_admin
     FROM support_tickets ORDER BY last_message_at DESC LIMIT 300`
  );
  ok(res, { tickets: rows });
}));

// GET /api/admin/support/tickets/:id/messages
app.get('/api/admin/support/tickets/:id/messages', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { rows: tRows } = await pool.query('SELECT id FROM support_tickets WHERE id = $1', [req.params.id]);
  if (!tRows[0]) return err(res, 'Тикет не найден', 404);
  const { rows } = await pool.query(
    'SELECT id, sender, text, created_at FROM support_messages WHERE ticket_id = $1 ORDER BY created_at ASC LIMIT 500',
    [req.params.id]
  );
  await pool.query('UPDATE support_tickets SET unread_admin = 0 WHERE id = $1', [req.params.id]);
  ok(res, { messages: rows });
}));

// POST /api/admin/support/tickets/:id/messages — ответ от лица поддержки
app.post('/api/admin/support/tickets/:id/messages', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { text } = bodyOf(req);
  if (!isStr(text, 3000)) return err(res, 'Сообщение пустое или слишком длинное');

  const { rows: tRows } = await pool.query('SELECT id FROM support_tickets WHERE id = $1', [req.params.id]);
  if (!tRows[0]) return err(res, 'Тикет не найден', 404);

  const now = new Date().toISOString();
  const msgId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO support_messages (id, ticket_id, sender, text, created_at) VALUES ($1,$2,'admin',$3,$4)`,
    [msgId, req.params.id, text, now]
  );
  await pool.query(
    `UPDATE support_tickets SET last_message_at = $1, unread_client = unread_client + 1 WHERE id = $2`,
    [now, req.params.id]
  );
  ok(res, { messageId: msgId });
}));

// PUT /api/admin/support/tickets/:id — изменить статус (open/closed)
app.put('/api/admin/support/tickets/:id', requireAdmin, ah(async (req, res) => {
  if (!isUuid(req.params.id)) return err(res, 'Не найдено', 404);
  const { status } = bodyOf(req);
  if (!['open', 'closed'].includes(status)) return err(res, 'Неверный статус');
  await pool.query('UPDATE support_tickets SET status = $1 WHERE id = $2', [status, req.params.id]);
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
  const allowed = ['rubBank', 'rubCard', 'rubCardsAccepted', 'uahBank', 'uahCard', 'uahCardsAccepted', 'xrocketLink', 'cryptobotLink', 'tonAddress', 'trcAddress', 'starsManager', 'starsNote'];
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

app.get('/api/admin/bonus', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'bonus_%'");
  const bonus = {};
  rows.forEach(r => { bonus[r.key.replace('bonus_', '')] = r.value; });
  ok(res, { bonus });
}));

app.put('/api/admin/bonus', requireAdmin, ah(async (req, res) => {
  const body = bodyOf(req);
  const allowed = ['title', 'btnText', 'modalTitle', 'modalText', 'link'];
  for (const key of allowed) {
    if (body[key] !== undefined && isStr(String(body[key]), 2000)) {
      await pool.query(
        `INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        ['bonus_' + key, String(body[key])]
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
  const allowedTypes = ['all', 'visit', 'request', 'order_submit', 'admin_login_ok', 'admin_login_fail', 'click'];
  const typeParam = req.query.type;
  const eventType = (typeParam && allowedTypes.includes(typeParam)) ? typeParam : 'all';

  // BUG FIX: limit/offset нужно приводить к числу безопасно
  const limit  = Math.min(toNum(req.query.limit, 100, 1, 500), 500);
  const offset = toNum(req.query.offset, 0, 0, 1_000_000);

  let query  = 'SELECT id, ip, user_agent, referer, path, method, country, event_type, extra, created_at, user_numeric_id FROM site_logs';
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
  // BUG FIX: колонка с числовым ID пользователя (для старых БД без неё)
  await pool.query(`ALTER TABLE site_logs ADD COLUMN IF NOT EXISTS user_numeric_id INTEGER;`).catch(() => {});
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_logs_user_num ON site_logs(user_numeric_id)`);

  // Таблица простых числовых ID пользователей: 1, 2, 3, ...
  // numeric_id — обычный SERIAL, поэтому первый когда-либо созданный
  // пользователь в системе гарантированно получает номер 1.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_registry (
      numeric_id   SERIAL PRIMARY KEY,
      client_key   TEXT UNIQUE NOT NULL,
      ip           TEXT DEFAULT '',
      user_agent   TEXT DEFAULT '',
      created_at   TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_client_registry_seen ON client_registry(last_seen_at DESC)`);

  // Таблицы тех.поддержки (чат)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_tickets (
      id              TEXT PRIMARY KEY,
      ticket_number   SERIAL,
      client_id       TEXT NOT NULL,
      status          TEXT NOT NULL DEFAULT 'open',
      created_at      TEXT NOT NULL,
      last_message_at TEXT NOT NULL,
      unread_admin    INTEGER NOT NULL DEFAULT 0,
      unread_client   INTEGER NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_support_tickets_client ON support_tickets(client_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_support_tickets_last   ON support_tickets(last_message_at DESC)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id          TEXT PRIMARY KEY,
      ticket_id   TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
      sender      TEXT NOT NULL,
      text        TEXT NOT NULL,
      created_at  TEXT NOT NULL
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_support_messages_ticket ON support_messages(ticket_id, created_at)`);

  // Добавляем колонки IP и UserAgent к orders если нет (для старых БД)
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS client_ip   TEXT DEFAULT '';
  `).catch(() => {});
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_agent  TEXT DEFAULT '';
  `).catch(() => {});
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS client_id   TEXT DEFAULT '';
  `).catch(() => {});

  // Таблица личных уведомлений от админа конкретному клиенту (кнопка "Написать" в заявках)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_notifications (
      id          TEXT PRIMARY KEY,
      client_id   TEXT NOT NULL,
      title       TEXT NOT NULL,
      text        TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      delivered   INTEGER NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_client_notif_client ON client_notifications(client_id, delivered)`);

  // Таблица доверенных устройств админки (чтобы не спрашивать пароль после 3 успешных входов подряд)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_trusted_devices (
      device_id     TEXT PRIMARY KEY,
      success_count INTEGER NOT NULL DEFAULT 0,
      trusted       INTEGER NOT NULL DEFAULT 0,
      created_at    TEXT NOT NULL,
      last_login_at TEXT NOT NULL
    )
  `);
  // BUG FIX: доверие устройства теперь истекает по TTL и хранит доп. инфо для UI отзыва
  await pool.query(`ALTER TABLE admin_trusted_devices ADD COLUMN IF NOT EXISTS expires_at TEXT;`).catch(() => {});
  await pool.query(`ALTER TABLE admin_trusted_devices ADD COLUMN IF NOT EXISTS label TEXT DEFAULT '';`).catch(() => {});
  await pool.query(`ALTER TABLE admin_trusted_devices ADD COLUMN IF NOT EXISTS ip TEXT DEFAULT '';`).catch(() => {});

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