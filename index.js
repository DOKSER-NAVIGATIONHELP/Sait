// ============================================================
// TIERS CLUB — Express API (для Render)
// Портировано с Cloudflare Worker
// ============================================================

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '15mb' })); // файлы чеков идут как base64 в JSON

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // требуется для Render Postgres
});

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

// ── Токен (HMAC-SHA256, аналог signToken/verifyToken из Worker) ──
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
    // защита от timing-атак
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ── Пароли (PBKDF2, как было в Worker) ──────────────────
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
  return verifyToken(token, JWT_SECRET);
}

function requireAdmin(req, res, next) {
  const payload = requireAuth(req);
  if (!payload) return err(res, 'Не авторизован', 401);
  req.admin = payload;
  next();
}

// ── PUBLIC ROUTES ────────────────────────────────────────

// GET /api/tiers
app.get('/api/tiers', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tiers ORDER BY sort_order ASC');
  const tiers = rows.map(t => ({
    ...t,
    features: JSON.parse(t.features || '[]'),
    highlight: t.highlight === 1,
  }));
  ok(res, { tiers });
});

// GET /api/requisites
app.get('/api/requisites', async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'req_%'");
  const req_ = {};
  rows.forEach(r => { req_[r.key.replace('req_', '')] = r.value; });
  ok(res, { requisites: req_ });
});

// POST /api/orders
app.post('/api/orders', async (req, res) => {
  const { tierName, methodId, methodName, amount, contact, fileName, fileType, fileData } = req.body;
  if (!tierName || !methodId || !contact || !fileName || !fileData) {
    return err(res, 'Не все поля заполнены');
  }
  if (contact.length > 200) return err(res, 'Контакт слишком длинный');
  if (fileName.length > 200) return err(res, 'Имя файла слишком длинное');
  if (fileData.length > 11_000_000) return err(res, 'Файл слишком большой');
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (!allowed.includes(fileType)) return err(res, 'Недопустимый тип файла');

  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO orders (id, tier_name, method_id, method_name, amount, contact, file_name, file_type, file_data, status, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [id, tierName, methodId, methodName, amount, contact, fileName, fileType, fileData, 'pending', new Date().toISOString()]
  );
  ok(res, { id });
});

// ── ADMIN AUTH ───────────────────────────────────────────

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return err(res, 'Пароль обязателен', 401);

  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  const row = rows[0];

  if (!row) {
    const hash = hashPassword('admin1234');
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [hash]
    );
    if (password !== 'admin1234') return err(res, 'Неверный пароль', 401);
  } else {
    if (!verifyPassword(password, row.value)) return err(res, 'Неверный пароль', 401);
  }

  const token = signToken({ role: 'admin', exp: Date.now() + 12 * 60 * 60 * 1000 }, JWT_SECRET);
  ok(res, { token });
});

// ── ADMIN PROTECTED ROUTES ───────────────────────────────

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const status = req.query.status || 'all';
  let query = 'SELECT id, tier_name, method_id, method_name, amount, contact, file_name, file_type, status, created_at FROM orders';
  const params = [];
  if (status !== 'all') { query += ' WHERE status = $1'; params.push(status); }
  query += ' ORDER BY created_at DESC';
  const { rows } = await pool.query(query, params);
  ok(res, { orders: rows });
});

app.get('/api/admin/orders/:id/file', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT file_data, file_type, file_name FROM orders WHERE id = $1',
    [req.params.id]
  );
  const row = rows[0];
  if (!row) return err(res, 'Не найдено', 404);
  const raw = row.file_data.includes(',') ? row.file_data.split(',')[1] : row.file_data;
  const binary = Buffer.from(raw, 'base64');
  res.set({
    'Content-Type': row.file_type,
    'Content-Disposition': `inline; filename="${row.file_name}"`,
  });
  res.send(binary);
});

app.put('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['pending', 'approved', 'rejected'].includes(status)) return err(res, 'Неверный статус');
  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
  ok(res);
});

app.delete('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
  ok(res);
});

app.get('/api/admin/tiers', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tiers ORDER BY sort_order ASC');
  ok(res, { tiers: rows.map(t => ({ ...t, features: JSON.parse(t.features || '[]'), highlight: t.highlight === 1 })) });
});

app.post('/api/admin/tiers', requireAdmin, async (req, res) => {
  const body = req.body;
  const id = crypto.randomUUID();
  const { rows: last } = await pool.query('SELECT MAX(sort_order) as m FROM tiers');
  const order = (last[0]?.m ?? 0) + 1;
  await pool.query(
    `INSERT INTO tiers (id, name, flag, highlight, price_rub, price_usdt, price_uah, price_stars, period, description, features, cta_text, sort_order)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id, body.name || '', body.flag || '', body.highlight ? 1 : 0,
     body.priceRub || 0, body.priceUsdt || 0, body.priceUah || 0, body.priceStars || 0,
     body.period || '/ месяц', body.description || '',
     JSON.stringify(body.features || []), body.ctaText || 'Оформить', order]
  );
  ok(res, { id });
});

app.put('/api/admin/tiers/:id', requireAdmin, async (req, res) => {
  const body = req.body;
  await pool.query(
    `UPDATE tiers SET name=$1, flag=$2, highlight=$3, price_rub=$4, price_usdt=$5, price_uah=$6, price_stars=$7, period=$8, description=$9, features=$10, cta_text=$11 WHERE id=$12`,
    [body.name || '', body.flag || '', body.highlight ? 1 : 0,
     body.priceRub || 0, body.priceUsdt || 0, body.priceUah || 0, body.priceStars || 0,
     body.period || '/ месяц', body.description || '',
     JSON.stringify(body.features || []), body.ctaText || 'Оформить', req.params.id]
  );
  ok(res);
});

app.delete('/api/admin/tiers/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM tiers WHERE id = $1', [req.params.id]);
  ok(res);
});

app.put('/api/admin/tiers/:id/move', requireAdmin, async (req, res) => {
  const { direction } = req.body; // 'up' | 'down'
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
});

app.get('/api/admin/requisites', requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT key, value FROM settings WHERE key LIKE 'req_%'");
  const req_ = {};
  rows.forEach(r => { req_[r.key.replace('req_', '')] = r.value; });
  ok(res, { requisites: req_ });
});

app.put('/api/admin/requisites', requireAdmin, async (req, res) => {
  const body = req.body;
  const allowed = ['rubBank', 'rubCard', 'rubCardsAccepted', 'uahBank', 'uahCard', 'uahCardsAccepted', 'tonAddress', 'trcAddress', 'starsNote'];
  for (const key of allowed) {
    if (body[key] !== undefined) {
      await pool.query(
        `INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        ['req_' + key, body[key]]
      );
    }
  }
  ok(res);
});

app.put('/api/admin/password', requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return err(res, 'Минимум 8 символов');

  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  const row = rows[0];
  if (row) {
    if (!verifyPassword(currentPassword, row.value)) return err(res, 'Неверный текущий пароль', 401);
  }
  const hash = hashPassword(newPassword);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [hash]
  );
  ok(res);
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const pending = await pool.query("SELECT COUNT(*) as c FROM orders WHERE status='pending'");
  const approved = await pool.query("SELECT COUNT(*) as c FROM orders WHERE status='approved'");
  const total = await pool.query('SELECT COUNT(*) as c FROM orders');
  const tiers = await pool.query('SELECT COUNT(*) as c FROM tiers');
  ok(res, {
    stats: {
      pending: Number(pending.rows[0].c),
      approved: Number(approved.rows[0].c),
      total: Number(total.rows[0].c),
      tiers: Number(tiers.rows[0].c),
    }
  });
});

app.use((req, res) => err(res, 'Not found', 404));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
