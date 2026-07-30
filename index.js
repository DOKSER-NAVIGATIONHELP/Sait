// ============================================================
// TIERS CLUB — Cloudflare Worker API
// ============================================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }
function ok(data = {}) { return json({ ok: true, ...data }); }

// ── JWT-like signed token (HMAC-SHA256 via WebCrypto) ──────
async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const data = btoa(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const [data, sigB64] = token.split('.');
    if (!data || !sigB64) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, enc.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(data));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// bcrypt не доступен в Workers — используем PBKDF2
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, key, 256
  );
  const saltHex = [...salt].map(b => b.toString(16).padStart(2,'0')).join('');
  const hashHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2,'0')).join('');
  return `pbkdf2:${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  try {
    const [, saltHex, hashHex] = stored.split(':');
    const salt = Uint8Array.from(saltHex.match(/../g), h => parseInt(h,16));
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, key, 256
    );
    const check = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2,'0')).join('');
    return check === hashHex;
  } catch { return false; }
}

// ── Auth middleware ────────────────────────────────────────
async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return await verifyToken(token, env.JWT_SECRET);
}

// ── Route handler ──────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── PUBLIC ROUTES ──────────────────────────────────────

    // GET /api/tiers — список тарифов
    if (path === '/api/tiers' && method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM tiers ORDER BY sort_order ASC'
      ).all();
      // features хранится как JSON строка
      const tiers = results.map(t => ({
        ...t,
        features: JSON.parse(t.features || '[]'),
        highlight: t.highlight === 1,
      }));
      return ok({ tiers });
    }

    // GET /api/requisites — реквизиты для оплаты
    if (path === '/api/requisites' && method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT key, value FROM settings WHERE key LIKE "req_%"'
      ).all();
      const req = {};
      results.forEach(r => { req[r.key.replace('req_','')] = r.value; });
      return ok({ requisites: req });
    }

    // POST /api/orders — создать заявку
    if (path === '/api/orders' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }

      const { tierName, methodId, methodName, amount, contact, fileName, fileType, fileData } = body;
      if (!tierName || !methodId || !contact || !fileName || !fileData) {
        return err('Не все поля заполнены');
      }
      if (contact.length > 200) return err('Контакт слишком длинный');
      if (fileName.length > 200) return err('Имя файла слишком длинное');
      // Проверка base64 размера (примерно до 8 МБ)
      if (fileData.length > 11_000_000) return err('Файл слишком большой');
      // Проверка типа
      const allowed = ['image/jpeg','image/png','image/webp','application/pdf'];
      if (!allowed.includes(fileType)) return err('Недопустимый тип файла');

      const id = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO orders (id, tier_name, method_id, method_name, amount, contact, file_name, file_type, file_data, status, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(id, tierName, methodId, methodName, amount, contact, fileName, fileType, fileData, 'pending', new Date().toISOString()).run();

      return ok({ id });
    }

    // ── ADMIN AUTH ─────────────────────────────────────────

    // POST /api/admin/login
    if (path === '/api/admin/login' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const { password } = body;
      if (!password) return err('Пароль обязателен', 401);

      const row = await env.DB.prepare(
        'SELECT value FROM settings WHERE key = "admin_password_hash"'
      ).first();

      if (!row) {
        // Первый запуск — инициализируем дефолтный пароль
        const hash = await hashPassword('admin1234');
        await env.DB.prepare(
          'INSERT OR REPLACE INTO settings (key, value) VALUES ("admin_password_hash", ?)'
        ).bind(hash).run();
        // Проверяем введённый
        if (password !== 'admin1234') return err('Неверный пароль', 401);
      } else {
        const valid = await verifyPassword(password, row.value);
        if (!valid) return err('Неверный пароль', 401);
      }

      const token = await signToken(
        { role: 'admin', exp: Date.now() + 12 * 60 * 60 * 1000 }, // 12 часов
        env.JWT_SECRET
      );
      return ok({ token });
    }

    // ── ADMIN PROTECTED ROUTES ─────────────────────────────
    const isAdmin = path.startsWith('/api/admin/');

    if (isAdmin && path !== '/api/admin/login') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Не авторизован', 401);
    }

    // GET /api/admin/orders
    if (path === '/api/admin/orders' && method === 'GET') {
      const status = url.searchParams.get('status') || 'all';
      let query = 'SELECT id, tier_name, method_id, method_name, amount, contact, file_name, file_type, status, created_at FROM orders';
      if (status !== 'all') query += ' WHERE status = ?';
      query += ' ORDER BY created_at DESC';
      const stmt = status !== 'all'
        ? env.DB.prepare(query).bind(status)
        : env.DB.prepare(query);
      const { results } = await stmt.all();
      return ok({ orders: results });
    }

    // GET /api/admin/orders/:id/file — получить файл чека
    const fileMatch = path.match(/^\/api\/admin\/orders\/([^/]+)\/file$/);
    if (fileMatch && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Не авторизован', 401);
      const row = await env.DB.prepare(
        'SELECT file_data, file_type, file_name FROM orders WHERE id = ?'
      ).bind(fileMatch[1]).first();
      if (!row) return err('Не найдено', 404);
      const binary = Uint8Array.from(atob(row.file_data.split(',')[1] || row.file_data), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          'Content-Type': row.file_type,
          'Content-Disposition': `inline; filename="${row.file_name}"`,
          ...CORS,
        },
      });
    }

    // PUT /api/admin/orders/:id — изменить статус
    const orderMatch = path.match(/^\/api\/admin\/orders\/([^/]+)$/);
    if (orderMatch && method === 'PUT') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const { status } = body;
      if (!['pending','approved','rejected'].includes(status)) return err('Неверный статус');
      await env.DB.prepare(
        'UPDATE orders SET status = ? WHERE id = ?'
      ).bind(status, orderMatch[1]).run();
      return ok();
    }

    // DELETE /api/admin/orders/:id
    if (orderMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM orders WHERE id = ?').bind(orderMatch[1]).run();
      return ok();
    }

    // GET /api/admin/tiers
    if (path === '/api/admin/tiers' && method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM tiers ORDER BY sort_order ASC'
      ).all();
      return ok({ tiers: results.map(t => ({ ...t, features: JSON.parse(t.features||'[]'), highlight: t.highlight===1 })) });
    }

    // POST /api/admin/tiers
    if (path === '/api/admin/tiers' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const id = crypto.randomUUID();
      const { results: last } = await env.DB.prepare('SELECT MAX(sort_order) as m FROM tiers').all();
      const order = (last[0]?.m ?? 0) + 1;
      await env.DB.prepare(
        `INSERT INTO tiers (id, name, flag, highlight, price_rub, price_usdt, price_uah, price_stars, period, description, features, cta_text, sort_order)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        id, body.name||'', body.flag||'', body.highlight?1:0,
        body.priceRub||0, body.priceUsdt||0, body.priceUah||0, body.priceStars||0,
        body.period||'/ месяц', body.description||'',
        JSON.stringify(body.features||[]), body.ctaText||'Оформить', order
      ).run();
      return ok({ id });
    }

    // PUT /api/admin/tiers/:id
    const tierMatch = path.match(/^\/api\/admin\/tiers\/([^/]+)$/);
    if (tierMatch && method === 'PUT') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      await env.DB.prepare(
        `UPDATE tiers SET name=?, flag=?, highlight=?, price_rub=?, price_usdt=?, price_uah=?, price_stars=?, period=?, description=?, features=?, cta_text=? WHERE id=?`
      ).bind(
        body.name||'', body.flag||'', body.highlight?1:0,
        body.priceRub||0, body.priceUsdt||0, body.priceUah||0, body.priceStars||0,
        body.period||'/ месяц', body.description||'',
        JSON.stringify(body.features||[]), body.ctaText||'Оформить', tierMatch[1]
      ).run();
      return ok();
    }

    // DELETE /api/admin/tiers/:id
    if (tierMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM tiers WHERE id = ?').bind(tierMatch[1]).run();
      return ok();
    }

    // PUT /api/admin/tiers/:id/move
    const moveMatch = path.match(/^\/api\/admin\/tiers\/([^/]+)\/move$/);
    if (moveMatch && method === 'PUT') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const { direction } = body; // 'up' | 'down'
      const current = await env.DB.prepare('SELECT id, sort_order FROM tiers WHERE id = ?').bind(moveMatch[1]).first();
      if (!current) return err('Не найдено', 404);
      const neighbor = await env.DB.prepare(
        direction === 'up'
          ? 'SELECT id, sort_order FROM tiers WHERE sort_order < ? ORDER BY sort_order DESC LIMIT 1'
          : 'SELECT id, sort_order FROM tiers WHERE sort_order > ? ORDER BY sort_order ASC LIMIT 1'
      ).bind(current.sort_order).first();
      if (!neighbor) return ok();
      await env.DB.prepare('UPDATE tiers SET sort_order=? WHERE id=?').bind(neighbor.sort_order, current.id).run();
      await env.DB.prepare('UPDATE tiers SET sort_order=? WHERE id=?').bind(current.sort_order, neighbor.id).run();
      return ok();
    }

    // GET /api/admin/requisites
    if (path === '/api/admin/requisites' && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT key, value FROM settings WHERE key LIKE "req_%"').all();
      const req = {};
      results.forEach(r => { req[r.key.replace('req_','')] = r.value; });
      return ok({ requisites: req });
    }

    // PUT /api/admin/requisites
    if (path === '/api/admin/requisites' && method === 'PUT') {
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const allowed = ['rubBank','rubCard','rubCardsAccepted','uahBank','uahCard','uahCardsAccepted','tonAddress','trcAddress','starsNote'];
      for (const key of allowed) {
        if (body[key] !== undefined) {
          await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('req_'+key, body[key]).run();
        }
      }
      return ok();
    }

    // PUT /api/admin/password
    if (path === '/api/admin/password' && method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Не авторизован', 401);
      let body;
      try { body = await request.json(); } catch { return err('Invalid JSON'); }
      const { currentPassword, newPassword } = body;
      if (!newPassword || newPassword.length < 8) return err('Минимум 8 символов');

      const row = await env.DB.prepare('SELECT value FROM settings WHERE key = "admin_password_hash"').first();
      if (row) {
        const valid = await verifyPassword(currentPassword, row.value);
        if (!valid) return err('Неверный текущий пароль', 401);
      }
      const hash = await hashPassword(newPassword);
      await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES ("admin_password_hash", ?)').bind(hash).run();
      return ok();
    }

    // GET /api/admin/stats
    if (path === '/api/admin/stats' && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Не авторизован', 401);
      const pending = await env.DB.prepare('SELECT COUNT(*) as c FROM orders WHERE status="pending"').first();
      const approved = await env.DB.prepare('SELECT COUNT(*) as c FROM orders WHERE status="approved"').first();
      const total = await env.DB.prepare('SELECT COUNT(*) as c FROM orders').first();
      const tiers = await env.DB.prepare('SELECT COUNT(*) as c FROM tiers').first();
      return ok({ stats: {
        pending: pending.c, approved: approved.c,
        total: total.c, tiers: tiers.c
      }});
    }

    return err('Not found', 404);
  }
};
