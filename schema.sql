-- ============================================================
-- TIERS CLUB — D1 Database Schema
-- Запустить: wrangler d1 execute tiers-db --file=schema.sql
-- ============================================================

CREATE TABLE IF NOT EXISTS tiers (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  flag        TEXT DEFAULT '',
  highlight   INTEGER DEFAULT 0,
  price_rub   REAL DEFAULT 0,
  price_usdt  REAL DEFAULT 0,
  price_uah   REAL DEFAULT 0,
  price_stars REAL DEFAULT 0,
  period      TEXT DEFAULT '/ месяц',
  description TEXT DEFAULT '',
  features    TEXT DEFAULT '[]',  -- JSON array
  cta_text    TEXT DEFAULT 'Оформить',
  sort_order  INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
  id          TEXT PRIMARY KEY,
  tier_name   TEXT NOT NULL,
  method_id   TEXT NOT NULL,
  method_name TEXT NOT NULL,
  amount      TEXT NOT NULL,
  contact     TEXT NOT NULL,
  file_name   TEXT NOT NULL,
  file_type   TEXT NOT NULL,
  file_data   TEXT NOT NULL,  -- base64
  status      TEXT DEFAULT 'pending',  -- pending | approved | rejected
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Индексы для скорости
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tiers_order ON tiers(sort_order);

-- Дефолтные реквизиты
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('req_rubBank',          'Ozon Банк'),
  ('req_rubCard',          '2204321166536060'),
  ('req_rubCardsAccepted', 'Сбербанк, Тинькофф / Т-Банк, ВТБ, Альфа-Банк, Ozon Карта'),
  ('req_uahBank',          'Monobank'),
  ('req_uahCard',          '4441114432886206'),
  ('req_uahCardsAccepted', 'Monobank, ПриватБанк, Ощадбанк, ПУМБ'),
  ('req_tonAddress',       'UQDBLmmdgdLdkHhANV0pNY7PnDKPo_sp9p51e1XtX2ChgWME'),
  ('req_trcAddress',       'TRvgVquVHPaddvWRJL7p5z5phM2sLSQqsf'),
  ('req_starsNote',        'Напишите нам в Telegram — пришлём инвойс на нужную сумму прямо в чат.');

-- Дефолтные тарифы
INSERT OR IGNORE INTO tiers (id, name, flag, highlight, price_rub, price_usdt, price_uah, price_stars, period, description, features, cta_text, sort_order) VALUES
  ('t1', 'Базовый',    'старт',         0, 990,  11, 450,  250,  '/ месяц', 'Для тех, кто хочет для начала посмотреть, что внутри.', '["Базовая часть материалов","Доступ в общий чат","Сохранение контента разрешено"]', 'Оформить', 1),
  ('t2', 'Расширенный','чаще выбирают', 1, 2490, 27, 1100, 620,  '/ месяц', 'Полноценный доступ к закрытому разделу и большей части материалов.', '["Всё из предыдущего уровня","Расширенный архив","Обновления раз в месяц","Приоритет в поддержке"]', 'Оформить', 2),
  ('t3', 'Полный',     'максимум',      0, 5990, 65, 2700, 1490, '/ месяц', 'Весь доступ целиком, без ограничений и очереди на обновления.', '["Всё из предыдущего уровня","Полный архив без ограничений","Обновления каждую неделю","Личный менеджер"]', 'Оформить', 3);
