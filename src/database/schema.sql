-- ==========================================================
-- SECURE LOGIN SYSTEM: DATABASE SCHEMA
-- Designed with integrity constraints, indexes, and audit logging
-- ==========================================================

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  two_factor_enabled INTEGER NOT NULL DEFAULT 0,
  two_factor_secret TEXT DEFAULT NULL,
  backup_codes TEXT DEFAULT NULL,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  lockout_until TEXT DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
  updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS login_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER DEFAULT NULL,
  attempted_email TEXT NOT NULL,
  status TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  timestamp TEXT NOT NULL DEFAULT (DATETIME('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id ON login_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON login_audit_logs(timestamp);
