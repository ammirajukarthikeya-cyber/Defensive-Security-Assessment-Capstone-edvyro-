const Database = require('better-sqlite3');
const path = require('path');
const { encryptSecret, decryptSecret } = require('../utils/crypto');

const DEFAULT_DB_PATH = path.join(__dirname, 'app.sqlite');

let db = null;

/**
 * Initialise the SQLite database and create tables if they don't exist.
 * Uses WAL journal mode for better concurrent-read performance (file databases),
 * and enforces foreign keys and parameterized statements.
 *
 * @param {string} [customPath] - Optional custom path or ':memory:' for tests
 */
function initDatabase(customPath) {
  const dbPath = customPath || process.env.DB_PATH || DEFAULT_DB_PATH;

  if (db) {
    try {
      db.close();
    } catch (_) {}
    db = null;
  }

  db = new Database(dbPath);

  // Performance & safety pragmas
  if (dbPath !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash   TEXT    NOT NULL,
      totp_secret     TEXT    DEFAULT NULL,
      totp_enabled    INTEGER DEFAULT 0,
      last_totp_token TEXT    DEFAULT NULL,
      created_at      TEXT    DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
  `);

  // Non-destructive schema migration check for existing databases
  try {
    const columns = db.pragma('table_info(users)').map((c) => c.name);
    if (!columns.includes('last_totp_token')) {
      db.exec('ALTER TABLE users ADD COLUMN last_totp_token TEXT DEFAULT NULL;');
    }
  } catch (_) {}

  return db;
}

/** Close active database connection */
function closeDatabase() {
  if (db) {
    try {
      db.close();
    } catch (_) {}
    db = null;
  }
}

/** Get active database connection */
function getDatabase() {
  if (!db) {
    return initDatabase();
  }
  return db;
}

// ---------------------------------------------------------------------------
// Prepared Statements (parameterised -> SQL-injection safe)
// ---------------------------------------------------------------------------

/** Insert a new user */
function createUser(username, email, passwordHash) {
  const conn = getDatabase();
  const stmt = conn.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  );
  return stmt.run(username, email, passwordHash);
}

/** Find user by username (case-insensitive via NOCASE collation) */
function findUserByUsername(username) {
  const conn = getDatabase();
  const stmt = conn.prepare('SELECT * FROM users WHERE username = ?');
  const user = stmt.get(username);
  if (user && user.totp_secret) {
    user._raw_totp_secret = user.totp_secret;
    user.totp_secret = decryptSecret(user.totp_secret);
  }
  return user;
}

/** Find user by email */
function findUserByEmail(email) {
  const conn = getDatabase();
  const stmt = conn.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);
  if (user && user.totp_secret) {
    user._raw_totp_secret = user.totp_secret;
    user.totp_secret = decryptSecret(user.totp_secret);
  }
  return user;
}

/** Find user by ID */
function findUserById(id) {
  const conn = getDatabase();
  const stmt = conn.prepare('SELECT * FROM users WHERE id = ?');
  const user = stmt.get(id);
  if (user && user.totp_secret) {
    user._raw_totp_secret = user.totp_secret;
    user.totp_secret = decryptSecret(user.totp_secret);
  }
  return user;
}

/** Find raw user record without automatic decryption (for cryptographic verification tests) */
function getRawUserById(id) {
  const conn = getDatabase();
  const stmt = conn.prepare('SELECT * FROM users WHERE id = ?');
  return stmt.get(id);
}

/** Save TOTP secret for a user (encrypted at rest using AES-256-GCM) */
function saveTotpSecret(userId, secret) {
  const conn = getDatabase();
  const encryptedSecret = encryptSecret(secret);
  const stmt = conn.prepare('UPDATE users SET totp_secret = ? WHERE id = ?');
  return stmt.run(encryptedSecret, userId);
}

/** Enable TOTP for a user */
function enableTotp(userId) {
  const conn = getDatabase();
  const stmt = conn.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?');
  return stmt.run(userId);
}

/** Disable TOTP for a user */
function disableTotp(userId) {
  const conn = getDatabase();
  const stmt = conn.prepare(
    'UPDATE users SET totp_enabled = 0, totp_secret = NULL, last_totp_token = NULL WHERE id = ?'
  );
  return stmt.run(userId);
}

/** Track last successfully verified TOTP token to prevent OTP replay attacks */
function updateLastTotpToken(userId, token) {
  const conn = getDatabase();
  const stmt = conn.prepare('UPDATE users SET last_totp_token = ? WHERE id = ?');
  return stmt.run(token, userId);
}

module.exports = {
  initDatabase,
  closeDatabase,
  getDatabase,
  createUser,
  findUserByUsername,
  findUserByEmail,
  findUserById,
  getRawUserById,
  saveTotpSecret,
  enableTotp,
  disableTotp,
  updateLastTotpToken,
};
