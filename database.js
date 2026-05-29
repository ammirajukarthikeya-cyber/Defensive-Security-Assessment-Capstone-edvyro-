const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'app.sqlite');

let db;

/**
 * Initialise the SQLite database and create tables if they don't exist.
 * Uses WAL journal mode for better concurrent-read performance.
 */
function initDatabase() {
  db = new Database(DB_PATH);

  // Performance & safety pragmas
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT    NOT NULL,
      totp_secret   TEXT    DEFAULT NULL,
      totp_enabled  INTEGER DEFAULT 0,
      created_at    TEXT    DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
  `);

  return db;
}

// ---------------------------------------------------------------------------
// Prepared Statements  (parameterised → SQL-injection safe)
// ---------------------------------------------------------------------------

/** Insert a new user */
function createUser(username, email, passwordHash) {
  const stmt = db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  );
  return stmt.run(username, email, passwordHash);
}

/** Find user by username */
function findUserByUsername(username) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  return stmt.get(username);
}

/** Find user by email */
function findUserByEmail(email) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  return stmt.get(email);
}

/** Find user by ID */
function findUserById(id) {
  const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
  return stmt.get(id);
}

/** Save TOTP secret for a user */
function saveTotpSecret(userId, secret) {
  const stmt = db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?');
  return stmt.run(secret, userId);
}

/** Enable TOTP for a user */
function enableTotp(userId) {
  const stmt = db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?');
  return stmt.run(userId);
}

/** Disable TOTP for a user */
function disableTotp(userId) {
  const stmt = db.prepare(
    'UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?'
  );
  return stmt.run(userId);
}

module.exports = {
  initDatabase,
  createUser,
  findUserByUsername,
  findUserByEmail,
  findUserById,
  saveTotpSecret,
  enableTotp,
  disableTotp,
};
