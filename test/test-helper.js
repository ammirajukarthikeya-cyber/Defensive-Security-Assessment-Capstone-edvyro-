const path = require('path');
const fs = require('fs');

// Configure test environment variables before requiring app
process.env.NODE_ENV = 'test';
process.env.BCRYPT_ROUNDS = '4'; // Fast rounds for tests while fully verifying bcrypt
process.env.SESSION_SECRET = 'test-suite-secure-secret-key-0987654321';
process.env.SESSION_COOKIE_NAME = 'sid';
process.env.COOKIE_SECURE = 'false';
process.env.AUTH_RATE_LIMIT_WINDOW_MS = '60000'; // 1 minute
process.env.AUTH_RATE_LIMIT_MAX = '5'; // 5 attempts threshold for rate limit test

const TEST_DB_PATH = path.join(__dirname, 'test_app.sqlite');
const TEST_SESSIONS_DIR = __dirname;
const TEST_SESSIONS_DB = 'test_sessions.sqlite';

process.env.DB_PATH = TEST_DB_PATH;
process.env.SESSION_DB_DIR = TEST_SESSIONS_DIR;
process.env.SESSION_DB_NAME = TEST_SESSIONS_DB;

const { initDatabase, closeDatabase, getDatabase } = require('../db/database');
const app = require('../server');

function setupTestDatabase() {
  cleanupTestDatabase();
  initDatabase(TEST_DB_PATH);
}

function cleanupTestDatabase() {
  closeDatabase();
  const filesToDelete = [
    TEST_DB_PATH,
    `${TEST_DB_PATH}-wal`,
    `${TEST_DB_PATH}-shm`,
    path.join(TEST_SESSIONS_DIR, TEST_SESSIONS_DB),
    path.join(TEST_SESSIONS_DIR, `${TEST_SESSIONS_DB}-wal`),
    path.join(TEST_SESSIONS_DIR, `${TEST_SESSIONS_DB}-shm`),
  ];
  for (const f of filesToDelete) {
    if (fs.existsSync(f)) {
      try {
        fs.unlinkSync(f);
      } catch (_) {}
    }
  }
}

module.exports = {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  getDatabase,
  TEST_DB_PATH,
};
