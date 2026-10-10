const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const { app, setupTestDatabase, cleanupTestDatabase, getDatabase } = require('./test-helper');

describe('Defensive Control 1: Safe Password Storage & Hashing', () => {
  before(() => {
    setupTestDatabase();
  });

  after(() => {
    cleanupTestDatabase();
  });

  beforeEach(() => {
    const db = getDatabase();
    db.exec('DELETE FROM users;');
  });

  it('should store password as a salted bcrypt hash, never in plaintext', async () => {
    const rawPassword = 'StrongP@ssw0rd!2026';
    const payload = {
      username: 'alice_crypto',
      email: 'alice@example.com',
      password: rawPassword,
    };

    const res = await request(app)
      .post('/api/auth/register')
      .send(payload)
      .expect(201);

    // Verify API response does not expose the password or hash
    assert.strictEqual(res.body.user.username, 'alice_crypto');
    assert.strictEqual(res.body.user.email, 'alice@example.com');
    assert.strictEqual(res.body.user.password, undefined);
    assert.strictEqual(res.body.user.password_hash, undefined);

    // Query database directly to inspect stored representation
    const db = getDatabase();
    const userRow = db.prepare('SELECT * FROM users WHERE username = ?').get('alice_crypto');

    assert.ok(userRow, 'User row should exist in database');
    assert.notStrictEqual(userRow.password_hash, rawPassword, 'Password must not be stored in plaintext');

    // Verify bcrypt hash structure ($2a$ or $2b$ prefix)
    assert.match(userRow.password_hash, /^\$2[ab]\$\d{2}\$[./A-Za-z0-9]{53}$/, 'Must be a valid bcrypt hash');

    // Verify bcrypt.compare succeeds with correct password
    const isMatch = await bcrypt.compare(rawPassword, userRow.password_hash);
    assert.strictEqual(isMatch, true, 'Stored bcrypt hash must verify against correct password');

    // Verify bcrypt.compare fails with incorrect password
    const isWrongMatch = await bcrypt.compare('WrongPassword!123', userRow.password_hash);
    assert.strictEqual(isWrongMatch, false, 'Stored bcrypt hash must reject incorrect password');
  });

  it('should generate distinct salt and unique hashes for identical passwords', async () => {
    const commonPassword = 'IdenticalP@ssword1!';

    await request(app)
      .post('/api/auth/register')
      .send({ username: 'user_one', email: 'user1@example.com', password: commonPassword })
      .expect(201);

    await request(app)
      .post('/api/auth/register')
      .send({ username: 'user_two', email: 'user2@example.com', password: commonPassword })
      .expect(201);

    const db = getDatabase();
    const row1 = db.prepare('SELECT password_hash FROM users WHERE username = ?').get('user_one');
    const row2 = db.prepare('SELECT password_hash FROM users WHERE username = ?').get('user_two');

    assert.notStrictEqual(
      row1.password_hash,
      row2.password_hash,
      'Identical passwords must produce distinct hashes due to cryptographic salting'
    );
  });
});
