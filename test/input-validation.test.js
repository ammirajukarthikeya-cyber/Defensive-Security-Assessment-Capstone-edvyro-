const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, setupTestDatabase, cleanupTestDatabase, getDatabase } = require('./test-helper');

describe('Defensive Control 2: Server-Side Input Validation', () => {
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

  it('should reject registration when required fields are missing', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({})
      .expect(400);

    assert.ok(res.body.error, 'Response should contain error message');
    assert.ok(Array.isArray(res.body.errors), 'Response should provide field errors');
  });

  it('should reject usernames that are too short, too long, or contain invalid characters', async () => {
    // Too short (< 3 chars)
    let res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'ab', email: 'valid@example.com', password: 'ValidP@ssword1!' })
      .expect(400);
    assert.match(res.body.error, /Username must be 3-30 characters/);

    // Too long (> 30 chars)
    res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'a'.repeat(31), email: 'valid@example.com', password: 'ValidP@ssword1!' })
      .expect(400);
    assert.match(res.body.error, /Username must be 3-30 characters/);

    // Disallowed characters (XSS probe / special chars)
    res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'user<script>', email: 'valid@example.com', password: 'ValidP@ssword1!' })
      .expect(400);
    assert.match(res.body.error, /Username may only contain letters, numbers, and underscores/);
  });

  it('should reject malformed email addresses', async () => {
    const invalidEmails = ['plainaddress', 'missing@domain', '@missinguser.com', 'user@domain..com'];

    for (const email of invalidEmails) {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'valid_user', email, password: 'ValidP@ssword1!' })
        .expect(400);

      assert.match(res.body.error, /valid email address/i);
    }
  });

  it('should reject weak passwords failing complexity requirements', async () => {
    const weakPasswords = [
      { pass: 'Short1!', expected: /between 8 and 128 characters/i },
      { pass: 'nouppercase1!', expected: /uppercase letter/i },
      { pass: 'NOLOWERCASE1!', expected: /lowercase letter/i },
      { pass: 'NoNumberHere!', expected: /at least one number/i },
      { pass: 'NoSpecial1234', expected: /special character/i },
    ];

    for (const { pass, expected } of weakPasswords) {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: 'valid_user', email: 'valid@example.com', password: pass })
        .expect(400);

      assert.match(res.body.error, expected);
    }
  });

  it('should reject oversized passwords (>128 chars) to mitigate bcrypt DoS CPU exhaustion', async () => {
    const hugePassword = 'P@1' + 'a'.repeat(130);

    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'valid_user', email: 'valid@example.com', password: hugePassword })
      .expect(400);

    assert.match(res.body.error, /between 8 and 128 characters/i);
  });

  it('should reject duplicate usernames and emails with 409 Conflict', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'first_user', email: 'first@example.com', password: 'ValidP@ssword1!' })
      .expect(201);

    // Duplicate username
    const resUser = await request(app)
      .post('/api/auth/register')
      .send({ username: 'first_user', email: 'different@example.com', password: 'ValidP@ssword1!' })
      .expect(409);
    assert.strictEqual(resUser.body.error, 'Username is already taken.');

    // Duplicate email
    const resEmail = await request(app)
      .post('/api/auth/register')
      .send({ username: 'different_user', email: 'first@example.com', password: 'ValidP@ssword1!' })
      .expect(409);
    assert.strictEqual(resEmail.body.error, 'Email is already registered.');
  });

  it('should enforce input validation on login endpoints', async () => {
    // Missing username
    const res1 = await request(app)
      .post('/api/auth/login')
      .send({ password: 'SomePassword123!' })
      .expect(400);
    assert.match(res1.body.error, /Username is required/i);

    // Missing password
    const res2 = await request(app)
      .post('/api/auth/login')
      .send({ username: 'alice' })
      .expect(400);
    assert.match(res2.body.error, /Password is required/i);
  });
});
