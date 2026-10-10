const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, setupTestDatabase, cleanupTestDatabase, getDatabase } = require('./test-helper');

describe('Defensive Control 4: Generic Authentication Errors & Enumeration Mitigation', () => {
  before(() => {
    setupTestDatabase();
  });

  after(() => {
    cleanupTestDatabase();
  });

  beforeEach(async () => {
    const db = getDatabase();
    db.exec('DELETE FROM users;');

    // Seed one existing registered user
    await request(app)
      .post('/api/auth/register')
      .send({
        username: 'known_user',
        email: 'known@example.com',
        password: 'CorrectP@ssword1!',
      })
      .expect(201);
  });

  it('should return identical HTTP 401 and identical generic error message for non-existent username vs incorrect password', async () => {
    // Case A: Non-existent username
    const nonExistentRes = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'ghost_user_9999',
        password: 'SomePassword123!',
      })
      .expect(401);

    // Case B: Existing username with incorrect password
    const wrongPasswordRes = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'known_user',
        password: 'WrongPassword123!',
      })
      .expect(401);

    // Verify exact equality of status and error payload
    assert.strictEqual(nonExistentRes.status, 401);
    assert.strictEqual(wrongPasswordRes.status, 401);

    assert.strictEqual(
      nonExistentRes.body.error,
      'Invalid username or password.',
      'Must return generic error for unknown user'
    );
    assert.strictEqual(
      wrongPasswordRes.body.error,
      'Invalid username or password.',
      'Must return generic error for wrong password'
    );

    assert.deepStrictEqual(
      nonExistentRes.body,
      wrongPasswordRes.body,
      'Response bodies must be completely indistinguishable to thwart account enumeration'
    );
  });

  it('should not leak stack traces or internal implementation details on unhandled or malformed inputs', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: { $ne: null }, // Potential NoSQL / type juggling probe
        password: null,
      })
      .expect(400);

    assert.ok(res.body.error);
    assert.strictEqual(res.body.stack, undefined, 'Stack trace must not be leaked');
    assert.strictEqual(res.body.sql, undefined, 'SQL queries must not be leaked');
  });
});
