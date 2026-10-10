const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const {
  findUserById,
  saveTotpSecret,
  enableTotp,
  disableTotp,
  updateLastTotpToken,
} = require('../db/database');
const { requireAuth, requireFullAuth } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logger');

const router = express.Router();

const tokenValidation = [
  body('token')
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('Token must be a 6-digit number.')
    .isNumeric()
    .withMessage('Token must be a 6-digit number.'),
];

// ---------------------------------------------------------------------------
// POST /api/2fa/setup  –  Generate a TOTP secret & QR code
// ---------------------------------------------------------------------------
router.post('/setup', requireAuth, async (req, res) => {
  // Disallow access if a 2FA challenge is currently pending completion
  if (req.session.requires2FA) {
    return res.status(403).json({ error: 'Two-factor authentication required.' });
  }

  try {
    const user = findUserById(req.session.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    if (user.totp_enabled) {
      return res.status(400).json({ error: '2FA is already enabled.' });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `SecureLogin (${user.username})`,
      issuer: 'SecureLoginSystem',
      length: 20,
    });

    // Store encrypted secret in DB
    saveTotpSecret(user.id, secret.base32);

    // Generate QR code as data-URL
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    logSecurityEvent({
      event: 'AUTH_2FA_SETUP_INITIATED',
      req,
      userId: user.id,
      username: user.username,
      details: { step: 'qr_generated' },
    });

    res.json({
      message: 'Scan the QR code with your authenticator app, then verify with a token.',
      secret: secret.base32,
      qrCode: qrDataUrl,
    });
  } catch (err) {
    logSecurityEvent({
      event: 'SECURITY_SYSTEM_ERROR',
      level: 'ERROR',
      req,
      details: { action: '2fa_setup', message: err.message },
    });
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/2fa/verify  –  Verify token & enable 2FA
// ---------------------------------------------------------------------------
router.post(
  '/verify',
  requireAuth,
  tokenValidation,
  (req, res) => {
    if (req.session.requires2FA) {
      return res.status(403).json({ error: 'Two-factor authentication required.' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const user = findUserById(req.session.userId);
    if (!user || !user.totp_secret) {
      return res.status(400).json({ error: 'Please set up 2FA first.' });
    }
    if (user.totp_enabled) {
      return res.status(400).json({ error: '2FA is already enabled.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1, // allow ±30 s drift
    });

    if (!verified) {
      logSecurityEvent({
        event: 'AUTH_2FA_VERIFICATION_FAILED',
        level: 'WARN',
        req,
        userId: user.id,
        username: user.username,
      });
      return res.status(401).json({ error: 'Invalid token. Please try again.' });
    }

    enableTotp(user.id);
    req.session.requires2FA = false;

    logSecurityEvent({
      event: 'AUTH_2FA_ENABLED',
      req,
      userId: user.id,
      username: user.username,
    });

    res.json({ message: 'Two-factor authentication enabled successfully!' });
  }
);

// ---------------------------------------------------------------------------
// POST /api/2fa/validate  –  Validate TOTP during login
// ---------------------------------------------------------------------------
router.post(
  '/validate',
  requireAuth,
  tokenValidation,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    if (!req.session.requires2FA) {
      return res.status(400).json({ error: 'No 2FA challenge pending.' });
    }

    const user = findUserById(req.session.userId);
    if (!user || !user.totp_secret) {
      return res.status(400).json({ error: '2FA is not configured for this user.' });
    }

    // Defensive Token Replay Prevention
    if (user.last_totp_token === req.body.token) {
      logSecurityEvent({
        event: 'AUTH_2FA_REPLAY_ATTEMPT',
        level: 'WARN',
        req,
        userId: user.id,
        username: user.username,
        details: { endpoint: '/api/2fa/validate' },
      });
      return res.status(401).json({ error: 'Invalid or previously used 2FA token.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      logSecurityEvent({
        event: 'AUTH_2FA_CHALLENGE_FAILED',
        level: 'WARN',
        req,
        userId: user.id,
        username: user.username,
      });
      return res.status(401).json({ error: 'Invalid 2FA token.' });
    }

    // Mark token as consumed to prevent replay within validity window
    updateLastTotpToken(user.id, req.body.token);

    // Prevent Session Fixation: Regenerate session ID upon successful 2FA step completion
    const userId = user.id;
    const username = user.username;
    const email = user.email;

    req.session.regenerate((err) => {
      if (err) {
        logSecurityEvent({
          event: 'SECURITY_SYSTEM_ERROR',
          level: 'ERROR',
          req,
          details: { action: 'session_regenerate_2fa', message: err.message },
        });
        return res.status(500).json({ error: 'Session error.' });
      }

      req.session.userId = userId;
      req.session.username = username;
      req.session.requires2FA = false;

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: 'Session save error.' });
        }

        logSecurityEvent({
          event: 'AUTH_2FA_VALIDATED',
          req,
          userId,
          username,
        });

        res.json({
          message: 'Two-factor authentication verified!',
          user: { id: userId, username, email },
        });
      });
    });
  }
);

// ---------------------------------------------------------------------------
// POST /api/2fa/disable  –  Disable 2FA (requires valid token)
// ---------------------------------------------------------------------------
router.post(
  '/disable',
  requireFullAuth,
  tokenValidation,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const user = findUserById(req.session.userId);
    if (!user || !user.totp_enabled) {
      return res.status(400).json({ error: '2FA is not enabled.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      logSecurityEvent({
        event: 'AUTH_2FA_DISABLE_FAILED',
        level: 'WARN',
        req,
        userId: user.id,
        username: user.username,
      });
      return res.status(401).json({ error: 'Invalid token. Cannot disable 2FA.' });
    }

    disableTotp(user.id);

    logSecurityEvent({
      event: 'AUTH_2FA_DISABLED',
      req,
      userId: user.id,
      username: user.username,
    });

    res.json({ message: 'Two-factor authentication disabled.' });
  }
);

module.exports = router;
