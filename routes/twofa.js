const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const {
  findUserById,
  saveTotpSecret,
  enableTotp,
  disableTotp,
} = require('../db/database');
const { requireAuth, requireFullAuth } = require('../middleware/auth');

const router = express.Router();

// ---------------------------------------------------------------------------
// POST /api/2fa/setup  –  Generate a TOTP secret & QR code
// ---------------------------------------------------------------------------
router.post('/setup', requireAuth, async (req, res) => {
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

    // Store the base32 secret (not yet enabled)
    saveTotpSecret(user.id, secret.base32);

    // Generate QR code as data-URL
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      message: 'Scan the QR code with your authenticator app, then verify with a token.',
      secret: secret.base32,
      qrCode: qrDataUrl,
    });
  } catch (err) {
    console.error('2FA setup error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/2fa/verify  –  Verify token & enable 2FA
// ---------------------------------------------------------------------------
router.post(
  '/verify',
  requireAuth,
  [body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Token must be a 6-digit number.')],
  (req, res) => {
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
      return res.status(401).json({ error: 'Invalid token. Please try again.' });
    }

    enableTotp(user.id);
    req.session.requires2FA = false;
    res.json({ message: 'Two-factor authentication enabled successfully!' });
  }
);

// ---------------------------------------------------------------------------
// POST /api/2fa/validate  –  Validate TOTP during login
// ---------------------------------------------------------------------------
router.post(
  '/validate',
  requireAuth,
  [body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Token must be a 6-digit number.')],
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

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid 2FA token.' });
    }

    req.session.requires2FA = false;
    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ error: 'Session save error.' });
      }
      res.json({
        message: 'Two-factor authentication verified!',
        user: { id: user.id, username: user.username, email: user.email },
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
  [body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Token must be a 6-digit number.')],
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
      return res.status(401).json({ error: 'Invalid token. Cannot disable 2FA.' });
    }

    disableTotp(user.id);
    res.json({ message: 'Two-factor authentication disabled.' });
  }
);

module.exports = router;
