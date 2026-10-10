/**
 * Authentication middleware
 * Guards routes that require a logged-in (and optionally fully-2FA-verified) user.
 */

/**
 * requireAuth – user must have a session with userId set.
 * Used for routes that don't need 2FA verification (e.g., 2FA setup page).
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  next();
}

/**
 * requireFullAuth – user must be fully authenticated (past 2FA if enabled).
 * Used for protected dashboard routes.
 */
function requireFullAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  if (req.session.requires2FA) {
    return res.status(403).json({ error: 'Two-factor authentication required.' });
  }
  next();
}

module.exports = { requireAuth, requireFullAuth };
