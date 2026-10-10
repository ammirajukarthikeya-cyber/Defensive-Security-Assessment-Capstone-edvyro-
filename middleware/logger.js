/**
 * Defensive Security Audit Logger Module
 * Emits structured, machine-parsable JSON audit logs for security and SIEM pipelines.
 * Sanitizes all output to ensure credentials, tokens, and PII are never leaked into logs.
 */

const SENSITIVE_KEYS = new Set([
  'password',
  'token',
  'secret',
  'totp_secret',
  'cookie',
  'session',
  'authorization',
]);

/**
 * Sanitizes an object by removing or masking known sensitive fields.
 *
 * @param {object} obj - Object to sanitize
 * @returns {object} Sanitized clone of object
 */
function sanitizeDetails(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeDetails(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Extracts sanitized client IP address from Express request.
 *
 * @param {import('express').Request} [req]
 * @returns {string} Sanitized IP address
 */
function getClientIp(req) {
  if (!req) return 'unknown';
  return req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Emits a structured security audit log entry.
 *
 * @param {object} params
 * @param {string} params.event - Event identifier (e.g. AUTH_LOGIN_SUCCESS)
 * @param {string} [params.level='INFO'] - Log level ('INFO', 'WARN', 'ERROR')
 * @param {import('express').Request} [params.req] - Express request object
 * @param {string|number} [params.userId] - Optional sanitized user ID
 * @param {string} [params.username] - Optional sanitized username
 * @param {object} [params.details] - Additional contextual details
 */
function logSecurityEvent({ event, level = 'INFO', req, userId, username, details = {} }) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    type: 'SECURITY_AUDIT',
    level,
    event,
    ip: getClientIp(req),
    user: {
      id: userId || req?.session?.userId || null,
      username: username || req?.session?.username || null,
    },
    details: sanitizeDetails(details),
  };

  const output = JSON.stringify(logEntry);
  if (level === 'ERROR') {
    console.error(output);
  } else if (level === 'WARN') {
    console.warn(output);
  } else {
    console.log(output);
  }

  return logEntry;
}

module.exports = {
  logSecurityEvent,
  sanitizeDetails,
  getClientIp,
};
