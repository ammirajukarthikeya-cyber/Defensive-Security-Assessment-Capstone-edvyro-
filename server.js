require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { initDatabase } = require('./db/database');
const authRoutes = require('./routes/auth');
const twofaRoutes = require('./routes/twofa');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Database Initialization
// ---------------------------------------------------------------------------
initDatabase();

// ---------------------------------------------------------------------------
// Security Headers (Helmet)
// Mitigates Clickjacking, Cross-Site Scripting, MIME-sniffing, etc.
// ---------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// ---------------------------------------------------------------------------
// Rate Limiting (Defensive Brute-Force & Credential Stuffing Controls)
// ---------------------------------------------------------------------------
const generalWindowMs = parseInt(process.env.GENERAL_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const generalMax = parseInt(process.env.GENERAL_RATE_LIMIT_MAX, 10) || 100;

const generalLimiter = rateLimit({
  windowMs: generalWindowMs,
  max: generalMax,
  skip: (_req) => process.env.NODE_ENV === 'test' && process.env.TEST_ENABLE_RATE_LIMIT !== 'true',
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authWindowMs = parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const authMax = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10;

const authLimiter = rateLimit({
  windowMs: authWindowMs,
  max: authMax,
  skip: (_req) => process.env.NODE_ENV === 'test' && process.env.TEST_ENABLE_RATE_LIMIT !== 'true',
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// ---------------------------------------------------------------------------
// Body Parsing
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ---------------------------------------------------------------------------
// Session Management & Cookie Hardening
// ---------------------------------------------------------------------------
const sessionSecret = process.env.SESSION_SECRET || 'dev-insecure-session-key-change-me';
if (process.env.NODE_ENV === 'production' && sessionSecret === 'dev-insecure-session-key-change-me') {
  console.error('FATAL: Insecure default SESSION_SECRET cannot be used in production mode.');
  process.exit(1);
}

const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = isProduction || process.env.COOKIE_SECURE === 'true';
const sessionMaxAge = parseInt(process.env.SESSION_MAX_AGE_MS, 10) || 30 * 60 * 1000; // 30 minutes
const cookieName = process.env.SESSION_COOKIE_NAME || 'sid';

const sessionStore =
  process.env.NODE_ENV === 'test' && process.env.USE_MEMORY_STORE === 'true'
    ? new session.MemoryStore()
    : new SQLiteStore({
        db: process.env.SESSION_DB_NAME || 'sessions.sqlite',
        dir: process.env.SESSION_DB_DIR || path.join(__dirname, 'db'),
        concurrentDB: true,
      });

app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    name: cookieName,
    cookie: {
      httpOnly: true, // Mitigate XSS-based session hijacking
      secure: cookieSecure, // Enforce HTTPS-only cookie transmission
      sameSite: 'strict', // Mitigate Cross-Site Request Forgery (CSRF)
      maxAge: sessionMaxAge, // Inactivity / absolute session timeout
      path: '/',
    },
  })
);

// ---------------------------------------------------------------------------
// Static Assets
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/2fa/validate', authLimiter); // Protect 2FA challenge against brute-force guessing
app.use('/api/2fa', twofaRoutes);

// ---------------------------------------------------------------------------
// SPA Fallback (Single Page Application routing)
// ---------------------------------------------------------------------------
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Error Handling Middleware
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ---------------------------------------------------------------------------
// Start Server (Only when run directly, not when required by tests)
// ---------------------------------------------------------------------------
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🔐  Secure Login System running at http://localhost:${PORT}\n`);
  });
}

module.exports = app;
