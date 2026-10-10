# 🔐 SecureVault — Hardened Authentication Service

[![Security Architecture: Defensive Controls](https://img.shields.io/badge/Security-OWASP%20ASVS%20Level%202-blue.svg)](AUTHENTICATION_SECURITY_NOTE.md)
[![Tests Passing](https://img.shields.io/badge/Tests-17%20passed-brightgreen.svg)](test/)
[![Private Safe](https://img.shields.io/badge/Repository-Private--Safe-success.svg)](.gitignore)

A production-grade, hardened local authentication service and single-page application (SPA) featuring defensive password storage, server-side schema validation, brute-force rate limiting, secure session lifecycles, and Two-Factor Authentication (2FA TOTP).

---

## 🛡️ Defensive Controls Implemented

| Control | Description | Primary Defense |
| :--- | :--- | :--- |
| **Password Hashing** | Passwords hashed using `bcrypt` (12 rounds) with dynamic salts. Never stored in plaintext. Length capped at 128 characters to thwart CPU DoS. | Offline Cracking / Rainbow Tables / CPU Exhaustion |
| **Server-Side Validation** | Strict input validation via `express-validator` enforcing length, character constraints, email normalization, and password complexity. | Malformed Inputs / Injection / XSS |
| **Secure Cookie Flags** | Session cookies issue `HttpOnly` (blocks JS access), `SameSite=Strict` (blocks CSRF), and configurable `Secure` (requires HTTPS). | Session Theft / CSRF / Network Sniffing |
| **Session Fixation Defense** | Automatic session ID regeneration (`req.session.regenerate()`) upon login and registration. | Session Hijacking / Fixation Attacks |
| **Session Expiry & Invalidation** | Strict 30-minute session lifetime, server-side destruction (`req.session.destroy()`), and client cookie clearing (`Expires=1970`) upon logout. | Zombie Sessions / Unauthorized Re-entry |
| **Rate Limiting & Throttling** | Multi-tier throttling via `express-rate-limit`: 10 auth attempts / 15 mins, protecting login, register, and 2FA challenge endpoints with HTTP 429. | Credential Stuffing / Brute-Force / OTP Guessing |
| **Generic Auth Errors** | Indistinguishable HTTP 401 error responses for non-existent users and wrong passwords. Dummy hash comparison eliminates timing side-channels. | Account & Username Enumeration |
| **Two-Factor Auth (TOTP)** | Optional RFC 6238 compliant time-based one-time passwords with QR code provisioning and rate-limited verification. | Single-Factor Compromise |

For full threat modeling and architecture analysis, see [AUTHENTICATION_SECURITY_NOTE.md](AUTHENTICATION_SECURITY_NOTE.md).

---

## 📁 Repository Structure

```text
secure-login-system/
├── db/                                # Database & Persistence layer
│   ├── .gitkeep                       # Keeps folder tracked without committing databases
│   └── database.js                    # Parameterized queries (SQL-injection immune)
├── middleware/                        # Express middleware
│   └── auth.js                        # Session & 2FA guards
├── public/                            # Static frontend client
│   ├── css/styles.css                 # Dark-mode glassmorphic interface
│   ├── js/app.js                      # Client logic & session countdown timer
│   ├── js/particles.js                # Canvas background animation
│   └── index.html                     # Single-page interface
├── routes/                            # API route controllers
│   ├── auth.js                        # Registration, login, logout, me endpoints
│   └── twofa.js                       # TOTP setup, verification, validate endpoints
├── test/                              # Automated integration test suite
│   ├── test-helper.js                 # Test environment & isolated database setup
│   ├── password-hashing.test.js       # Verifies bcrypt salting & plaintext exclusion
│   ├── input-validation.test.js       # Verifies schema validation & boundary checks
│   ├── session-security.test.js       # Verifies cookie flags, fixation defense & logout
│   ├── generic-errors.test.js         # Verifies enumeration defense & timing shields
│   ├── rate-limiting.test.js          # Verifies brute-force throttling & HTTP 429
│   └── twofa.test.js                  # Verifies TOTP lifecycle & access barriers
├── .env.example                       # Safe environment template (no secrets committed)
├── .gitignore                         # Comprehensive ignore rules (Private-Safe)
├── AUTHENTICATION_SECURITY_NOTE.md    # Defensive engineering & threat modeling note
├── THREAT_MODEL.md                    # Detailed STRIDE threat analysis document
├── package.json                       # Scripts and project dependencies
└── server.js                          # Express application configuration & security headers
```

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
* [Node.js](https://nodejs.org/) v18+ (tested on Node v24)
* NPM

### 2. Installation
```bash
# Install dependencies
npm install
```

### 3. Environment Configuration
Copy the template configuration file:
```bash
cp .env.example .env
```
Ensure `SESSION_SECRET` is set to a cryptographically strong random key for your deployment.

### 4. Running the Application
```bash
# Development mode with auto-reload:
npm run dev

# Production mode:
npm start
```
Navigate to `http://localhost:3000` in your web browser.

---

## 🧪 Running Automated Tests

Run the full automated test suite demonstrating all defensive controls:

```bash
npm test
```

For detailed specification output:
```bash
npm run test:verbose
```

### Test Coverage Highlights
* **Suite 1:** Safe Password Storage & Hashing (`test/password-hashing.test.js`)
* **Suite 2:** Server-Side Input Validation (`test/input-validation.test.js`)
* **Suite 3:** Secure Cookie Settings, Logout & Session Lifecycle (`test/session-security.test.js`)
* **Suite 4:** Generic Authentication Errors & Timing Mitigation (`test/generic-errors.test.js`)
* **Suite 5:** Rate Limiting & Brute-Force Throttling (`test/rate-limiting.test.js`)
* **Suite 6:** Two-Factor Authentication TOTP Flow (`test/twofa.test.js`)

---

## 🔒 Private-Safe Guarantee

This repository is designed to be **safe for private or public GitHub hosting**:
* **No committed credentials:** Secrets, tokens, and keys are strictly excluded via `.gitignore`.
* **No committed databases:** SQLite `.sqlite`, `.sqlite-shm`, `.sqlite-wal` files are ignored.
* **Production safety guard:** `server.js` refuses to start in `NODE_ENV=production` if insecure default secrets are detected.
