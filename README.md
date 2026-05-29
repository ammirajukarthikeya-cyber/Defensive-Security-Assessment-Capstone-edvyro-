# 🔐 SecureVault — Secure Login & Authentication System

A premium, production-ready single-page web application (SPA) featuring a secure login, registration, and session management system built with **Node.js, Express, SQLite**, and vanilla client-side technologies. It features built-in **Two-Factor Authentication (2FA)** and follows industry-standard security practices to mitigate common web vulnerabilities.

---

## ✨ Features

### 🛡️ Core Security Architecture
* **Password Hashing:** Passwords are never stored in plain text. They are hashed using **bcrypt** with a work factor (cost) of 12 rounds, providing high resistance to offline brute-force and dictionary attacks.
* **SQL Injection Prevention:** The database layer uses `better-sqlite3`'s parameterized prepared statements, rendering SQL injection attacks impossible.
* **Session Fixation & Lifecycle Protection:**
  * Session IDs are automatically regenerated upon successful login and registration.
  * Sessions are persisted securely in a SQLite database store (`connect-sqlite3`).
  * Cookies are configured with security flags: `HttpOnly` (mitigates XSS-based cookie theft), `SameSite=Strict` (blocks Cross-Site Request Forgery - CSRF), and `Secure` (requires HTTPS in production).
  * Automatically counts down and enforces a 30-minute session expiry client-side and server-side.
* **Brute-Force & Rate Limiting:** Built-in endpoint throttling prevents automated credential stuffing:
  * General API rate limits (100 requests per 15 minutes).
  * Strict authentication limits (10 login attempts per 15 minutes per IP).
* **HTTP Header Protection:** Employs **Helmet** to set secure response headers (CSP, anti-clickjacking, X-XSS-Protection, etc.).
* **Two-Factor Authentication (2FA):** Optional user-enabled 2FA using Time-based One-Time Passwords (TOTP) compliant with RFC 6238 (supports Google Authenticator, Authy, Microsoft Authenticator).

### 🎨 Modern Dark-Glassmorphic UI
* Implements a state-of-the-art **Glassmorphism** dark mode layout using modern typography and smooth visual gradients.
* Real-time client-side **Password Strength Meter** evaluating length, casing, numbers, and special characters.
* Responsive, high-performance canvas **Particle Network background** reacting dynamically to cursor movements.
* User-friendly **interactive OTP inputs** featuring auto-advance focus, backspace backtrack navigation, and automatic 6-digit code pasting.
* Live-fading, dynamic toast notifications for feedback.

---

## 🛠️ Tech Stack

* **Backend:** Node.js, Express
* **Database & Sessions:** SQLite (`better-sqlite3`, `connect-sqlite3`)
* **Security & Auth:** `bcryptjs`, `speakeasy` (TOTP generation/verification), `express-rate-limit`, `helmet`, `express-validator`
* **Frontend:** HTML5, CSS3 Custom Properties, Vanilla JavaScript ES6 (No heavy frameworks or libraries required)

---

## 📁 File Structure

```text
secure-login-system/
├── db/                   # Database layer
│   ├── app.sqlite        # User credentials database (auto-created)
│   ├── database.js       # SQLite connections and parameterized actions
│   └── sessions.sqlite   # Session storage database (auto-created)
├── middleware/           # Express middlewares
│   └── auth.js           # Session and 2FA guards
├── public/               # Client-side static assets
│   ├── css/
│   │   └── styles.css    # Premium Glassmorphism stylesheet
│   ├── js/
│   │   ├── app.js        # Auth state router and AJAX API interaction
│   │   └── particles.js  # Canvas particle animation script
│   └── index.html        # Main single-page application markup
├── routes/               # Express endpoints
│   ├── auth.js           # Login, registration, and logout handlers
│   └── twofa.js          # TOTP setup, verification, validation, & disabling
├── server.js             # Express app config, rate limiters, & security headers
└── package.json          # Node dependencies
```

---

## 🚀 Setup & Installation

### Prerequisites
* [Node.js](https://nodejs.org/) (v16 or higher recommended)
* NPM (comes bundled with Node)

### Installation Steps

1. **Clone or copy the files** to your local environment.
2. Navigate to the project root directory:
   ```bash
   cd secure-login-system
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

---

## 💻 Running the App

### Development Mode
Runs the server with hot-reloading using Node's native watch utility:
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

Once started, open your browser and navigate to **`http://localhost:3000`**.

---

## 🔒 Recommended Security Adjustments for Production

1. **Session Secret:** In `server.js`, configure the `SESSION_SECRET` session setting using a secure environment variable (e.g., using `dotenv`):
   ```javascript
   secret: process.env.SESSION_SECRET || 'your-production-safe-random-long-key'
   ```
2. **HTTPS Redirection:** Ensure the site runs behind SSL/TLS (HTTPS). When `NODE_ENV` is set to `'production'`, cookies will automatically have their `secure` attribute set to `true`, preventing them from being transmitted over unencrypted HTTP.
3. **HTTP Strict Transport Security (HSTS):** Set Helmet's HSTS header to enforce HTTPS-only connections.
