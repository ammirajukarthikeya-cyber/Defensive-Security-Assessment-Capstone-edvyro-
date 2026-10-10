# 🛡️ Defensive Security Assessment Capstone

**Course / Platform:** Edvyro Cyber Security  
**Project:** Defensive Security Assessment Capstone  
**Repository:** [Defensive-Security-Assessment-Capstone-edvyro-](https://github.com/ammirajukarthikeya-cyber/Defensive-Security-Assessment-Capstone-edvyro-)  
**Target Application:** SecureVault Authentication & Session Management Service (`secure-login-system`)  
**Lead Assessor:** ammirajukarthikeya-cyber  
**Standard Compliance:** OWASP WSTG v4.2, NIST SP 800-115, NIST SP 800-63B  
**Assessment Status:** Remediated & 100% Verified  

---

## 📌 Executive Summary & Assessment Objectives

This capstone project demonstrates an end-to-end, authorized defensive security assessment of an internal Node.js/Express web application. The assessment methodology is strictly ethical and evidence-based, spanning:

1. **Ethical Scoping, Written Authorization & Rules of Engagement (RoE):** Defined strict loopback boundaries, privacy safeguards, and non-destructive protocols.
2. **Defensive Assessment across 5 Core Domains:** Audited **Configuration**, **Authentication**, **Input Validation**, **Dependencies**, and **Logging & Monitoring**.
3. **Evidence-Based Technical Findings:** Identified and cataloged 10 reproducible vulnerabilities (including Critical supply chain CVEs, weak CSP, 2FA session fixation, plaintext TOTP secret storage, and OTP replay).
4. **Defensive Source-Code Remediation:** Patched all Critical and High risks using defensive programming, authenticated AES-256-GCM encryption, session regeneration, and SIEM-grade audit telemetry.
5. **Retest Verification:** Developed automated regression assertions with **24 passing security tests across 11 test suites (100% pass rate)**.

---

## 📊 Security Posture: Baseline vs. Remediated

```
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                 SECURITY ASSESSMENT METRICS                              ║
╠═══════════════════════════════╦══════════════════════════╦═══════════════════════════════╣
║ Metric                        ║ Pre-Assessment Baseline  ║ Post-Remediation Verification ║
╠═══════════════════════════════╬══════════════════════════╬═══════════════════════════════╣
║ Critical Vulnerabilities      ║ 2                        ║ 0 (100% Remediated)           ║
║ High Vulnerabilities          ║ 4                        ║ 0 (100% Remediated)           ║
║ Medium Vulnerabilities        ║ 3                        ║ 0 (100% Remediated)           ║
║ Low Vulnerabilities           ║ 1                        ║ 1 (Isolated build tool)       ║
║ Automated Security Tests      ║ 17 passing               ║ 24 passing (0 failures)       ║
║ Transitive Dependency CVEs    ║ 14 CVEs                  ║ 0 Critical, 0 High, 0 Mod     ║
║ Test Pass Rate                ║ Baseline                 ║ 100% PASS (24 / 24)           ║
╚═══════════════════════════════╩══════════════════════════╩═══════════════════════════════╝
```

---

## 🗺️ Architecture & Level 1 Data Flow Diagram (DFD)

```mermaid
flowchart TD
    classDef actorStyle fill:#2C3E50,stroke:#1A252F,stroke-width:2px,color:#FFFFFF;
    classDef perimeterStyle fill:#E67E22,stroke:#D35400,stroke-width:2px,color:#FFFFFF;
    classDef appStyle fill:#2980B9,stroke:#1F618D,stroke-width:2px,color:#FFFFFF;
    classDef dataStyle fill:#27AE60,stroke:#1E8449,stroke-width:2px,color:#FFFFFF;

    subgraph Zone0["Zone 0: Public Network (Untrusted)"]
        User["Client Browser"]:::actorStyle
        Attacker["Threat Actor"]:::actorStyle
    end

    TB1["== Trust Boundary 1: Perimeter Edge =="]

    subgraph Zone1["Zone 1: Ingress & Perimeter Defense"]
        Helmet["Helmet CSP & Security Headers"]:::perimeterStyle
        RateLimiter["express-rate-limit Ingress Shields"]:::perimeterStyle
    end

    TB2["== Trust Boundary 2: Application Core =="]

    subgraph Zone2["Zone 2: Application & Business Tier"]
        AuthRoutes["routes/auth.js (Bcrypt Timing Mitigation)"]:::appStyle
        TwoFARoutes["routes/twofa.js (Session Regeneration & Replay Defense)"]:::appStyle
        Logger["middleware/logger.js (Sanitized JSON Audit Logger)"]:::appStyle
        Crypto["utils/crypto.js (AES-256-GCM Authenticated Encryption)"]:::appStyle
    end

    TB3["== Trust Boundary 3: Persistence Boundary =="]

    subgraph Zone3["Zone 3: Persistent Data Tier"]
        DB[("SQLite Database (app.sqlite) - Parameterized Queries")]:::dataStyle
        Sessions[("Session Store (sessions.sqlite) - Strict Cookies")]:::dataStyle
    end

    User -->|"HTTPS / Auth Requests"| TB1
    Attacker -.->|"Throttled abuse attempts"| TB1
    TB1 --> Helmet
    Helmet --> RateLimiter
    RateLimiter --> TB2
    TB2 --> AuthRoutes
    TB2 --> TwoFARoutes
    TwoFARoutes --> Crypto
    TwoFARoutes --> Logger
    AuthRoutes --> Logger
    Crypto -->|"AES-256-GCM Ciphertext"| TB3
    AuthRoutes -->|"Salted Bcrypt Hashes"| TB3
    TB3 --> DB
    TB3 --> Sessions
```

---

## 📋 Comprehensive Findings Matrix

| ID | Finding Title | Domain | Pre-Risk | CWE / OWASP | Root Cause & Defensive Patch | Status |
| :---: | :--- | :---: | :---: | :--- | :--- | :---: |
| **SEC-01** | Weak CSP (`'unsafe-inline'` in `script-src`) | Configuration | **HIGH** | CWE-79 / A05:2021 | Helmet CSP allowed inline scripts. Removed `'unsafe-inline'`; all scripts loaded as static assets. | **RESOLVED** |
| **SEC-02** | 2FA Session Fixation Across Validation | Authentication | **HIGH** | CWE-384 / A07:2021 | Session ID was not regenerated after TOTP validation. Added `req.session.regenerate()` in `/validate`. | **RESOLVED** |
| **SEC-03** | Plaintext Storage of TOTP Secrets | Auth / DB | **HIGH** | CWE-312 / A02:2021 | Secrets saved as plain base32 in SQLite. Implemented AES-256-GCM authenticated encryption at rest. | **RESOLVED** |
| **SEC-04** | TOTP Token Replay Vulnerability | Authentication | **MEDIUM** | CWE-294 / A07:2021 | Token accepted repeatedly in 90s window. Added `last_totp_token` tracking to block token reuse. | **RESOLVED** |
| **SEC-05** | Missing Rate Limiting on 2FA Endpoints | Auth / Config | **MEDIUM** | CWE-307 / A07:2021 | Setup and verify endpoints unthrottled. Bound `authLimiter` across the entire `/api/2fa` router. | **RESOLVED** |
| **SEC-06** | Malformed JSON Triggers HTTP 500 | Validation | **MEDIUM** | CWE-754 / A05:2021 | Bad JSON caused 500 internal server error. Handled syntax error cleanly with HTTP 400. | **RESOLVED** |
| **SEC-07** | Transitive Supply Chain CVEs in `tar`/`qs` | Dependencies | **CRITICAL** | CWE-1395 / A06:2021 | Critical/High CVEs in transitive dependencies. Applied `npm audit fix` and package override `tar: ^7.5.22`. | **RESOLVED** |
| **SEC-08** | Complete Absence of Security Audit Logging | Logging | **HIGH** | CWE-778 / A09:2021 | No structured logs for auth events. Created `middleware/logger.js` with sanitized JSON telemetry. | **RESOLVED** |
| **SEC-09** | Unconfigured Reverse Proxy Trust | Configuration | **LOW** | CWE-345 / A05:2021 | Express did not declare proxy trust. Added configurable `app.set('trust proxy', ...)`. | **RESOLVED** |
| **SEC-10** | Transitive Build Tool Advisory (`node-gyp`) | Dependencies | **LOW** | CWE-1395 / A06:2021 | Build-time proxy utility advisory in native compile tool. Documented and accepted (isolated build phase). | **ACCEPTED** |

---

## 🛠️ Defensive Codebase Structure

```text
├── DEFENSIVE_ASSESSMENT_SCOPING.md        # Formal Scoping, Authorization Statement & RoE
├── DEFENSIVE_SECURITY_ASSESSMENT_REPORT.md# Complete Sanitized Security Assessment Report
├── THREAT_MODEL.md                        # Threat Model & STRIDE Analysis
├── README.md                              # Repository overview & capstone documentation
├── server.js                              # Hardened Express server, Helmet CSP, proxy trust, error handling
├── utils/
│   └── crypto.js                          # AES-256-GCM authenticated encryption helpers
├── middleware/
│   ├── auth.js                            # Authentication & MFA authorization guards
│   └── logger.js                          # Structured JSON security audit logger with PII sanitization
├── routes/
│   ├── auth.js                            # Parameterized bcrypt registration, login, timing defense
│   └── twofa.js                           # Speakeasy TOTP setup, session regeneration, replay protection
├── db/
│   └── database.js                        # Parameterized SQLite persistence & encrypted secret handling
├── public/                                # Client UI (HTML/CSS/JS) with external scripts
└── test/
    ├── test-helper.js                     # Test database lifecycle and environment initialization
    ├── defensive-assessment-retest.test.js# Automated capstone retest assertions (7 tests)
    ├── generic-errors.test.js             # Error disclosure & enumeration mitigation tests
    ├── input-validation.test.js          # Server-side schema validation tests
    ├── password-hashing.test.js           # Salted bcrypt verification tests
    ├── rate-limiting.test.js              # Rate limiter throttling & 429 response tests
    ├── session-security.test.js           # Cookie flags, session fixation & logout tests
    └── twofa.test.js                      # End-to-end 2FA lifecycle & session tests
```

---

## 🚀 Running Locally & Verifying Retests

### 1. Installation
```bash
npm install
```

### 2. Run Automated Security Test Suite
```bash
npm test
```
*Executes all 24 security tests across 11 test suites covering configuration, authentication, validation, dependencies, and logging.*

### 3. Launch Development Server
```bash
npm run dev
# Or production mode:
npm start
```
Navigate to `http://localhost:3000` to interact with the hardened authentication interface.

---

## 📜 Key Assessment Documents
* 📄 **[Scoping, Authorization & Rules of Engagement](./DEFENSIVE_ASSESSMENT_SCOPING.md)**
* 📄 **[Master Security Assessment Report](./DEFENSIVE_SECURITY_ASSESSMENT_REPORT.md)**
* 📄 **[Threat Model & Secure Configuration Plan](./THREAT_MODEL.md)**
