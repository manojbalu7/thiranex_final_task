# 🛡️ SecureShield: Secure Login & Identity Management System

A production-grade, enterprise-ready authentication web application engineered with defensive cybersecurity baselines to mitigate the **OWASP Top 10** vulnerabilities.

---

## 🚀 Key Features

### 1. 🔐 Cryptographic Password Hashing (Bcrypt)
- Passwords are **never** stored in plaintext.
- Utilizes **bcrypt** with **12 adaptive salt rounds** (\(2^{12} = 4,096\) key stretching iterations).
- Generates a unique 128-bit cryptographic salt for every password, completely neutralizing **Rainbow Table** attacks.
- Constant-time hash verification protects against side-channel timing attacks.

### 2. 🛡️ 100% SQL Injection Immunity (Parameterized Queries)
- Powered by **SQLite** via `better-sqlite3` in WAL mode.
- Every single database operation employs strict **parameterized prepared statements** (`db.prepare('... WHERE email = ?').get(email)`).
- Eliminates string concatenation in SQL queries, mathematically ensuring user input is treated as literal data and cannot alter query grammar.

### 3. 🍪 Hardened Session Management & Logout
- Express session configured with **HttpOnly** cookie flags, blocking JavaScript from accessing `document.cookie` (defense against Cross-Site Scripting / XSS session hijacking).
- **SameSite=Lax** policy prevents Cross-Site Request Forgery (CSRF).
- **Session Fixation Mitigation**: Session IDs are automatically regenerated via `req.session.regenerate()` immediately upon login.
- Complete server-side session destruction and cookie clearing on logout.

### 4. 📱 Two-Factor Authentication (2FA / TOTP)
- Implements **RFC 6238 Time-based One-Time Password (TOTP)** compatible with:
  - Google Authenticator
  - Microsoft Authenticator
  - Authy / 1Password
- In-app **QR Code** generation for instantaneous mobile pairing.
- **8 Single-Use Emergency Backup Recovery Codes** generated during 2FA setup. Each backup code is hashed with bcrypt in the database and automatically invalidated upon first use.

### 5. ⏱️ Brute-Force Rate Limiting & Account Lockout
- **Rate limiting** on authentication endpoints to throttle automated dictionary and credential stuffing attacks.
- **Account Lockout**: Automatically locks an account for 15 minutes after 5 consecutive failed login attempts.

### 6. 📋 Security Audit Logging Trail
- Chronological audit logs recording every authentication attempt, status code (`SUCCESS`, `FAILED_INVALID_PASSWORD`, `2FA_CHALLENGE`, etc.), client IP address, user-agent device signature, and timestamp.

### 7. 🧪 Interactive Security Playground
- Built-in educational testing suite (`/security-demo.html`) demonstrating live comparisons between vulnerable SQL concatenation vs. parameterized queries, real-time bcrypt salt extraction, and cookie inspection.

---

## 📂 Project Directory Structure

```
thrinex/
├── src/
│   ├── config/
│   │   └── config.js            # Configuration & environment variables
│   ├── database/
│   │   ├── db.js                # SQLite engine setup & WAL mode
│   │   └── schema.sql           # SQL schema for users & audit logs
│   ├── middleware/
│   │   ├── auth.js              # requireAuth, requireGuest, requirePreAuth2FA
│   │   ├── rateLimiter.js       # Brute-force & API rate limiters
│   │   └── validation.js       # Strict input validation & password policy
│   ├── controllers/
│   │   ├── authController.js    # Register, login, 2FA challenge, logout
│   │   ├── twoFactorController.js # 2FA setup, QR code, confirm, disable
│   │   ├── userController.js    # Profile, password updates, audit logs
│   │   └── demoController.js    # Interactive SQLi and bcrypt demonstration
│   ├── routes/
│   │   ├── authRoutes.js        # /api/auth endpoints
│   │   ├── twoFactorRoutes.js   # /api/2fa endpoints
│   │   ├── userRoutes.js        # /api/user endpoints
│   │   └── demoRoutes.js        # /api/demo playground endpoints
│   ├── utils/
│   │   ├── security.js          # Cryptographic hashing, TOTP & backup codes
│   │   └── logger.js            # Security audit trail logging
│   └── server.js                # Express app entry point & Helmet security headers
├── public/                      # Responsive frontend web application
│   ├── css/
│   │   └── style.css            # Modern glassmorphism cyber-theme
│   ├── js/
│   │   ├── auth.js              # Real-time password meter & auth handler
│   │   ├── dashboard.js         # User dashboard, 2FA setup modal, audit logs
│   │   ├── two-factor.js        # 2FA challenge & backup code fallback
│   │   └── security-demo.js     # Live SQLi & bcrypt playground scripts
│   ├── index.html               # Landing & security architecture overview
│   ├── login.html               # Sign in interface
│   ├── register.html            # Registration interface
│   ├── verify-2fa.html          # 2FA code verification interface
│   ├── dashboard.html           # Authenticated user dashboard & 2FA controls
│   └── security-demo.html       # Interactive security playground
├── tests/
│   ├── security.test.js         # Automated security specifications test suite
│   └── e2e.test.js              # End-to-end HTTP integration test suite
├── .env                         # Environment configuration
├── .env.example                 # Configuration template
├── package.json                 # Dependencies and npm run scripts
└── README.md                    # Project documentation
```

---

## ⚡ Quick Start Guide

### 1. Prerequisites
- **Node.js**: v18.0.0 or newer (tested on Node.js v24)
- **npm**: v9.0.0 or newer

### 2. Installation
Clone or navigate to the project directory and install dependencies:
```bash
npm install
```

### 3. Environment Configuration
Verify or modify the `.env` file (a pre-configured `.env` is created automatically from `.env.example`):
```env
PORT=3000
NODE_ENV=development
SESSION_SECRET=thrinex-super-secure-session-key-change-this-in-production-random-984712
DB_PATH=./data/secure_auth.sqlite
BCRYPT_SALT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
APP_NAME=SecureAuthApp
```

### 4. Run the Application
Start the server:
```bash
npm start
```
For development with auto-reload:
```bash
npm run dev
```

### 5. Access the Web Application
Open your web browser and navigate to:
- **Home / Overview**: [http://localhost:3000/](http://localhost:3000/)
- **Register Account**: [http://localhost:3000/register.html](http://localhost:3000/register.html)
- **Sign In**: [http://localhost:3000/login.html](http://localhost:3000/login.html)
- **Security Playground**: [http://localhost:3000/security-demo.html](http://localhost:3000/security-demo.html)

---

## 🧪 Automated Testing

### 1. Security Unit & Invariance Tests
Tests database schema integrity, bcrypt salt creation, parameterized query SQLi resistance, TOTP generation & verification, and single-use backup recovery codes:
```bash
npm test
```
*Expected Result:* `7 / 7 TESTS PASSED`

### 2. End-to-End HTTP Integration Tests
Launches end-to-end tests across all HTTP API routes (registration, weak password rejection, SQL injection login attempts, 2FA pairing, TOTP challenge, and secure logout):
```bash
npm run test:e2e
```
*Expected Result:* `ALL 11 END-TO-END INTEGRATION TESTS PASSED!`

---

## 🛡️ Technical Security Deep-Dive

### How SQL Injection is Prevented
In vulnerable systems, dynamic queries concatenate user input directly:
```javascript
// ❌ VULNERABLE: Input `' OR '1'='1` alters syntax logic
const sql = `SELECT * FROM users WHERE email = '${req.body.email}'`;
```
In **SecureShield**, every query uses parameterized statements:
```javascript
// ✅ SECURE: SQLite treats parameter strictly as literal data
const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
const user = stmt.get(req.body.email);
```
The database engine pre-compiles the SQL command structure before binding parameters. Even if an attacker supplies `' OR '1'='1 --`, SQLite searches for a user whose literal email address is the string `"' OR '1'='1 --"`, completely neutralizing the attack.

### How Bcrypt Hashing Protects Passwords
- **Salt Generation**: Bcrypt prepends a cryptographically secure pseudo-random 128-bit salt to each password before hashing. Even if two users choose identical passwords, their stored hashes are completely different.
- **Work Factor / Key Stretching**: The cost factor `12` means the hashing algorithm performs \(2^{12} = 4,096\) rounds. This creates an intentional, calibrated delay (~80-120ms) that is imperceptible to legitimate users but makes brute-force hardware cracking computationally impossible.

### Two-Factor Authentication (2FA) Architecture
1. **Secret Generation**: Creates a Base32 RFC 3548 secret key.
2. **QR Code Pairing**: Generates an `otpauth://totp/SecureAuthApp:user@example.com?secret=...` URI rendered as a QR code Data URL.
3. **Time-Drift Window**: Verifies the current 30-second epoch token while accepting a slight window drift for mobile clock variations.
4. **Emergency Recovery**: Generates 8 cryptographically random alphanumeric backup codes. Each code is hashed with bcrypt and stored as JSON. When used, the code is matched, authenticated, and immediately pruned from the database.

---

## 📡 API Endpoint Reference

| Method | Endpoint | Description | Protection |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register new user account | Rate Limiter, Password Policy, Bcrypt |
| `POST` | `/api/auth/login` | Authenticate user credentials | Rate Limiter, Account Lockout, 2FA Check |
| `POST` | `/api/auth/verify-2fa` | Complete 2FA challenge with TOTP/Backup | Rate Limiter, Pre-Auth Session Required |
| `POST` | `/api/auth/logout` | Terminate active session | Session Invalidation, Cookie Cleared |
| `GET` | `/api/auth/status` | Check session authentication state | Session Inspection |
| `POST` | `/api/2fa/setup` | Generate 2FA secret and QR code | Requires Active Session |
| `POST` | `/api/2fa/confirm` | Confirm 2FA and receive backup codes | Requires Active Session, 6-digit TOTP |
| `POST` | `/api/2fa/disable` | Disable 2FA | Requires Password Confirmation |
| `GET` | `/api/user/profile` | Retrieve user details and session state | Requires Active Session |
| `GET` | `/api/user/audit-logs` | Retrieve chronological security audit trail | Requires Active Session |
| `POST` | `/api/user/change-password` | Update account password | Requires Current Password & Complexity Check |
| `POST` | `/api/demo/sqli-test` | Test SQL injection neutralization live | Public Demonstration Endpoint |
| `POST` | `/api/demo/hash-test` | Test bcrypt salt and cost factor live | Public Demonstration Endpoint |
| `GET` | `/api/demo/security-info`| Inspect session cookie security flags | Public Demonstration Endpoint |

---

## 📜 License
This project is open-source and released under the **MIT License**.
