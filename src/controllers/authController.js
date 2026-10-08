const db = require('../database/db');
const security = require('../utils/security');
const { logAuthEvent } = require('../utils/logger');
const config = require('../config/config');

// Dummy bcrypt hash to maintain constant response timing for non-existent users
const DUMMY_HASH = '$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

/**
 * Handles new user registration
 */
async function register(req, res) {
  try {
    const { username, email, password } = req.body;

    // Parameterized query: check for existing username or email safely
    const checkStmt = db.prepare(`
      SELECT id, username, email FROM users
      WHERE email = ? OR username = ?
    `);
    const existing = checkStmt.get(email, username);

    if (existing) {
      const field = existing.email.toLowerCase() === email.toLowerCase() ? 'Email' : 'Username';
      return res.status(409).json({
        success: false,
        error: `${field} is already registered. Please choose another or log in.`
      });
    }

    // Hash password with bcrypt and cryptographic salt rounds
    const passwordHash = await security.hashPassword(password);

    // Parameterized query: insert new user
    const insertStmt = db.prepare(`
      INSERT INTO users (username, email, password_hash)
      VALUES (?, ?, ?)
    `);
    const result = insertStmt.run(username, email, passwordHash);
    const newUserId = result.lastInsertRowid;

    logAuthEvent({
      userId: newUserId,
      email: email,
      status: 'REGISTERED',
      req
    });

    // Automatically establish authenticated session
    req.session.regenerate((err) => {
      if (err) {
        console.error('[SESSION ERROR]', err);
        return res.status(500).json({ success: false, error: 'Session initialization failed.' });
      }

      req.session.userId = newUserId;
      return res.status(201).json({
        success: true,
        message: 'Account created successfully!',
        redirect: '/dashboard.html'
      });
    });
  } catch (err) {
    console.error('[REGISTER ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'An unexpected error occurred during registration.'
    });
  }
}

/**
 * Handles user login with password verification, lockout protection, and 2FA trigger
 */
async function login(req, res) {
  try {
    const { emailOrUsername, password } = req.body;

    // Parameterized query: Fetch user by email or username (mitigates SQL injection)
    const selectStmt = db.prepare(`
      SELECT id, username, email, password_hash, two_factor_enabled, failed_login_attempts, lockout_until
      FROM users
      WHERE email = ? OR username = ?
    `);
    const user = selectStmt.get(emailOrUsername, emailOrUsername);

    // User not found: perform dummy password comparison to neutralize timing attacks
    if (!user) {
      await security.comparePassword(password, DUMMY_HASH);
      logAuthEvent({
        userId: null,
        email: emailOrUsername,
        status: 'FAILED_USER_NOT_FOUND',
        req
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials. Please verify your email/username and password.'
      });
    }

    // Check account lockout status
    if (user.lockout_until) {
      const lockoutTime = new Date(user.lockout_until).getTime();
      const now = Date.now();

      if (lockoutTime > now) {
        const remainingMinutes = Math.ceil((lockoutTime - now) / 60000);
        logAuthEvent({
          userId: user.id,
          email: user.email,
          status: 'FAILED_ACCOUNT_LOCKED',
          req
        });
        return res.status(423).json({
          success: false,
          error: `Account is temporarily locked due to multiple failed attempts. Please try again in ${remainingMinutes} minute(s).`
        });
      } else {
        // Lockout expired: reset attempts
        db.prepare('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?').run(user.id);
        user.failed_login_attempts = 0;
      }
    }

    // Verify password using bcrypt (constant-time verification)
    const passwordMatch = await security.comparePassword(password, user.password_hash);

    if (!passwordMatch) {
      const attempts = user.failed_login_attempts + 1;
      let lockoutDate = null;

      if (attempts >= config.maxLoginAttempts) {
        const lockoutMs = Date.now() + config.lockoutDurationMinutes * 60 * 1000;
        lockoutDate = new Date(lockoutMs).toISOString();

        db.prepare(`
          UPDATE users
          SET failed_login_attempts = ?, lockout_until = ?
          WHERE id = ?
        `).run(attempts, lockoutDate, user.id);

        logAuthEvent({
          userId: user.id,
          email: user.email,
          status: 'ACCOUNT_LOCKED',
          req
        });

        return res.status(423).json({
          success: false,
          error: `Too many failed attempts. Your account has been locked for ${config.lockoutDurationMinutes} minutes.`
        });
      } else {
        db.prepare(`
          UPDATE users
          SET failed_login_attempts = ?
          WHERE id = ?
        `).run(attempts, user.id);

        logAuthEvent({
          userId: user.id,
          email: user.email,
          status: 'FAILED_INVALID_PASSWORD',
          req
        });

        const remaining = config.maxLoginAttempts - attempts;
        return res.status(401).json({
          success: false,
          error: `Invalid credentials. (${remaining} attempt${remaining === 1 ? '' : 's'} remaining before temporary lockout)`
        });
      }
    }

    // Password is valid: reset failed attempts
    db.prepare(`
      UPDATE users
      SET failed_login_attempts = 0, lockout_until = NULL
      WHERE id = ?
    `).run(user.id);

    // If Two-Factor Authentication is enabled, initiate 2FA challenge
    if (user.two_factor_enabled === 1) {
      req.session.preAuthUserId = user.id;
      req.session.preAuthEmail = user.email;

      logAuthEvent({
        userId: user.id,
        email: user.email,
        status: '2FA_CHALLENGE',
        req
      });

      return res.json({
        success: true,
        requires2FA: true,
        redirect: '/verify-2fa.html'
      });
    }

    // 2FA not enabled: complete login and regenerate session ID to prevent Session Fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error('[SESSION FIXATION MITIGATION ERROR]', err);
        return res.status(500).json({ success: false, error: 'Failed to initialize session.' });
      }

      req.session.userId = user.id;

      logAuthEvent({
        userId: user.id,
        email: user.email,
        status: 'SUCCESS',
        req
      });

      return res.json({
        success: true,
        requires2FA: false,
        redirect: '/dashboard.html'
      });
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred during login.'
    });
  }
}

/**
 * Handles Two-Factor Authentication token or backup code verification
 */
async function verifyTwoFactor(req, res) {
  try {
    const { token } = req.body;
    const userId = req.session.preAuthUserId;

    // Fetch user details including 2FA secret and backup codes
    const stmt = db.prepare(`
      SELECT id, email, two_factor_secret, backup_codes
      FROM users
      WHERE id = ?
    `);
    const user = stmt.get(userId);

    if (!user || !user.two_factor_secret) {
      return res.status(400).json({
        success: false,
        error: '2FA is not properly configured for this account. Please log in again.',
        redirect: '/login.html'
      });
    }

    let isValid = false;
    let usedBackupCode = false;

    // 1. Try TOTP token verification (6 digits)
    if (/^\d{6}$/.test(token.trim())) {
      isValid = security.verify2FAToken(token, user.two_factor_secret);
    }

    // 2. If TOTP failed or user provided backup code, test against stored backup recovery codes
    if (!isValid && user.backup_codes) {
      try {
        const storedCodes = JSON.parse(user.backup_codes);
        const backupResult = await security.verifyBackupCode(token, storedCodes);

        if (backupResult.valid) {
          isValid = true;
          usedBackupCode = true;

          // Invalidate used single-use backup code
          storedCodes.splice(backupResult.matchedIndex, 1);
          db.prepare('UPDATE users SET backup_codes = ? WHERE id = ?')
            .run(JSON.stringify(storedCodes), user.id);
        }
      } catch (e) {
        console.error('[BACKUP CODE PARSE ERROR]', e);
      }
    }

    if (!isValid) {
      logAuthEvent({
        userId: user.id,
        email: user.email,
        status: '2FA_FAILED',
        req
      });

      return res.status(400).json({
        success: false,
        error: 'Invalid 2FA code or backup code. Please check and try again.'
      });
    }

    // Successful 2FA: regenerate session and promote to authenticated state
    req.session.regenerate((err) => {
      if (err) {
        console.error('[SESSION REGEN ERROR]', err);
        return res.status(500).json({ success: false, error: 'Failed to establish session.' });
      }

      req.session.userId = user.id;
      delete req.session.preAuthUserId;
      delete req.session.preAuthEmail;

      logAuthEvent({
        userId: user.id,
        email: user.email,
        status: usedBackupCode ? '2FA_SUCCESS_BACKUP_CODE' : '2FA_SUCCESS',
        req
      });

      return res.json({
        success: true,
        message: usedBackupCode ? 'Authenticated using emergency backup code.' : '2FA verification successful.',
        redirect: '/dashboard.html'
      });
    });
  } catch (err) {
    console.error('[2FA VERIFY ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred during 2FA verification.'
    });
  }
}

/**
 * Handles user logout and session destruction
 */
function logout(req, res) {
  const userId = req.session?.userId;
  const email = req.user?.email || 'authenticated_user';

  if (userId) {
    logAuthEvent({
      userId,
      email,
      status: 'LOGOUT',
      req
    });
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('[LOGOUT ERROR]', err);
      return res.status(500).json({ success: false, error: 'Could not log out.' });
    }

    res.clearCookie('connect.sid', { path: '/' });
    return res.json({
      success: true,
      message: 'Logged out successfully.',
      redirect: '/login.html'
    });
  });
}

/**
 * Returns current authentication status for client navigation
 */
function checkStatus(req, res) {
  if (req.session && req.session.userId) {
    const stmt = db.prepare('SELECT id, username, email, two_factor_enabled, created_at FROM users WHERE id = ?');
    const user = stmt.get(req.session.userId);
    if (user) {
      return res.json({
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          twoFactorEnabled: user.two_factor_enabled === 1,
          createdAt: user.created_at
        }
      });
    }
  }

  return res.json({
    authenticated: false,
    user: null,
    pending2FA: Boolean(req.session && req.session.preAuthUserId)
  });
}

module.exports = {
  register,
  login,
  verifyTwoFactor,
  logout,
  checkStatus
};
