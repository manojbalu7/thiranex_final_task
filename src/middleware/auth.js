const db = require('../database/db');

/**
 * Middleware ensuring the request has an active, valid session
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
      return res.redirect('/login.html');
    }
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Your session may have expired.'
    });
  }

  try {
    // Verify user exists in the database using parameterized query (SQLi protection)
    const stmt = db.prepare(`
      SELECT id, username, email, two_factor_enabled, created_at, updated_at
      FROM users
      WHERE id = ?
    `);
    const user = stmt.get(req.session.userId);

    if (!user) {
      // User was deleted or ID invalid: destroy session
      req.session.destroy();
      return res.status(401).json({
        success: false,
        error: 'User account not found. Session terminated.'
      });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('[AUTH MIDDLEWARE ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error during authentication.'
    });
  }
}

/**
 * Middleware ensuring the user is not logged in (e.g. for login/register pages)
 */
function requireGuest(req, res, next) {
  if (req.session && req.session.userId) {
    if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
      return res.redirect('/dashboard.html');
    }
    return res.status(400).json({
      success: false,
      error: 'You are already logged in.',
      redirect: '/dashboard.html'
    });
  }
  next();
}

/**
 * Middleware ensuring the user has passed step 1 (password) and is awaiting 2FA
 */
function requirePreAuth2FA(req, res, next) {
  if (!req.session || !req.session.preAuthUserId) {
    return res.status(400).json({
      success: false,
      error: 'No pending two-factor authentication challenge found. Please log in first.',
      redirect: '/login.html'
    });
  }
  next();
}

module.exports = {
  requireAuth,
  requireGuest,
  requirePreAuth2FA
};
