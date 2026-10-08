const db = require('../database/db');
const security = require('../utils/security');
const { getUserAuditLogs, logAuthEvent } = require('../utils/logger');

/**
 * Returns current authenticated user profile
 */
function getProfile(req, res) {
  const user = req.user;
  return res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      twoFactorEnabled: user.two_factor_enabled === 1,
      createdAt: user.created_at,
      updatedAt: user.updated_at
    },
    session: {
      sessionId: req.sessionID ? `${req.sessionID.slice(0, 8)}...` : 'active',
      cookieExpires: req.session.cookie?.expires || null,
      maxAge: req.session.cookie?.maxAge || null
    }
  });
}

/**
 * Returns security audit logs for the current user
 */
function getAuditLogs(req, res) {
  const logs = getUserAuditLogs(req.user.id, 25);
  return res.json({
    success: true,
    logs
  });
}

/**
 * Changes user password with current password verification
 */
async function changePassword(req, res) {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Fetch user password hash
    const stmt = db.prepare('SELECT password_hash, email FROM users WHERE id = ?');
    const user = stmt.get(userId);

    const isMatch = await security.comparePassword(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect.'
      });
    }

    // Hash new password
    const newHash = await security.hashPassword(newPassword);

    // Update database using parameterized query
    const updateStmt = db.prepare(`
      UPDATE users
      SET password_hash = ?,
          updated_at = DATETIME('now')
      WHERE id = ?
    `);
    updateStmt.run(newHash, userId);

    logAuthEvent({
      userId,
      email: user.email,
      status: 'PASSWORD_CHANGED',
      req
    });

    return res.json({
      success: true,
      message: 'Password updated successfully!'
    });
  } catch (err) {
    console.error('[PASSWORD CHANGE ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'Failed to update password.'
    });
  }
}

module.exports = {
  getProfile,
  getAuditLogs,
  changePassword
};
