const db = require('../database/db');

/**
 * Logs an authentication or security audit event to the database and server console
 * @param {Object} options
 * @param {number|null} options.userId - ID of the user if identified
 * @param {string} options.email - The email or username attempted
 * @param {string} options.status - Event status code (e.g. 'SUCCESS', 'FAILED_INVALID_PASSWORD', '2FA_CHALLENGE')
 * @param {Object} [options.req] - Express request object for IP and User-Agent extraction
 */
function logAuthEvent({ userId = null, email, status, req = null }) {
  try {
    let ip = 'Unknown';
    let userAgent = 'Unknown';

    if (req) {
      ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';
      userAgent = req.headers['user-agent'] || 'Unknown Agent';
      // Normalize IPv6 localhost
      if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
      }
    }

    const stmt = db.prepare(`
      INSERT INTO login_audit_logs (user_id, attempted_email, status, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(userId, email || 'anonymous', status, ip, userAgent);

    console.log(`[AUDIT] [${new Date().toISOString()}] Status: ${status} | User: ${email} | IP: ${ip}`);
  } catch (err) {
    console.error('[AUDIT ERROR] Failed to record audit log:', err.message);
  }
}

/**
 * Retrieves recent audit logs for a specific user ID
 * @param {number} userId 
 * @param {number} limit 
 * @returns {Array}
 */
function getUserAuditLogs(userId, limit = 20) {
  try {
    const stmt = db.prepare(`
      SELECT id, attempted_email, status, ip_address, user_agent, timestamp
      FROM login_audit_logs
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT ?
    `);
    return stmt.all(userId, limit);
  } catch (err) {
    console.error('[AUDIT ERROR] Failed to fetch user audit logs:', err.message);
    return [];
  }
}

module.exports = {
  logAuthEvent,
  getUserAuditLogs
};
