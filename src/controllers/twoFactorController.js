const db = require('../database/db');
const security = require('../utils/security');
const { logAuthEvent } = require('../utils/logger');

/**
 * Initiates 2FA setup by generating a secret, otpauth URI, and QR code
 */
async function setup2FA(req, res) {
  try {
    const userId = req.session.userId;
    const user = req.user;

    if (user.two_factor_enabled === 1) {
      return res.status(400).json({
        success: false,
        error: 'Two-Factor Authentication is already enabled on your account.'
      });
    }

    // Generate fresh TOTP secret
    const secret = security.generate2FASecret();
    const otpAuthUri = security.generate2FAURI(user.email, secret);
    const qrCodeUrl = await security.generateQRCodeDataUrl(otpAuthUri);

    // Save candidate secret in session until confirmed
    req.session.temp2FASecret = secret;

    return res.json({
      success: true,
      secret,
      qrCodeUrl
    });
  } catch (err) {
    console.error('[2FA SETUP ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'Failed to generate 2FA setup details.'
    });
  }
}

/**
 * Confirms 2FA setup with a test token, enables 2FA, and returns backup codes
 */
async function confirmAndEnable2FA(req, res) {
  try {
    const { token } = req.body;
    const userId = req.session.userId;
    const tempSecret = req.session.temp2FASecret;

    if (!tempSecret) {
      return res.status(400).json({
        success: false,
        error: 'No 2FA setup in progress. Please start the setup process again.'
      });
    }

    // Verify code against temporary secret
    const isValid = security.verify2FAToken(token, tempSecret);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid 6-digit code. Please ensure your authenticator clock is synced.'
      });
    }

    // Generate emergency backup recovery codes
    const { plainCodes, hashedCodes } = await security.generateBackupCodes(8);

    // Persist secret and hashed backup codes in database (Parameterized query)
    const updateStmt = db.prepare(`
      UPDATE users
      SET two_factor_enabled = 1,
          two_factor_secret = ?,
          backup_codes = ?,
          updated_at = DATETIME('now')
      WHERE id = ?
    `);
    updateStmt.run(tempSecret, JSON.stringify(hashedCodes), userId);

    delete req.session.temp2FASecret;

    logAuthEvent({
      userId,
      email: req.user.email,
      status: '2FA_ENABLED',
      req
    });

    return res.json({
      success: true,
      message: 'Two-Factor Authentication has been successfully enabled!',
      backupCodes: plainCodes
    });
  } catch (err) {
    console.error('[2FA CONFIRM ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'Failed to activate 2FA.'
    });
  }
}

/**
 * Disables 2FA (requires password confirmation for authorization)
 */
async function disable2FA(req, res) {
  try {
    const { password } = req.body;
    const userId = req.session.userId;

    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Your current password is required to disable 2FA.'
      });
    }

    // Fetch user password hash
    const stmt = db.prepare('SELECT password_hash, email FROM users WHERE id = ?');
    const user = stmt.get(userId);

    const isMatch = await security.comparePassword(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'Incorrect password. Cannot disable 2FA.'
      });
    }

    // Update database
    const updateStmt = db.prepare(`
      UPDATE users
      SET two_factor_enabled = 0,
          two_factor_secret = NULL,
          backup_codes = NULL,
          updated_at = DATETIME('now')
      WHERE id = ?
    `);
    updateStmt.run(userId);

    logAuthEvent({
      userId,
      email: user.email,
      status: '2FA_DISABLED',
      req
    });

    return res.json({
      success: true,
      message: 'Two-Factor Authentication has been successfully disabled.'
    });
  } catch (err) {
    console.error('[2FA DISABLE ERROR]', err);
    return res.status(500).json({
      success: false,
      error: 'Failed to disable 2FA.'
    });
  }
}

module.exports = {
  setup2FA,
  confirmAndEnable2FA,
  disable2FA
};
