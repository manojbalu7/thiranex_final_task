const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { generateSecret, generateURI, verifySync } = require('otplib');
const QRCode = require('qrcode');
const config = require('../config/config');

/**
 * Hashes a plaintext password using bcrypt with cryptographic salt
 * @param {string} password 
 * @returns {Promise<string>}
 */
async function hashPassword(password) {
  return await bcrypt.hash(password, config.bcryptRounds);
}

/**
 * Compares plaintext password against stored bcrypt hash (constant-time)
 * @param {string} password 
 * @param {string} hash 
 * @returns {Promise<boolean>}
 */
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Generates a new Base32 secret key for TOTP 2FA
 * @returns {string}
 */
function generate2FASecret() {
  return generateSecret();
}

/**
 * Generates an otpauth:// URI for authenticator applications
 * @param {string} accountIdentifier 
 * @param {string} secret 
 * @returns {string}
 */
function generate2FAURI(accountIdentifier, secret) {
  return generateURI({
    issuer: config.appName,
    label: accountIdentifier,
    secret: secret
  });
}

/**
 * Generates a base64 Data URL containing the QR code for scanning
 * @param {string} otpAuthUri 
 * @returns {Promise<string>}
 */
async function generateQRCodeDataUrl(otpAuthUri) {
  return await QRCode.toDataURL(otpAuthUri, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 256,
    color: {
      dark: '#0f172a',
      light: '#ffffff'
    }
  });
}

/**
 * Verifies a 6-digit TOTP token against the user's secret
 * @param {string} token 
 * @param {string} secret 
 * @returns {boolean}
 */
function verify2FAToken(token, secret) {
  try {
    const cleanToken = String(token).trim();
    const result = verifySync({ token: cleanToken, secret });
    return Boolean(result && result.valid);
  } catch (err) {
    return false;
  }
}

/**
 * Generates emergency single-use backup recovery codes
 * Returns plaintext codes for the user to store and hashed codes for database storage
 * @param {number} count 
 * @returns {Promise<{ plainCodes: string[], hashedCodes: string[] }>}
 */
async function generateBackupCodes(count = 8) {
  const plainCodes = [];
  const hashedCodes = [];

  for (let i = 0; i < count; i++) {
    // Format: 4 chars - 4 chars (e.g. A1B2-C3D4)
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    plainCodes.push(formatted);
    const hash = await bcrypt.hash(formatted, 10);
    hashedCodes.push(hash);
  }

  return { plainCodes, hashedCodes };
}

/**
 * Checks if a candidate backup code matches any stored hashed backup codes
 * @param {string} candidateCode 
 * @param {string[]} storedHashedCodes 
 * @returns {Promise<{ valid: boolean, matchedIndex: number }>}
 */
async function verifyBackupCode(candidateCode, storedHashedCodes) {
  const normalized = String(candidateCode).trim().toUpperCase();
  for (let i = 0; i < storedHashedCodes.length; i++) {
    const match = await bcrypt.compare(normalized, storedHashedCodes[i]);
    if (match) {
      return { valid: true, matchedIndex: i };
    }
  }
  return { valid: false, matchedIndex: -1 };
}

module.exports = {
  hashPassword,
  comparePassword,
  generate2FASecret,
  generate2FAURI,
  generateQRCodeDataUrl,
  verify2FAToken,
  generateBackupCodes,
  verifyBackupCode
};
