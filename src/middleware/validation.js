const validator = require('validator');

/**
 * Validates registration request payload
 */
function validateRegistration(req, res, next) {
  let { username, email, password, confirmPassword } = req.body;

  // Type & Existence check
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({
      success: false,
      error: 'All fields (username, email, password, confirmPassword) are required.'
    });
  }

  username = String(username).trim();
  email = String(email).trim().toLowerCase();
  password = String(password);
  confirmPassword = String(confirmPassword);

  // Username validation
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({
      success: false,
      error: 'Username must be between 3 and 30 characters and contain only letters, numbers, and underscores.'
    });
  }

  // Email format validation
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'Please enter a valid email address.'
    });
  }

  // Password confirmation check
  if (password !== confirmPassword) {
    return res.status(400).json({
      success: false,
      error: 'Passwords do not match.'
    });
  }

  // Password complexity policy:
  // - Minimum 8 characters, maximum 128 characters
  // - At least 1 lowercase letter
  // - At least 1 uppercase letter
  // - At least 1 digit
  // - At least 1 special character
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      success: false,
      error: 'Password must be between 8 and 128 characters in length.'
    });
  }

  if (!/[a-z]/.test(password)) {
    return res.status(400).json({
      success: false,
      error: 'Password must contain at least one lowercase letter.'
    });
  }

  if (!/[A-Z]/.test(password)) {
    return res.status(400).json({
      success: false,
      error: 'Password must contain at least one uppercase letter.'
    });
  }

  if (!/[0-9]/.test(password)) {
    return res.status(400).json({
      success: false,
      error: 'Password must contain at least one numeric digit.'
    });
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) {
    return res.status(400).json({
      success: false,
      error: 'Password must contain at least one special character (e.g. !@#$%^&*).'
    });
  }

  // Pass sanitized values
  req.body.username = username;
  req.body.email = validator.normalizeEmail(email) || email;
  req.body.password = password;

  next();
}

/**
 * Validates login request payload
 */
function validateLogin(req, res, next) {
  let { emailOrUsername, password } = req.body;

  if (!emailOrUsername || !password) {
    return res.status(400).json({
      success: false,
      error: 'Both email/username and password are required.'
    });
  }

  emailOrUsername = String(emailOrUsername).trim();
  password = String(password);

  if (emailOrUsername.length === 0 || password.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Email/username and password cannot be empty.'
    });
  }

  req.body.emailOrUsername = emailOrUsername;
  req.body.password = password;

  next();
}

/**
 * Validates 2FA verification token payload
 */
function validateTwoFactorToken(req, res, next) {
  let { token } = req.body;

  if (!token) {
    return res.status(400).json({
      success: false,
      error: 'A verification code or backup code is required.'
    });
  }

  token = String(token).trim();

  // Allow either standard 6-digit TOTP token or 9-character backup code (e.g., A1B2-C3D4 or A1B2C3D4)
  const isSixDigit = /^\d{6}$/.test(token);
  const isBackupCode = /^[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{4}$/.test(token);

  if (!isSixDigit && !isBackupCode) {
    return res.status(400).json({
      success: false,
      error: 'Invalid code format. Enter a 6-digit TOTP code or an 8-character backup code.'
    });
  }

  req.body.token = token;
  next();
}

/**
 * Validates password change payload
 */
function validatePasswordChange(req, res, next) {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    return res.status(400).json({
      success: false,
      error: 'Current password, new password, and confirmation are required.'
    });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({
      success: false,
      error: 'New passwords do not match.'
    });
  }

  if (currentPassword === newPassword) {
    return res.status(400).json({
      success: false,
      error: 'New password cannot be the same as the current password.'
    });
  }

  if (newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({
      success: false,
      error: 'New password must be between 8 and 128 characters in length.'
    });
  }

  if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword) || !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(newPassword)) {
    return res.status(400).json({
      success: false,
      error: 'New password must include uppercase, lowercase, numbers, and special characters.'
    });
  }

  next();
}

module.exports = {
  validateRegistration,
  validateLogin,
  validateTwoFactorToken,
  validatePasswordChange
};
