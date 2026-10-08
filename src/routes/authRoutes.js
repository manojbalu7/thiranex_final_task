const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authLimiter, twoFactorLimiter } = require('../middleware/rateLimiter');
const { validateRegistration, validateLogin, validateTwoFactorToken } = require('../middleware/validation');
const { requirePreAuth2FA, requireGuest } = require('../middleware/auth');

// Register endpoint
router.post('/register', authLimiter, requireGuest, validateRegistration, authController.register);

// Login endpoint
router.post('/login', authLimiter, requireGuest, validateLogin, authController.login);

// Two-Factor Verification endpoint
router.post('/verify-2fa', twoFactorLimiter, requirePreAuth2FA, validateTwoFactorToken, authController.verifyTwoFactor);

// Logout endpoint
router.post('/logout', authController.logout);

// Session / auth status check endpoint
router.get('/status', authController.checkStatus);

module.exports = router;
