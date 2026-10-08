const express = require('express');
const router = express.Router();
const twoFactorController = require('../controllers/twoFactorController');
const { requireAuth } = require('../middleware/auth');
const { twoFactorLimiter } = require('../middleware/rateLimiter');
const { validateTwoFactorToken } = require('../middleware/validation');

// Generate 2FA secret and QR code
router.post('/setup', requireAuth, twoFactorController.setup2FA);

// Confirm and enable 2FA with 6-digit token
router.post('/confirm', requireAuth, twoFactorLimiter, validateTwoFactorToken, twoFactorController.confirmAndEnable2FA);

// Disable 2FA with password confirmation
router.post('/disable', requireAuth, twoFactorController.disable2FA);

module.exports = router;
