const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { requireAuth } = require('../middleware/auth');
const { validatePasswordChange } = require('../middleware/validation');

// Get user profile & session info
router.get('/profile', requireAuth, userController.getProfile);

// Get user security audit logs
router.get('/audit-logs', requireAuth, userController.getAuditLogs);

// Change user password
router.post('/change-password', requireAuth, validatePasswordChange, userController.changePassword);

module.exports = router;
