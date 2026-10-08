const express = require('express');
const router = express.Router();
const demoController = require('../controllers/demoController');

// Interactive SQL Injection test
router.post('/sqli-test', demoController.testSQLInjection);

// Interactive bcrypt hash test
router.post('/hash-test', demoController.testHashing);

// Security architecture info
router.get('/security-info', demoController.inspectSecurity);

module.exports = router;
