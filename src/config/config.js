require('dotenv').config();
const path = require('path');

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
  sessionSecret: process.env.SESSION_SECRET || 'secure-login-fallback-secret-key-2026',
  dbPath: path.resolve(__dirname, '../../', process.env.DB_PATH || './data/secure_auth.sqlite'),
  bcryptRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12,
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
  lockoutDurationMinutes: parseInt(process.env.LOCKOUT_DURATION_MINUTES, 10) || 15,
  appName: process.env.APP_NAME || 'SecureAuthApp'
};

module.exports = config;
