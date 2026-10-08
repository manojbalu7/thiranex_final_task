const rateLimit = require('express-rate-limit');

/**
 * Rate limiter for authentication endpoints (Login, Register)
 * Mitigates brute-force attacks and automated credential stuffing
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Limit each IP to 15 requests per window
  standardHeaders: true, // Return standard RateLimit-* headers
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP address. Please try again after 15 minutes.'
  }
});

/**
 * Strict rate limiter for Two-Factor Authentication verification
 */
const twoFactorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 6, // 6 attempts per 5 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many 2FA verification attempts. Please wait 5 minutes before trying again.'
  }
});

/**
 * General rate limiter for all public endpoints
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = {
  authLimiter,
  twoFactorLimiter,
  generalLimiter
};
