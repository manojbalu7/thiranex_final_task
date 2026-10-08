const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');
const config = require('./config/config');

// Initialize Express app
const app = express();

// Security Headers with Helmet
// Configure Content Security Policy to allow inline app scripts & data: URIs for QR codes
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// Payload size limit to prevent Denial of Service (DoS) memory exhaustion
app.use(express.json({ limit: '15kb' }));
app.use(express.urlencoded({ extended: true, limit: '15kb' }));

// Secure Session Management Configuration
app.use(
  session({
    name: 'secure_auth_sid', // Obfuscate session cookie name (avoids framework fingerprinting)
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side scripts from accessing session cookie (XSS protection)
      sameSite: 'lax', // Mitigates Cross-Site Request Forgery (CSRF)
      secure: config.isProduction, // HTTPS only in production
      maxAge: 24 * 60 * 60 * 1000 // 24-hour session lifetime
    }
  })
);

// Serve static frontend assets
app.use(express.static(path.join(__dirname, '../public')));

// Mount API Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/2fa', require('./routes/twoFactorRoutes'));
app.use('/api/user', require('./routes/userRoutes'));
app.use('/api/demo', require('./routes/demoRoutes'));

// Fallback for HTML page routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Central Error Handler
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
  res.status(500).json({
    success: false,
    error: config.isProduction ? 'Internal Server Error' : err.message
  });
});

// Start Server
if (require.main === module) {
  app.listen(config.port, () => {
    console.log('====================================================');
    console.log(`🔒 SECURE LOGIN SYSTEM RUNNING ON PORT ${config.port}`);
    console.log(`🌐 Local URL: http://localhost:${config.port}`);
    console.log(`🛡️  Environment: ${config.nodeEnv}`);
    console.log(`💾 Database: SQLite (${config.dbPath})`);
    console.log('====================================================');
  });
}

module.exports = app;
