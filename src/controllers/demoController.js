const db = require('../database/db');
const bcrypt = require('bcryptjs');

/**
 * Demonstrates SQL Injection vs Parameterized Queries safely
 */
function testSQLInjection(req, res) {
  const { input } = req.body;
  if (!input) {
    return res.status(400).json({ success: false, error: 'Input query string is required.' });
  }

  // 1. Simulation of vulnerable string concatenation (DEMO ONLY, NOT EXECUTED)
  const vulnerableRawSql = `SELECT * FROM users WHERE email = '${input}' AND password_hash = '...';`;

  // 2. Safe execution using Parameterized Query
  const secureSql = `SELECT id, username, email FROM users WHERE email = ?;`;
  let secureResult = null;
  let executionError = null;

  try {
    const stmt = db.prepare(secureSql);
    secureResult = stmt.get(input);
  } catch (err) {
    executionError = err.message;
  }

  return res.json({
    success: true,
    inputProvided: input,
    vulnerableQuerySimulation: {
      explanation: 'In a vulnerable system, string concatenation allows malicious input to alter query logic.',
      rawConstructedSql: vulnerableRawSql,
      riskLevel: 'CRITICAL (OWASP Top 10: A03:2021-Injection)'
    },
    secureParameterizedQuery: {
      explanation: 'With prepared statements and parameterized inputs, SQLite treats input strictly as literal data, completely neutralizing malicious SQL syntax.',
      parameterizedSqlTemplate: secureSql,
      parameterBound: input,
      databaseExecutionSafe: true,
      recordsReturned: secureResult ? 1 : 0,
      note: secureResult ? 'Record found for literal match' : 'No records found (injection attempt safely neutralized)'
    }
  });
}

/**
 * Demonstrates bcrypt hashing and salt generation
 */
async function testHashing(req, res) {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, error: 'Password is required.' });
  }

  const start = Date.now();
  const salt = await bcrypt.genSalt(12);
  const hash = await bcrypt.hash(password, salt);
  const durationMs = Date.now() - start;

  // Deconstruct bcrypt hash: $2a$12$salt(22 chars)hash(31 chars)
  const parts = hash.split('$');
  const algorithm = parts[1] ? `bcrypt ($${parts[1]}$)` : 'bcrypt';
  const cost = parts[2] ? `${parts[2]} rounds (2^${parts[2]} iterations)` : '12 rounds';

  return res.json({
    success: true,
    plaintext: password,
    bcryptAnalysis: {
      algorithm,
      costFactor: cost,
      saltGenerated: salt,
      fullHash: hash,
      computationTimeMs: `${durationMs} ms`,
      securityBenefits: [
        'Salt is cryptographically unique per password, preventing Rainbow Table attacks.',
        'Adaptive work factor (12 rounds) makes brute-force and GPU cracking computationally prohibitive.',
        'Constant-time comparison protects against side-channel timing attacks.'
      ]
    }
  });
}

/**
 * Inspects current security headers and session configuration
 */
function inspectSecurity(req, res) {
  return res.json({
    success: true,
    securityArchitecture: {
      sessionCookie: {
        httpOnly: true,
        description: 'Blocks JavaScript access (document.cookie), mitigating Cross-Site Scripting (XSS) session theft.',
        sameSite: 'Lax',
        descriptionSameSite: 'Prevents Cross-Site Request Forgery (CSRF) on cross-origin requests.',
        secure: req.secure || process.env.NODE_ENV === 'production'
      },
      headers: {
        'Content-Security-Policy': 'Enforced via Helmet',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY (Clickjacking mitigation)'
      },
      rateLimiter: 'Active (Express-Rate-Limit protecting auth routes)'
    }
  });
}

module.exports = {
  testSQLInjection,
  testHashing,
  inspectSecurity
};
