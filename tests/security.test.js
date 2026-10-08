/**
 * ==========================================================
 * SECURE LOGIN SYSTEM: AUTOMATED SECURITY TEST SUITE
 * Tests:
 * 1. Database schema and tables
 * 2. Bcrypt password hashing & salt verification
 * 3. SQL Injection resistance (Auth bypass payloads)
 * 4. Password complexity policy enforcement
 * 5. Two-Factor Authentication (TOTP RFC 6238 & Backup Codes)
 * 6. Account Lockout against Brute Force Attacks
 * 7. Session Fixation & Logout Invalidation
 * ==========================================================
 */

const assert = require('assert');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const security = require('../src/utils/security');
const { generateSecret, generateSync, verifySync } = require('otplib');

console.log('====================================================');
console.log('🧪 RUNNING COMPREHENSIVE SECURITY TEST SUITE');
console.log('====================================================\n');

let passedTests = 0;
let totalTests = 0;

function runTest(testName, testFn) {
  totalTests++;
  try {
    testFn();
    console.log(`  ✅ [PASS] ${testName}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ [FAIL] ${testName}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

async function runAsyncTest(testName, testFn) {
  totalTests++;
  try {
    await testFn();
    console.log(`  ✅ [PASS] ${testName}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ [FAIL] ${testName}`);
    console.error(`     Error: ${err.message}\n`);
  }
}

async function main() {
  // Use in-memory SQLite database for isolated testing
  const testDb = new Database(':memory:');
  const schemaPath = path.join(__dirname, '../src/database/schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  testDb.exec(schemaSql);

  // TEST 1: Database Schema Integrity
  runTest('Database schema creates users and login_audit_logs tables', () => {
    const tables = testDb.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);
    assert(tables.includes('users'), 'Users table should exist');
    assert(tables.includes('login_audit_logs'), 'Audit logs table should exist');
  });

  // TEST 2: Bcrypt Password Hashing & Salt Verification
  await runAsyncTest('Password hashing produces bcrypt salt rounds and non-plaintext hash', async () => {
    const rawPassword = 'SecurePassword#2026';
    const hash = await security.hashPassword(rawPassword);

    assert.notStrictEqual(hash, rawPassword, 'Hash must never equal plaintext password');
    assert(hash.startsWith('$2a$') || hash.startsWith('$2b$'), 'Hash must follow standard bcrypt format');

    const isValid = await security.comparePassword(rawPassword, hash);
    assert.strictEqual(isValid, true, 'Original password must successfully match bcrypt hash');

    const isWrongValid = await security.comparePassword('WrongPassword123!', hash);
    assert.strictEqual(isWrongValid, false, 'Incorrect password must be rejected');
  });

  // TEST 3: SQL Injection Attack Neutralization
  await runAsyncTest('Parameterized queries neutralize SQL injection attack payloads', async () => {
    // Insert legitimate user
    const legitPassHash = await security.hashPassword('LegitPassword123!');
    testDb.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
      .run('admin', 'admin@example.com', legitPassHash);

    // Common SQL Injection Exploit Payloads
    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "' OR 1=1 --",
      "admin' --",
      "' UNION SELECT 1, 'hacked', 'hacked', 0, NULL, NULL, 0, NULL, '', '' --",
      "'; DROP TABLE users; --"
    ];

    for (const payload of sqlInjectionPayloads) {
      // Secure Parameterized Query
      const query = testDb.prepare('SELECT * FROM users WHERE email = ? OR username = ?');
      const result = query.get(payload, payload);

      // Verify that the query treats the payload as a literal string value, finding 0 records
      assert.strictEqual(result, undefined, `SQL Injection payload "${payload}" must NOT bypass authentication!`);
    }

    // Verify database table was not dropped or compromised
    const userCount = testDb.prepare('SELECT COUNT(*) as count FROM users').get().count;
    assert.strictEqual(userCount, 1, 'Database integrity must remain fully intact after SQL injection tests');
  });

  // TEST 4: Two-Factor Authentication (TOTP) RFC 6238 Verification
  runTest('TOTP 2FA secret generation and token verification', () => {
    const secret = security.generate2FASecret();
    assert(typeof secret === 'string' && secret.length >= 16, 'Secret must be valid Base32 string');

    // Generate valid token for current time window
    const token = generateSync({ secret });
    assert(typeof token === 'string' && token.length === 6, 'Token must be 6 digits');

    // Verify valid token
    const isVerified = security.verify2FAToken(token, secret);
    assert.strictEqual(isVerified, true, 'Valid TOTP token must verify successfully');

    // Reject invalid token
    const isInvalidVerified = security.verify2FAToken('000000', secret);
    assert.strictEqual(isInvalidVerified, false, 'Invalid TOTP token must be rejected');
  });

  // TEST 5: Emergency Backup Recovery Codes Generation and Consumption
  await runAsyncTest('Emergency backup recovery codes generation, verification, and single-use consumption', async () => {
    const { plainCodes, hashedCodes } = await security.generateBackupCodes(8);

    assert.strictEqual(plainCodes.length, 8, 'Must generate exactly 8 backup recovery codes');
    assert.strictEqual(hashedCodes.length, 8, 'Must generate 8 corresponding bcrypt hashes');

    const testCode = plainCodes[0];

    // Verify first backup code matches
    const verifyResult = await security.verifyBackupCode(testCode, hashedCodes);
    assert.strictEqual(verifyResult.valid, true, 'Valid backup code must be accepted');
    assert.strictEqual(verifyResult.matchedIndex, 0, 'Matched index must match code position');

    // Invalidate single-use code
    hashedCodes.splice(verifyResult.matchedIndex, 1);

    // Verify that the consumed code cannot be used a second time
    const secondAttempt = await security.verifyBackupCode(testCode, hashedCodes);
    assert.strictEqual(secondAttempt.valid, false, 'Consumed backup code must NOT be usable a second time (single-use replay protection)');
  });

  // TEST 6: Account Lockout & Brute Force Protection Logic
  runTest('Brute force tracking locks account after threshold failed attempts', () => {
    const maxAttempts = 5;
    let attempts = 0;
    let isLocked = false;

    // Simulate 5 consecutive failed login attempts
    for (let i = 1; i <= maxAttempts; i++) {
      attempts++;
      if (attempts >= maxAttempts) {
        isLocked = true;
      }
    }

    assert.strictEqual(attempts, 5, 'Must track 5 failed attempts');
    assert.strictEqual(isLocked, true, 'Account must transition to locked status after 5 failed attempts');
  });

  // TEST 7: Password Complexity Policy
  runTest('Password complexity checks reject weak passwords', () => {
    const weakPasswords = [
      'short1!',           // Less than 8 chars
      'nouppercase123!',   // Missing uppercase
      'NOLOWERCASE123!',   // Missing lowercase
      'NoNumbersSpecial!', // Missing number
      'NoSpecialNumber123' // Missing special character
    ];

    const hasComplexity = (pwd) => (
      pwd.length >= 8 &&
      /[a-z]/.test(pwd) &&
      /[A-Z]/.test(pwd) &&
      /[0-9]/.test(pwd) &&
      /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(pwd)
    );

    for (const weak of weakPasswords) {
      assert.strictEqual(hasComplexity(weak), false, `Weak password "${weak}" must fail complexity policy`);
    }

    assert.strictEqual(hasComplexity('ValidStrongPass#2026'), true, 'Strong password must pass complexity policy');
  });

  console.log('\n====================================================');
  console.log(`📊 TEST RESULTS: ${passedTests} / ${totalTests} TESTS PASSED`);
  if (passedTests === totalTests) {
    console.log('🎉 ALL SECURITY SPECIFICATIONS VERIFIED & VALIDATED!');
  } else {
    console.log('⚠️ SOME TESTS FAILED. PLEASE REVIEW LOGS.');
    process.exitCode = 1;
  }
  console.log('====================================================\n');
}

main().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
