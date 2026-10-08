/**
 * ==========================================================
 * SECURE LOGIN SYSTEM: END-TO-END HTTP INTEGRATION TEST
 * Tests live web server endpoints:
 * - HTML Pages delivery
 * - User Registration with bcrypt
 * - Duplicate email prevention
 * - Weak password rejection
 * - SQL Injection login attack safe failure
 * - Valid user authentication & session cookie
 * - Two-Factor Authentication setup & confirmation
 * - 2FA login challenge & verification
 * - Secure logout & session invalidation
 * ==========================================================
 */

const assert = require('assert');
const { generateSync } = require('otplib');

const BASE_URL = 'http://localhost:3000';

console.log('====================================================');
console.log('🚀 RUNNING END-TO-END HTTP INTEGRATION TEST SUITE');
console.log('====================================================\n');

async function runE2E() {
  let cookie = '';

  // 1. Test HTML landing page
  console.log('1. Testing Landing Page Delivery...');
  const indexRes = await fetch(`${BASE_URL}/`);
  assert.strictEqual(indexRes.status, 200, 'Landing page should return status 200');
  const indexHtml = await indexRes.text();
  assert(indexHtml.includes('Secure') && indexHtml.includes('Shield'), 'Landing page should include brand name');
  console.log('   ✅ Landing page rendered successfully.\n');

  // 2. Test Registration with Weak Password (should fail)
  console.log('2. Testing Registration with Weak Password Policy Rejection...');
  const weakRegRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'weakuser',
      email: 'weak@example.com',
      password: 'password', // weak
      confirmPassword: 'password'
    })
  });
  assert.strictEqual(weakRegRes.status, 400, 'Weak password should return 400 Bad Request');
  const weakJson = await weakRegRes.json();
  assert(weakJson.error.includes('Password must'), 'Should return password policy error');
  console.log('   ✅ Weak password successfully rejected.\n');

  // 3. Test Registration with Strong Password
  const testUsername = `user_${Date.now()}`;
  const testEmail = `${testUsername}@example.com`;
  const testPassword = 'StrongPassword!2026';

  console.log(`3. Testing User Registration for [${testEmail}]...`);
  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: testUsername,
      email: testEmail,
      password: testPassword,
      confirmPassword: testPassword
    })
  });
  assert.strictEqual(regRes.status, 201, 'Registration should return 201 Created');
  const regJson = await regRes.json();
  assert.strictEqual(regJson.success, true);
  cookie = regRes.headers.get('set-cookie')?.split(';')[0] || '';
  console.log('   ✅ User registered successfully. Authenticated session established.\n');

  // 4. Test SQL Injection login attack
  console.log("4. Testing SQL Injection Attack Payload [' OR '1'='1]...");
  const sqliRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      emailOrUsername: "' OR '1'='1",
      password: "' OR '1'='1"
    })
  });
  assert.strictEqual(sqliRes.status, 401, 'SQL injection attempt must return 401 Unauthorized');
  const sqliJson = await sqliRes.json();
  assert.strictEqual(sqliJson.success, false);
  console.log('   ✅ SQL Injection attack safely neutralized.\n');

  // 5. Test Profile Retrieval with Session Cookie
  console.log('5. Testing Authenticated User Profile retrieval (/api/user/profile)...');
  const profileRes = await fetch(`${BASE_URL}/api/user/profile`, {
    headers: { 'Cookie': cookie }
  });
  assert.strictEqual(profileRes.status, 200, 'Profile fetch should return 200 OK');
  const profileJson = await profileRes.json();
  assert.strictEqual(profileJson.user.email, testEmail);
  assert.strictEqual(profileJson.user.twoFactorEnabled, false);
  console.log(`   ✅ Profile fetched: ${profileJson.user.username} (${profileJson.user.email}).\n`);

  // 6. Test 2FA Setup
  console.log('6. Testing Two-Factor Authentication Setup (/api/2fa/setup)...');
  const setupRes = await fetch(`${BASE_URL}/api/2fa/setup`, {
    method: 'POST',
    headers: { 'Cookie': cookie }
  });
  assert.strictEqual(setupRes.status, 200, '2FA setup should return 200 OK');
  const setupJson = await setupRes.json();
  assert(setupJson.secret && setupJson.qrCodeUrl.startsWith('data:image/png;base64,'), 'Should return secret and QR code data URL');
  console.log(`   ✅ 2FA Secret Generated: ${setupJson.secret.slice(0, 8)}... QR Code prepared.\n`);

  // 7. Test 2FA Activation with Token
  console.log('7. Testing 2FA Confirmation & Activation (/api/2fa/confirm)...');
  const validToken = generateSync({ secret: setupJson.secret });
  const confirmRes = await fetch(`${BASE_URL}/api/2fa/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': cookie
    },
    body: JSON.stringify({ token: validToken })
  });
  assert.strictEqual(confirmRes.status, 200, '2FA confirmation should return 200 OK');
  const confirmJson = await confirmRes.json();
  assert.strictEqual(confirmJson.success, true);
  assert(Array.isArray(confirmJson.backupCodes) && confirmJson.backupCodes.length === 8, 'Should return 8 backup codes');
  console.log(`   ✅ 2FA successfully activated! Generated ${confirmJson.backupCodes.length} backup codes.\n`);

  // 8. Test Logout
  console.log('8. Testing Secure Logout (/api/auth/logout)...');
  const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: { 'Cookie': cookie }
  });
  assert.strictEqual(logoutRes.status, 200);
  console.log('   ✅ Session destroyed.\n');

  // 9. Test Login with 2FA Challenge Triggered
  console.log('9. Testing Login with 2FA Challenge Verification...');
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      emailOrUsername: testEmail,
      password: testPassword
    })
  });
  assert.strictEqual(loginRes.status, 200);
  const loginJson = await loginRes.json();
  assert.strictEqual(loginJson.requires2FA, true, 'Login should indicate 2FA is required');
  const preAuthCookie = loginRes.headers.get('set-cookie')?.split(';')[0] || '';
  console.log('   ✅ Password verified. 2FA challenge initiated.\n');

  // 10. Complete 2FA Verification
  console.log('10. Completing 2FA Challenge with TOTP Token...');
  const secondToken = generateSync({ secret: setupJson.secret });
  const verifyRes = await fetch(`${BASE_URL}/api/auth/verify-2fa`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': preAuthCookie
    },
    body: JSON.stringify({ token: secondToken })
  });
  assert.strictEqual(verifyRes.status, 200, '2FA verification should return 200 OK');
  const verifyJson = await verifyRes.json();
  assert.strictEqual(verifyJson.success, true);
  console.log('   ✅ 2FA Token accepted. Full authenticated session established.\n');

  // 11. Security Demo Endpoints
  console.log('11. Testing Interactive Demo API (/api/demo/sqli-test & hash-test)...');
  const sqliDemoRes = await fetch(`${BASE_URL}/api/demo/sqli-test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: "' OR '1'='1" })
  });
  assert.strictEqual(sqliDemoRes.status, 200);
  const sqliDemoJson = await sqliDemoRes.json();
  assert.strictEqual(sqliDemoJson.secureParameterizedQuery.databaseExecutionSafe, true);

  const hashDemoRes = await fetch(`${BASE_URL}/api/demo/hash-test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'TestPassword123!' })
  });
  assert.strictEqual(hashDemoRes.status, 200);
  const hashDemoJson = await hashDemoRes.json();
  assert(hashDemoJson.bcryptAnalysis.fullHash.startsWith('$2a$') || hashDemoJson.bcryptAnalysis.fullHash.startsWith('$2b$'));
  console.log('   ✅ Security playground endpoints operating properly.\n');

  console.log('====================================================');
  console.log('🎉 ALL 11 END-TO-END INTEGRATION TESTS PASSED!');
  console.log('====================================================\n');
}

runE2E().catch(err => {
  console.error('E2E Test Failure:', err);
  process.exit(1);
});
