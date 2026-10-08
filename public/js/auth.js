// ==========================================================
// SECURE LOGIN SYSTEM: CLIENT-SIDE AUTH LOGIC
// Real-time validation, password strength calculator, submission
// ==========================================================

document.addEventListener('DOMContentLoaded', () => {
  const registerForm = document.getElementById('register-form');
  const loginForm = document.getElementById('login-form');

  // --- PASSWORD STRENGTH CALCULATION ---
  const passwordInput = document.getElementById('password');
  if (passwordInput && registerForm) {
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');
    const checkLength = document.getElementById('check-length');
    const checkUpper = document.getElementById('check-upper');
    const checkLower = document.getElementById('check-lower');
    const checkNumber = document.getElementById('check-number');
    const checkSpecial = document.getElementById('check-special');

    passwordInput.addEventListener('input', () => {
      const val = passwordInput.value;

      const hasLength = val.length >= 8;
      const hasUpper = /[A-Z]/.test(val);
      const hasLower = /[a-z]/.test(val);
      const hasNumber = /[0-9]/.test(val);
      const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(val);

      // Update Checklist UI
      updateCheckItem(checkLength, hasLength);
      updateCheckItem(checkUpper, hasUpper);
      updateCheckItem(checkLower, hasLower);
      updateCheckItem(checkNumber, hasNumber);
      updateCheckItem(checkSpecial, hasSpecial);

      // Score 0 to 5
      const score = [hasLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;

      // Update Strength Bar & Color
      if (val.length === 0) {
        strengthBar.style.width = '0%';
        strengthBar.style.backgroundColor = 'transparent';
        strengthText.innerText = '';
      } else if (score <= 2) {
        strengthBar.style.width = '30%';
        strengthBar.style.backgroundColor = '#ef4444'; // Red
        strengthText.innerText = 'Weak';
        strengthText.style.color = '#ef4444';
      } else if (score <= 4) {
        strengthBar.style.width = '70%';
        strengthBar.style.backgroundColor = '#f59e0b'; // Amber
        strengthText.innerText = 'Moderate';
        strengthText.style.color = '#f59e0b';
      } else {
        strengthBar.style.width = '100%';
        strengthBar.style.backgroundColor = '#10b981'; // Green
        strengthText.innerText = 'Strong & Secure';
        strengthText.style.color = '#10b981';
      }
    });
  }

  function updateCheckItem(element, isValid) {
    if (!element) return;
    if (isValid) {
      element.classList.add('valid');
      element.innerHTML = '✓ ' + element.innerText.replace(/^[✓✗•]\s*/, '');
    } else {
      element.classList.remove('valid');
      element.innerHTML = '• ' + element.innerText.replace(/^[✓✗•]\s*/, '');
    }
  }

  // --- REGISTRATION SUBMISSION ---
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const alertBox = document.getElementById('auth-alert');
      const submitBtn = document.getElementById('submit-btn');

      const username = document.getElementById('username').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;

      if (password !== confirmPassword) {
        showAlert(alertBox, 'Passwords do not match.', 'danger');
        return;
      }

      setLoading(submitBtn, true, 'Creating Account...');

      try {
        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password, confirmPassword })
        });

        const data = await response.json();

        if (data.success) {
          showAlert(alertBox, 'Registration successful! Directing to dashboard...', 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/dashboard.html';
          }, 1000);
        } else {
          showAlert(alertBox, data.error || 'Registration failed.', 'danger');
        }
      } catch (err) {
        showAlert(alertBox, 'Connection error. Please try again.', 'danger');
      } finally {
        setLoading(submitBtn, false, 'Register Account');
      }
    });
  }

  // --- LOGIN SUBMISSION ---
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const alertBox = document.getElementById('auth-alert');
      const submitBtn = document.getElementById('submit-btn');

      const emailOrUsername = document.getElementById('emailOrUsername').value.trim();
      const password = document.getElementById('password').value;

      setLoading(submitBtn, true, 'Authenticating...');

      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ emailOrUsername, password })
        });

        const data = await response.json();

        if (data.success) {
          if (data.requires2FA) {
            showAlert(alertBox, '2FA Required. Redirecting to verification...', 'warning');
            setTimeout(() => {
              window.location.href = '/verify-2fa.html';
            }, 800);
          } else {
            showAlert(alertBox, 'Login verified! Welcome back.', 'success');
            setTimeout(() => {
              window.location.href = data.redirect || '/dashboard.html';
            }, 800);
          }
        } else {
          showAlert(alertBox, data.error || 'Authentication failed.', 'danger');
        }
      } catch (err) {
        showAlert(alertBox, 'Server communication error.', 'danger');
      } finally {
        setLoading(submitBtn, false, 'Sign In');
      }
    });
  }
});

// Helper functions
function showAlert(el, msg, type = 'danger') {
  if (!el) return;
  el.className = `alert alert-${type}`;
  el.innerText = msg;
  el.style.display = 'block';
}

function setLoading(btn, isLoading, text) {
  if (!btn) return;
  btn.disabled = isLoading;
  btn.innerText = text;
}
