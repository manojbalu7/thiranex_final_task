// ==========================================================
// SECURE LOGIN SYSTEM: 2FA VERIFICATION HANDLER
// Supports 6-digit TOTP tokens and emergency backup codes
// ==========================================================

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('verify-2fa-form');
  const alertBox = document.getElementById('verify-alert');
  const submitBtn = document.getElementById('verify-btn');
  const toggleBackupBtn = document.getElementById('toggle-backup-mode');
  const codeLabel = document.getElementById('code-label');
  const tokenInput = document.getElementById('token-input');

  let isBackupMode = false;

  if (toggleBackupBtn) {
    toggleBackupBtn.addEventListener('click', (e) => {
      e.preventDefault();
      isBackupMode = !isBackupMode;

      if (isBackupMode) {
        codeLabel.innerText = 'Emergency Backup Code';
        tokenInput.placeholder = 'e.g. A1B2-C3D4';
        tokenInput.maxLength = 10;
        toggleBackupBtn.innerText = '← Use 6-digit Authenticator Code';
      } else {
        codeLabel.innerText = '6-Digit Authenticator Code';
        tokenInput.placeholder = '000000';
        tokenInput.maxLength = 6;
        toggleBackupBtn.innerText = 'Lost phone? Use an Emergency Backup Code';
      }
      tokenInput.value = '';
      tokenInput.focus();
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = tokenInput.value.trim();

      if (!token) {
        showAlert(alertBox, 'Please enter your verification code.', 'danger');
        return;
      }

      setLoading(submitBtn, true, 'Verifying...');

      try {
        const response = await fetch('/api/auth/verify-2fa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });

        const data = await response.json();

        if (data.success) {
          showAlert(alertBox, 'Verification complete! Redirecting...', 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/dashboard.html';
          }, 800);
        } else {
          showAlert(alertBox, data.error || 'Verification failed.', 'danger');
          tokenInput.value = '';
          tokenInput.focus();
        }
      } catch (err) {
        showAlert(alertBox, 'Network communication error.', 'danger');
      } finally {
        setLoading(submitBtn, false, 'Verify Code');
      }
    });
  }
});

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
