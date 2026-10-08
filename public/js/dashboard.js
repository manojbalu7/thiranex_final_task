// ==========================================================
// SECURE LOGIN SYSTEM: DASHBOARD & 2FA MANAGEMENT
// Profile, Audit Logs, TOTP 2FA Setup Flow, Password Change
// ==========================================================

let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
  loadUserProfile();
  loadAuditLogs();
  initModals();
  initPasswordForm();
  initLogout();
});

/**
 * Loads user profile data & session security state
 */
async function loadUserProfile() {
  try {
    const res = await fetch('/api/user/profile');
    if (res.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    const data = await res.json();
    if (!data.success) {
      window.location.href = '/login.html';
      return;
    }

    currentUser = data.user;

    // Render User Info
    document.getElementById('user-name-display').innerText = currentUser.username;
    document.getElementById('profile-username').innerText = currentUser.username;
    document.getElementById('profile-email').innerText = currentUser.email;
    document.getElementById('profile-created').innerText = new Date(currentUser.createdAt).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });

    // Render Session Info
    document.getElementById('session-id-preview').innerText = data.session.sessionId;

    // Render 2FA Status
    const statusBadge = document.getElementById('2fa-status-badge');
    const enableBtn = document.getElementById('btn-enable-2fa');
    const disableBtn = document.getElementById('btn-disable-2fa');

    if (currentUser.twoFactorEnabled) {
      statusBadge.className = 'badge badge-success';
      statusBadge.innerText = 'Active & Protected';
      enableBtn.style.display = 'none';
      disableBtn.style.display = 'inline-flex';
    } else {
      statusBadge.className = 'badge badge-warning';
      statusBadge.innerText = 'Disabled (Recommended)';
      enableBtn.style.display = 'inline-flex';
      disableBtn.style.display = 'none';
    }
  } catch (err) {
    console.error('Failed to load profile:', err);
  }
}

/**
 * Loads security audit logs
 */
async function loadAuditLogs() {
  const tableBody = document.getElementById('audit-table-body');
  try {
    const res = await fetch('/api/user/audit-logs');
    const data = await res.json();

    if (!data.success || !data.logs || data.logs.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: #94a3b8;">No audit logs recorded yet.</td></tr>';
      return;
    }

    tableBody.innerHTML = data.logs.map(log => {
      let badgeClass = 'badge-info';
      if (log.status.includes('SUCCESS') || log.status === 'REGISTERED') badgeClass = 'badge-success';
      if (log.status.includes('FAILED') || log.status.includes('LOCKED')) badgeClass = 'badge-danger';
      if (log.status.includes('2FA_CHALLENGE') || log.status.includes('2FA_DISABLED')) badgeClass = 'badge-warning';

      const formattedTime = new Date(log.timestamp).toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
      });

      return `
        <tr>
          <td><span class="badge ${badgeClass}">${escapeHtml(log.status)}</span></td>
          <td><code>${escapeHtml(log.ip_address || '127.0.0.1')}</code></td>
          <td style="color:#94a3b8; font-size: 0.8rem;">${escapeHtml(truncate(log.user_agent, 36))}</td>
          <td style="color:#cbd5e1;">${formattedTime}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: #ef4444;">Failed to load logs.</td></tr>';
  }
}

/**
 * Initializes 2FA Setup, Confirmation, and Disable Modals
 */
function initModals() {
  const enableBtn = document.getElementById('btn-enable-2fa');
  const disableBtn = document.getElementById('btn-disable-2fa');
  const setupModal = document.getElementById('setup-2fa-modal');
  const backupModal = document.getElementById('backup-codes-modal');
  const disableModal = document.getElementById('disable-2fa-modal');

  const closeButtons = document.querySelectorAll('.modal-close');
  closeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      setupModal.style.display = 'none';
      backupModal.style.display = 'none';
      disableModal.style.display = 'none';
    });
  });

  // Enable 2FA Click: Fetch QR Code and Secret
  if (enableBtn) {
    enableBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/2fa/setup', { method: 'POST' });
        const data = await res.json();

        if (data.success) {
          document.getElementById('qr-image').src = data.qrCodeUrl;
          document.getElementById('secret-key-text').innerText = data.secret;
          document.getElementById('setup-alert').style.display = 'none';
          document.getElementById('confirm-code-input').value = '';
          setupModal.style.display = 'flex';
        } else {
          alert(data.error || 'Could not initiate 2FA setup.');
        }
      } catch (e) {
        alert('Network error while requesting 2FA setup.');
      }
    });
  }

  // Copy secret key
  const copyKeyBtn = document.getElementById('btn-copy-secret');
  if (copyKeyBtn) {
    copyKeyBtn.addEventListener('click', () => {
      const text = document.getElementById('secret-key-text').innerText;
      navigator.clipboard.writeText(text).then(() => {
        copyKeyBtn.innerText = 'Copied!';
        setTimeout(() => copyKeyBtn.innerText = 'Copy Key', 2000);
      });
    });
  }

  // Confirm 2FA Code
  const confirmForm = document.getElementById('confirm-2fa-form');
  if (confirmForm) {
    confirmForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('confirm-code-input').value.trim();
      const alertBox = document.getElementById('setup-alert');
      const submitBtn = document.getElementById('btn-submit-confirm');

      setLoading(submitBtn, true, 'Verifying...');

      try {
        const res = await fetch('/api/2fa/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });
        const data = await res.json();

        if (data.success) {
          setupModal.style.display = 'none';
          renderBackupCodesModal(data.backupCodes);
          loadUserProfile();
          loadAuditLogs();
        } else {
          showAlert(alertBox, data.error || 'Failed to verify code.', 'danger');
        }
      } catch (err) {
        showAlert(alertBox, 'Communication error.', 'danger');
      } finally {
        setLoading(submitBtn, false, 'Verify & Activate 2FA');
      }
    });
  }

  // Disable 2FA Click
  if (disableBtn) {
    disableBtn.addEventListener('click', () => {
      document.getElementById('disable-password-input').value = '';
      document.getElementById('disable-alert').style.display = 'none';
      disableModal.style.display = 'flex';
    });
  }

  // Confirm Disable 2FA Form
  const disableForm = document.getElementById('disable-2fa-form');
  if (disableForm) {
    disableForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('disable-password-input').value;
      const alertBox = document.getElementById('disable-alert');
      const submitBtn = document.getElementById('btn-confirm-disable');

      setLoading(submitBtn, true, 'Disabling...');

      try {
        const res = await fetch('/api/2fa/disable', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();

        if (data.success) {
          disableModal.style.display = 'none';
          loadUserProfile();
          loadAuditLogs();
          alert('Two-Factor Authentication has been disabled.');
        } else {
          showAlert(alertBox, data.error || 'Failed to disable 2FA.', 'danger');
        }
      } catch (err) {
        showAlert(alertBox, 'Communication error.', 'danger');
      } finally {
        setLoading(submitBtn, false, 'Confirm & Disable');
      }
    });
  }
}

/**
 * Renders backup codes modal after successful 2FA activation
 */
function renderBackupCodesModal(codes) {
  const modal = document.getElementById('backup-codes-modal');
  const container = document.getElementById('backup-codes-container');

  container.innerHTML = codes.map(c => `<div><code>${c}</code></div>`).join('');

  document.getElementById('btn-copy-backup').onclick = () => {
    navigator.clipboard.writeText(codes.join('\n')).then(() => {
      document.getElementById('btn-copy-backup').innerText = 'Copied!';
      setTimeout(() => document.getElementById('btn-copy-backup').innerText = 'Copy Codes', 2000);
    });
  };

  document.getElementById('btn-download-backup').onclick = () => {
    const text = `SECURE LOGIN SYSTEM - EMERGENCY BACKUP RECOVERY CODES\nAccount: ${currentUser?.email}\nGenerated: ${new Date().toISOString()}\n\n` +
      codes.map((c, i) => `Code ${i + 1}: ${c}`).join('\n') +
      '\n\nKeep these codes safe. Each code can be used once if you lose access to your authenticator app.';
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '2FA-Backup-Codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  modal.style.display = 'flex';
}

/**
 * Initializes Password Change Form
 */
function initPasswordForm() {
  const form = document.getElementById('change-password-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const alertBox = document.getElementById('password-alert');
    const submitBtn = document.getElementById('btn-update-password');

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmNewPassword = document.getElementById('confirm-new-password').value;

    setLoading(submitBtn, true, 'Updating...');

    try {
      const res = await fetch('/api/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword, confirmNewPassword })
      });
      const data = await res.json();

      if (data.success) {
        showAlert(alertBox, 'Password successfully updated!', 'success');
        form.reset();
        loadAuditLogs();
      } else {
        showAlert(alertBox, data.error || 'Failed to update password.', 'danger');
      }
    } catch (err) {
      showAlert(alertBox, 'Network error.', 'danger');
    } finally {
      setLoading(submitBtn, false, 'Change Password');
    }
  });
}

/**
 * Initializes Secure Logout
 */
function initLogout() {
  const logoutBtn = document.getElementById('btn-logout');
  if (!logoutBtn) return;

  logoutBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      window.location.href = '/login.html';
    }
  });
}

// Utility Helpers
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

function escapeHtml(str) {
  return String(str || '').replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[tag] || tag));
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '...' : str;
}
