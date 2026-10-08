// ==========================================================
// SECURE LOGIN SYSTEM: INTERACTIVE SECURITY DEMO LOGIC
// Demonstrates SQL Injection Neutralization and bcrypt Salting
// ==========================================================

document.addEventListener('DOMContentLoaded', () => {
  initSQLiDemo();
  initHashDemo();
  initHeaderInspection();
});

function initSQLiDemo() {
  const form = document.getElementById('sqli-demo-form');
  const payloadPresets = document.querySelectorAll('.sqli-preset');

  payloadPresets.forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('sqli-input').value = btn.getAttribute('data-payload');
      form.dispatchEvent(new Event('submit'));
    });
  });

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('sqli-input').value;
      const resultContainer = document.getElementById('sqli-result-container');

      resultContainer.innerHTML = '<p style="color: #94a3b8;">Executing security analysis...</p>';

      try {
        const res = await fetch('/api/demo/sqli-test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input })
        });
        const data = await res.json();

        resultContainer.innerHTML = `
          <div style="margin-bottom: 1.25rem;">
            <div style="font-weight: 700; color: #ef4444; margin-bottom: 0.35rem;">⚠️ What happens in a VULNERABLE app (String Concatenation):</div>
            <pre style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); padding: 0.75rem; border-radius: 0.5rem; overflow-x: auto; color: #fca5a5;"><code>${escapeHtml(data.vulnerableQuerySimulation.rawConstructedSql)}</code></pre>
            <p style="font-size: 0.85rem; color: #94a3b8; margin-top: 0.35rem;">Notice how input broke out of quotes, altering the boolean condition and giving attackers unauthorized database access.</p>
          </div>

          <div>
            <div style="font-weight: 700; color: #10b981; margin-bottom: 0.35rem;">🛡️ How THIS APP protects you (Prepared Parameterized Statements):</div>
            <pre style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.75rem; border-radius: 0.5rem; overflow-x: auto; color: #6ee7b7;"><code>SQL Query: ${escapeHtml(data.secureParameterizedQuery.parameterizedSqlTemplate)}
Parameter Bound as Literal: "${escapeHtml(data.secureParameterizedQuery.parameterBound)}"</code></pre>
            <p style="font-size: 0.85rem; color: #6ee7b7; margin-top: 0.35rem;">Outcome: ${escapeHtml(data.secureParameterizedQuery.note)}. The database engine compiles SQL before parameters are bound, rendering injection mathematically impossible.</p>
          </div>
        `;
      } catch (err) {
        resultContainer.innerHTML = '<p style="color: #ef4444;">Failed to execute test.</p>';
      }
    });
  }
}

function initHashDemo() {
  const form = document.getElementById('hash-demo-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('hash-password-input').value;
    const resultContainer = document.getElementById('hash-result-container');

    resultContainer.innerHTML = '<p style="color: #94a3b8;">Computing cryptographic bcrypt rounds...</p>';

    try {
      const res = await fetch('/api/demo/hash-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      const analysis = data.bcryptAnalysis;

      resultContainer.innerHTML = `
        <div style="margin-top: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span style="font-size: 0.85rem; color: #94a3b8;">Computation Duration: <strong style="color: #38bdf8;">${analysis.computationTimeMs}</strong></span>
            <span class="badge badge-success">${analysis.costFactor}</span>
          </div>
          <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.2rem;">Generated Unique Salt (29 characters):</div>
            <code style="background: rgba(0,0,0,0.4); padding: 0.4rem 0.6rem; border-radius: 0.25rem; display: block; word-break: break-all; color: #f59e0b;">${escapeHtml(analysis.saltGenerated)}</code>
          </div>
          <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.2rem;">Final Bcrypt Hash (Stored in Database):</div>
            <code style="background: rgba(0,0,0,0.4); padding: 0.4rem 0.6rem; border-radius: 0.25rem; display: block; word-break: break-all; color: #38bdf8;">${escapeHtml(analysis.fullHash)}</code>
          </div>
          <ul style="list-style: disc; margin-left: 1.25rem; font-size: 0.8rem; color: #94a3b8;">
            ${analysis.securityBenefits.map(b => `<li>${escapeHtml(b)}</li>`).join('')}
          </ul>
        </div>
      `;
    } catch (err) {
      resultContainer.innerHTML = '<p style="color: #ef4444;">Failed to execute hash test.</p>';
    }
  });
}

async function initHeaderInspection() {
  const container = document.getElementById('security-info-container');
  if (!container) return;

  try {
    const res = await fetch('/api/demo/security-info');
    const data = await res.json();
    const sec = data.securityArchitecture;

    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
        <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 0.5rem; border: 1px solid var(--border-color);">
          <div style="font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem;">🍪 Session Cookie Flags</div>
          <ul style="list-style: none; font-size: 0.85rem; color: #cbd5e1;">
            <li>✓ <strong>HttpOnly:</strong> ${sec.sessionCookie.httpOnly} (Mitigates XSS cookie theft)</li>
            <li>✓ <strong>SameSite:</strong> ${sec.sessionCookie.sameSite} (Mitigates CSRF)</li>
            <li>✓ <strong>Masked SID:</strong> Custom cookie identifier</li>
          </ul>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 0.5rem; border: 1px solid var(--border-color);">
          <div style="font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem;">🛡️ Defensive Headers (Helmet)</div>
          <ul style="list-style: none; font-size: 0.85rem; color: #cbd5e1;">
            <li>✓ <strong>CSP:</strong> Content-Security-Policy</li>
            <li>✓ <strong>Clickjacking:</strong> X-Frame-Options DENY</li>
            <li>✓ <strong>MIME Sniffing:</strong> X-Content-Type nosniff</li>
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = '<p style="color: #ef4444;">Could not load security details.</p>';
  }
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[tag] || tag));
}
