(function () {
  // API Configuration
  const API_BASE = '/api';
  
  // DOM elements
  const inputEl = document.getElementById('newsInput');
  const sourceEl = document.getElementById('sourceInput');
  const btn = document.getElementById('validateBtn');
  const resultEl = document.getElementById('result');
  const themeToggle = document.getElementById('themeToggle');
  const container = document.querySelector('.container');
  const authLink = document.getElementById('authLink');

  // Theme handling
  function getStoredTheme() {
    return localStorage.getItem('theme') || 'dark';
  }
  
  function applyTheme(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', t);
    container.setAttribute('data-theme', t);
    if (themeToggle) themeToggle.textContent = t === 'light' ? '☀️' : '🌙';
  }
  
  function toggleTheme() {
    const current = document.body.getAttribute('data-theme') || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    localStorage.setItem('theme', next);
    applyTheme(next);
  }

  // API functions
  async function validateText(text, source) {
    try {
      const response = await fetch(`${API_BASE}/validation/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ text, source })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.errors?.[0]?.msg || 'Validation failed');
      }

      return await response.json();
    } catch (error) {
      console.error('Validation error:', error);
      throw error;
    }
  }

  async function getAuthStatus() {
    try {
      const response = await fetch(`${API_BASE}/auth/status`, {
        credentials: 'include'
      });
      return await response.json();
    } catch (error) {
      console.error('Auth status error:', error);
      return { authenticated: false, user: null };
    }
  }

  async function logout() {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  // Validation result rendering
  function renderResult(data, error = null) {
    if (error) {
      resultEl.innerHTML = `
        <div class="badge bad">
          <span class="dot"></span>
          <strong>Error: ${error}</strong>
        </div>
      `;
      return;
    }

    const { score, classification, reasons, confidence } = data;
    const reasonList = reasons.length
      ? `<ul class="reasons">${reasons.map(r => `<li>${r}</li>`).join('')}</ul>`
      : '';
    
    resultEl.innerHTML = `
      <div class="badge ${classification.tone}">
        <span class="dot"></span>
        <strong>${classification.label}</strong>
        <span style="opacity:.7; margin-left:8px;">(score: ${score.toFixed(2)})</span>
        <span style="opacity:.6; margin-left:8px;">confidence: ${confidence}%</span>
      </div>
      ${reasonList}
    `;
  }

  // Validation function
  async function validate() {
    const text = inputEl.value.trim();
    const source = sourceEl.value.trim();
    
    if (!text) {
      renderResult(null, 'Please enter some text to validate');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Validating...';

    try {
      const result = await validateText(text, source || null);
      renderResult(result);
    } catch (error) {
      renderResult(null, error.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Validate';
    }
  }

  // Auth UI management
  function applyAuthUi(authData) {
    if (!authLink) return;
    
    if (authData.authenticated && authData.user) {
      authLink.textContent = `Logout (${authData.user.email})`;
      authLink.href = '#';
      authLink.onclick = async (e) => {
        e.preventDefault();
        await logout();
        await checkAuthAndUpdateUI();
      };
    } else {
      authLink.textContent = 'Login';
      authLink.href = '/login';
      authLink.onclick = null;
    }
  }

  async function checkAuthAndUpdateUI() {
    const authData = await getAuthStatus();
    applyAuthUi(authData);
    return authData;
  }

  // Event listeners
  if (btn) {
    btn.addEventListener('click', validate);
  }

  if (inputEl) {
    inputEl.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'enter') {
        validate();
      }
    });
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }

  // Initialize
  applyTheme(getStoredTheme());
  checkAuthAndUpdateUI();
})();