(function () {
  const container = document.querySelector('.container');
  const themeToggle = document.getElementById('themeToggle');
  const form = document.getElementById('loginForm');
  const msg = document.getElementById('loginMsg');
  const registerToggle = document.getElementById('registerToggle');

  const API_BASE = '/api';

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

  // Auth API functions
  async function login(email, password) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }

    return data;
  }

  async function register(email, password, name) {
    const response = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ email, password, name })
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Registration failed');
    }

    return data;
  }

  // UI functions
  function showMessage(message, type = 'success') {
    msg.innerHTML = `<div class="badge ${type}"><span class="dot"></span><strong>${message}</strong></div>`;
  }

  function toggleRegisterMode() {
    const isRegister = registerToggle.textContent.includes('Register');
    const submitBtn = form.querySelector('button[type="submit"]');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    
    if (isRegister) {
      // Switch to register mode
      submitBtn.textContent = 'Register';
      document.getElementById('name').style.display = 'block';
      registerToggle.textContent = 'Already have an account? Login';
      
      // Add name field if it doesn't exist
      if (!document.getElementById('nameLabel')) {
        const nameLabel = document.createElement('label');
        nameLabel.id = 'nameLabel';
        nameLabel.className = 'input-label';
        nameLabel.htmlFor = 'name';
        nameLabel.textContent = 'Name (optional)';
        
        const nameInput = document.createElement('input');
        nameInput.id = 'name';
        nameInput.className = 'input input--text';
        nameInput.type = 'text';
        nameInput.placeholder = 'Your name';
        
        passwordInput.parentNode.insertBefore(nameLabel, passwordInput);
        passwordInput.parentNode.insertBefore(nameInput, passwordInput);
      }
    } else {
      // Switch to login mode
      submitBtn.textContent = 'Login';
      document.getElementById('name').style.display = 'none';
      registerToggle.textContent = 'Need an account? Register';
    }
  }

  // Event listeners
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }

  if (registerToggle) {
    registerToggle.addEventListener('click', (e) => {
      e.preventDefault();
      toggleRegisterMode();
    });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const name = document.getElementById('name')?.value.trim() || '';
    const isRegister = document.getElementById('name').style.display !== 'none';
    
    if (!email || !password) {
      showMessage('Please fill in all required fields', 'bad');
      
      return;
    }
    
    // Handle registration
    if (isRegister) {
      try {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Registering...';
        
        await register(email, password, name);
        showMessage('Registration successful! Redirecting...');
        
        setTimeout(() => {
          window.location.href = '/';
        }, 1500);
      } catch (error) {
        showMessage(error.message, 'bad');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Register';
      }
    } else {
      // Handle login
      try {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';
        
        const result = await login(email, password);
        showMessage('Login successful! Redirecting...');
        
        setTimeout(() => {
          window.location.href = '/';
        }, 1000);
      } catch (error) {
        showMessage(error.message, 'bad');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
      }
    }
  });

  // Initialize
  applyTheme(getStoredTheme());
})();
