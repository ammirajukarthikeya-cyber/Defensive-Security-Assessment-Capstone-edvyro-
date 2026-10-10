/**
 * SecureVault — Main Client Application
 * Handles views, forms, validation, OTP mechanics, session timer, and API requests.
 */

(function () {
  // ---------------------------------------------------------------------------
  // Global Application State
  // ---------------------------------------------------------------------------
  const state = {
    userId: null,
    username: null,
    email: null,
    totpEnabled: false,
    sessionTimeLeft: 1800, // 30 minutes in seconds
  };

  let timerInterval = null;

  // ---------------------------------------------------------------------------
  // UI Helpers & Utilities
  // ---------------------------------------------------------------------------

  /** Show toast alert banner with automatic fadeout */
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`;
    } else if (type === 'error') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
    } else if (type === 'warning') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    }

    toast.innerHTML = `
      ${iconSvg}
      <span class="toast-message"></span>
      <button class="toast-close" aria-label="Close message">&times;</button>
    `;

    // Securely escape message text to prevent DOM/XSS vulnerabilities
    toast.querySelector('.toast-message').textContent = message;
    container.appendChild(toast);

    const removeToast = () => {
      toast.style.animation = 'toastOut 0.3s cubic-bezier(0.36, 0.07, 0.19, 0.97) forwards';
      toast.addEventListener('animationend', () => toast.remove());
    };

    toast.querySelector('.toast-close').addEventListener('click', removeToast);

    setTimeout(() => {
      if (toast.parentNode) removeToast();
    }, 5000);
  }

  /** Switch active view card and clean inputs */
  function showView(viewId) {
    document.querySelectorAll('.view').forEach((view) => {
      view.classList.remove('active');
    });

    const activeView = document.getElementById(viewId);
    if (activeView) {
      activeView.classList.add('active');

      // Clear any form values
      const form = activeView.querySelector('form');
      if (form) {
        form.reset();
        
        // Hide password strength indicator if active
        const strengthEl = form.querySelector('.password-strength');
        if (strengthEl) strengthEl.classList.remove('visible');

        // Reset OTP states
        form.querySelectorAll('.otp-input').forEach((input) => {
          input.value = '';
          input.classList.remove('filled');
        });
      }
    }
  }

  /** Set form loading spinner state */
  function setFormLoading(form, isLoading) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (!submitBtn) return;
    const loader = submitBtn.querySelector('.btn-loader');
    const text = submitBtn.querySelector('.btn-text');

    if (isLoading) {
      submitBtn.disabled = true;
      if (loader) loader.style.display = 'inline-block';
      if (text) text.style.display = 'none';
    } else {
      submitBtn.disabled = false;
      if (loader) loader.style.display = 'none';
      if (text) text.style.display = 'inline-block';
    }
  }

  /** Trigger element shake animation on validation errors */
  function shakeElement(element) {
    element.classList.add('shake');
    element.addEventListener('animationend', () => {
      element.classList.remove('shake');
    }, { once: true });
  }

  // ---------------------------------------------------------------------------
  // Session Lifetime Countdown Timer
  // ---------------------------------------------------------------------------

  function startSessionTimer() {
    if (timerInterval) clearInterval(timerInterval);
    state.sessionTimeLeft = 1800; // Reset countdown to 30 mins
    updateTimerDisplay();

    timerInterval = setInterval(() => {
      state.sessionTimeLeft--;
      if (state.sessionTimeLeft <= 0) {
        clearInterval(timerInterval);
        handleSessionExpiration();
      } else {
        updateTimerDisplay();
      }
    }, 1000);
  }

  function resetSessionTimer() {
    state.sessionTimeLeft = 1800;
    updateTimerDisplay();
  }

  function updateTimerDisplay() {
    const timerEl = document.getElementById('session-timer');
    if (!timerEl) return;
    const mins = Math.floor(state.sessionTimeLeft / 60);
    const secs = state.sessionTimeLeft % 60;
    timerEl.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }

  async function handleSessionExpiration() {
    showToast('Your session has expired. You have been logged out.', 'warning');
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {
      console.error('Session expiration logout failure', e);
    }
    clearSessionState();
    showView('view-login');
  }

  function clearSessionState() {
    if (timerInterval) clearInterval(timerInterval);
    state.userId = null;
    state.username = null;
    state.email = null;
    state.totpEnabled = false;
  }

  // ---------------------------------------------------------------------------
  // Password Complexity Indicator
  // ---------------------------------------------------------------------------
  const regPassword = document.getElementById('reg-password');
  const strengthMeter = document.getElementById('password-strength');
  const strengthFill = document.getElementById('strength-fill');
  const strengthLabel = document.getElementById('strength-label');

  if (regPassword) {
    regPassword.addEventListener('input', () => {
      const val = regPassword.value;
      if (val.length === 0) {
        strengthMeter.classList.remove('visible');
        return;
      }

      strengthMeter.classList.add('visible');

      // Rules check
      let score = 0;
      if (val.length >= 8) score++;
      if (/[A-Z]/.test(val)) score++;
      if (/[a-z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;

      let width = '20%';
      let color = 'var(--strength-weak)';
      let text = 'Weak — Needs length, casing, numbers, & symbols';

      if (score === 3) {
        width = '50%';
        color = 'var(--strength-fair)';
        text = 'Fair — Add special characters or digits';
      } else if (score === 4) {
        width = '75%';
        color = 'var(--strength-good)';
        text = 'Good — Almost secure';
      } else if (score === 5) {
        width = '100%';
        color = 'var(--strength-strong)';
        text = 'Strong — Secure password';
      }

      strengthFill.style.width = width;
      strengthFill.style.backgroundColor = color;
      strengthLabel.textContent = text;
      strengthLabel.style.color = color;
    });
  }

  // ---------------------------------------------------------------------------
  // Interactive OTP Verification Groups
  // ---------------------------------------------------------------------------
  function setupOtpGroup(groupContainerId, submitFormId) {
    const container = document.getElementById(groupContainerId);
    if (!container) return;
    const inputs = container.querySelectorAll('.otp-input');
    const form = document.getElementById(submitFormId);

    inputs.forEach((input, index) => {
      // Key input focus handling
      input.addEventListener('input', (e) => {
        const val = input.value;
        if (val.length > 0) {
          input.value = val.charAt(val.length - 1); // Extract single digit
          input.classList.add('filled');
          
          if (index < inputs.length - 1) {
            inputs[index + 1].focus();
          } else {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.focus();
          }
        } else {
          input.classList.remove('filled');
        }
      });

      // Backspace backwards navigation
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace') {
          if (input.value === '') {
            if (index > 0) {
              inputs[index - 1].focus();
              inputs[index - 1].value = '';
              inputs[index - 1].classList.remove('filled');
            }
          } else {
            input.value = '';
            input.classList.remove('filled');
          }
          e.preventDefault();
        }
      });

      // Handle 6-digit tokens paste
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const data = (e.clipboardData || window.clipboardData).getData('text').trim();
        if (data.length === 6 && /^\d+$/.test(data)) {
          inputs.forEach((inp, idx) => {
            inp.value = data.charAt(idx);
            inp.classList.add('filled');
          });
          const lastInput = inputs[inputs.length - 1];
          lastInput.focus();
          // Trigger form submission event
          form.dispatchEvent(new Event('submit', { cancelable: true }));
        }
      });
    });
  }

  setupOtpGroup('otp-group-verify', 'twofa-verify-form');
  setupOtpGroup('otp-group-setup', 'twofa-setup-form');

  // ---------------------------------------------------------------------------
  // Password Visibility Toggle
  // ---------------------------------------------------------------------------
  document.querySelectorAll('.toggle-password').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;

      const eyeOpen = btn.querySelector('.eye-open');
      const eyeClosed = btn.querySelector('.eye-closed');

      if (input.type === 'password') {
        input.type = 'text';
        if (eyeOpen) eyeOpen.style.display = 'none';
        if (eyeClosed) eyeClosed.style.display = 'inline-block';
      } else {
        input.type = 'password';
        if (eyeOpen) eyeOpen.style.display = 'inline-block';
        if (eyeClosed) eyeClosed.style.display = 'none';
      }
    });
  });

  // ---------------------------------------------------------------------------
  // API Fetch Utility Wrap (Automatic session refresh + defaults)
  // ---------------------------------------------------------------------------
  async function apiFetch(url, options = {}) {
    const defaultHeaders = {
      'Content-Type': 'application/json',
    };
    options.headers = { ...defaultHeaders, ...options.headers };

    try {
      const response = await fetch(url, options);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong.');
      }

      // Successful request indicates active session, reset timer
      resetSessionTimer();
      return data;
    } catch (err) {
      console.error(`API Error [${url}]:`, err);
      throw err;
    }
  }

  // ---------------------------------------------------------------------------
  // Auth Functions & Lifecycle Events
  // ---------------------------------------------------------------------------

  /** Query and populate user dashboard properties */
  async function checkAuthAndPopulateDashboard() {
    try {
      const data = await apiFetch('/api/auth/me');
      state.userId = data.user.id;
      state.username = data.user.username;
      state.email = data.user.email;
      state.totpEnabled = data.user.totpEnabled;

      // Populate dashboard details securely
      document.getElementById('user-greeting').textContent = `Hello, ${state.username}`;
      document.getElementById('user-avatar').textContent = state.username.substring(0, 1).toUpperCase();
      document.getElementById('detail-username').textContent = state.username;
      document.getElementById('detail-email').textContent = state.email;
      document.getElementById('detail-created').textContent = new Date(data.user.createdAt).toLocaleDateString();

      // Configure security states
      const statusIcon = document.getElementById('twofa-status-icon');
      const statusText = document.getElementById('twofa-status-text');
      const toggleBtn = document.getElementById('twofa-toggle-btn');

      if (state.totpEnabled) {
        statusText.textContent = 'Enabled';
        statusIcon.className = 'security-item-icon check';
        statusIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`;
        toggleBtn.textContent = 'Disable';
        toggleBtn.className = 'btn btn-sm btn-danger';
      } else {
        statusText.textContent = 'Not enabled';
        statusIcon.className = 'security-item-icon';
        statusIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
        toggleBtn.textContent = 'Enable';
        toggleBtn.className = 'btn btn-sm btn-accent';
      }

      startSessionTimer();
      showView('view-dashboard');
    } catch (err) {
      clearSessionState();
      showView('view-login');
    }
  }

  // ---------------------------------------------------------------------------
  // Action Handlers
  // ---------------------------------------------------------------------------

  // Login Form Submission
  const loginForm = document.getElementById('login-form');
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      showToast('Please enter both username and password.', 'error');
      if (!username) shakeElement(usernameInput);
      if (!password) shakeElement(passwordInput);
      return;
    }

    setFormLoading(loginForm, true);

    try {
      const data = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });

      if (data.requires2FA) {
        showToast(data.message, 'info');
        showView('view-2fa-verify');
        // Focus first OTP field
        setTimeout(() => {
          const firstOtp = document.querySelector('#otp-group-verify .otp-input');
          if (firstOtp) firstOtp.focus();
        }, 100);
      } else {
        showToast('Successfully signed in!', 'success');
        await checkAuthAndPopulateDashboard();
      }
    } catch (err) {
      showToast(err.message, 'error');
      shakeElement(loginForm.querySelector('.auth-card') || loginForm);
    } finally {
      setFormLoading(loginForm, false);
    }
  });

  // Registration Form Submission
  const registerForm = document.getElementById('register-form');
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const usernameInput = document.getElementById('reg-username');
    const emailInput = document.getElementById('reg-email');
    const passwordInput = document.getElementById('reg-password');
    const confirmInput = document.getElementById('reg-confirm');

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirm = confirmInput.value;

    // Client Validation checks
    let hasError = false;
    if (!username || username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_]+$/.test(username)) {
      showToast('Username must be 3-30 alphanumeric characters / underscores.', 'error');
      shakeElement(usernameInput);
      hasError = true;
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showToast('Please enter a valid email address.', 'error');
      shakeElement(emailInput);
      hasError = true;
    }
    if (!password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
      showToast('Password does not satisfy all validation rules.', 'error');
      shakeElement(passwordInput);
      hasError = true;
    }
    if (password !== confirm) {
      showToast('Passwords do not match.', 'error');
      shakeElement(confirmInput);
      hasError = true;
    }

    if (hasError) return;

    setFormLoading(registerForm, true);

    try {
      await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username, email, password }),
      });

      showToast('Account successfully created!', 'success');
      await checkAuthAndPopulateDashboard();
    } catch (err) {
      showToast(err.message, 'error');
      shakeElement(registerForm.querySelector('.auth-card') || registerForm);
    } finally {
      setFormLoading(registerForm, false);
    }
  });

  // Login 2FA Verification Form
  const twofaVerifyForm = document.getElementById('twofa-verify-form');
  twofaVerifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const inputs = twofaVerifyForm.querySelectorAll('.otp-input');
    let token = '';
    inputs.forEach((inp) => token += inp.value);

    if (token.length !== 6 || !/^\d+$/.test(token)) {
      showToast('Please enter a complete 6-digit code.', 'error');
      shakeElement(document.getElementById('otp-group-verify'));
      return;
    }

    setFormLoading(twofaVerifyForm, true);

    try {
      await apiFetch('/api/2fa/validate', {
        method: 'POST',
        body: JSON.stringify({ token }),
      });

      showToast('Two-factor verification successful!', 'success');
      await checkAuthAndPopulateDashboard();
    } catch (err) {
      showToast(err.message, 'error');
      shakeElement(document.getElementById('otp-group-verify'));
      // Reset inputs on incorrect token
      inputs.forEach((inp) => {
        inp.value = '';
        inp.classList.remove('filled');
      });
      if (inputs[0]) inputs[0].focus();
    } finally {
      setFormLoading(twofaVerifyForm, false);
    }
  });

  // 2FA Setup Setup Form (Confirming secret setup)
  const twofaSetupForm = document.getElementById('twofa-setup-form');
  twofaSetupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const inputs = twofaSetupForm.querySelectorAll('.otp-input');
    let token = '';
    inputs.forEach((inp) => token += inp.value);

    if (token.length !== 6 || !/^\d+$/.test(token)) {
      showToast('Please enter a complete 6-digit verification code.', 'error');
      shakeElement(document.getElementById('otp-group-setup'));
      return;
    }

    setFormLoading(twofaSetupForm, true);

    try {
      await apiFetch('/api/2fa/verify', {
        method: 'POST',
        body: JSON.stringify({ token }),
      });

      showToast('Two-factor authentication successfully enabled!', 'success');
      await checkAuthAndPopulateDashboard();
    } catch (err) {
      showToast(err.message, 'error');
      shakeElement(document.getElementById('otp-group-setup'));
      inputs.forEach((inp) => {
        inp.value = '';
        inp.classList.remove('filled');
      });
      if (inputs[0]) inputs[0].focus();
    } finally {
      setFormLoading(twofaSetupForm, false);
    }
  });

  // 2FA Toggle Action from Dashboard (Enable or Disable)
  const twofaToggleBtn = document.getElementById('twofa-toggle-btn');
  twofaToggleBtn.addEventListener('click', async () => {
    if (state.totpEnabled) {
      // Disable Flow
      const token = prompt('Please enter the current 6-digit code from your authenticator app to disable 2FA:');
      if (token === null) return; // cancelled by user
      
      const cleanToken = token.trim();
      if (cleanToken.length !== 6 || !/^\d+$/.test(cleanToken)) {
        showToast('Invalid format. Token must be a 6-digit number.', 'error');
        return;
      }

      try {
        await apiFetch('/api/2fa/disable', {
          method: 'POST',
          body: JSON.stringify({ token: cleanToken }),
        });
        showToast('Two-factor authentication disabled.', 'success');
        await checkAuthAndPopulateDashboard();
      } catch (err) {
        showToast(err.message, 'error');
      }
    } else {
      // Enable Flow
      try {
        const qrContainer = document.getElementById('qr-container');
        qrContainer.innerHTML = `
          <div class="qr-placeholder">
            <span class="btn-loader large-loader"></span>
            <p>Generating QR code…</p>
          </div>
        `;

        const data = await apiFetch('/api/2fa/setup', { method: 'POST' });
        
        // Show QR Image
        qrContainer.innerHTML = `<img src="${data.qrCode}" alt="Authenticator QR Code" />`;
        document.getElementById('secret-code').textContent = data.secret;
        document.getElementById('secret-display').style.display = 'block';

        showView('view-2fa-setup');
        
        // Focus first setup OTP input
        setTimeout(() => {
          const firstSetupOtp = document.querySelector('#otp-group-setup .otp-input');
          if (firstSetupOtp) firstSetupOtp.focus();
        }, 100);
      } catch (err) {
        showToast(err.message, 'error');
      }
    }
  });

  // Dashboard Sign Out Button
  const logoutBtn = document.getElementById('logout-btn');
  logoutBtn.addEventListener('click', async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
      showToast('Signed out successfully.', 'success');
    } catch (e) {
      showToast('Logout request failed, cleaning local state.', 'warning');
    }
    clearSessionState();
    showView('view-login');
  });

  // ---------------------------------------------------------------------------
  // View Routing Button Events
  // ---------------------------------------------------------------------------
  document.getElementById('go-register').addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-register');
  });

  document.getElementById('go-login').addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-login');
  });

  document.getElementById('go-back-login').addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-login');
  });

  document.getElementById('go-back-dashboard').addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-dashboard');
  });

  // Initialize checks: check if user is already authenticated
  checkAuthAndPopulateDashboard();
})();
