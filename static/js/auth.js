/* ============================================================
   auth.js — Event Management System
   Handles: SHA-256 password hashing, form validation,
            password toggle, role selector, strength meter,
            loading states, flash auto-dismiss
   ============================================================ */

(function () {
    'use strict';

    /* ── SHA-256 via Web Crypto API ───────────────────────── */
    async function sha256(message) {
        const encoder = new TextEncoder();
        const data    = encoder.encode(message);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const hashArr = Array.from(new Uint8Array(hashBuf));
        return hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /* ── Helpers ──────────────────────────────────────────── */
    function $(id)   { return document.getElementById(id); }
    function $q(sel) { return document.querySelector(sel); }

    function setError(inputEl, errorEl, msg) {
        if (inputEl) inputEl.classList.add('is-error');
        if (errorEl) errorEl.textContent = msg;
    }

    function clearError(inputEl, errorEl) {
        if (inputEl) inputEl.classList.remove('is-error');
        if (errorEl) errorEl.textContent = '';
    }

    function showAlert(alertEl, msg, type = 'error') {
        if (!alertEl) return;
        alertEl.textContent = msg;
        alertEl.className   = `auth-alert ${type === 'error' ? 'show-error' : 'show-success'}`;
    }

    function hideAlert(alertEl) {
        if (!alertEl) return;
        alertEl.className   = 'auth-alert';
        alertEl.textContent = '';
    }

    function setLoading(btnEl, active) {
        if (!btnEl) return;
        btnEl.disabled = active;
        btnEl.classList.toggle('loading', active);
    }

    /* ── Validators ───────────────────────────────────────── */
    function validateEmail(val) {
        if (!val.trim())                          return 'Email is required.';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return 'Enter a valid email address.';
        return null;
    }

    function validatePassword(val) {
        if (!val)          return 'Password is required.';
        if (val.length < 6) return 'Password must be at least 6 characters.';
        return null;
    }

    function validateName(val) {
        if (!val.trim())   return 'Full name is required.';
        if (val.trim().length < 2) return 'Name must be at least 2 characters.';
        return null;
    }

    /* ── Password strength ────────────────────────────────── */
    function getStrength(password) {
        let score = 0;
        if (password.length >= 8)                       score++;
        if (password.length >= 12)                      score++;
        if (/[A-Z]/.test(password))                     score++;
        if (/[0-9]/.test(password))                     score++;
        if (/[^A-Za-z0-9]/.test(password))              score++;
        if (score <= 1) return { level: 0, label: 'Weak' };
        if (score <= 3) return { level: 1, label: 'Fair' };
        return { level: 2, label: 'Strong' };
    }

    function renderStrength(password, meterEl, labelEl) {
        if (!meterEl) return;
        const bars   = meterEl.querySelectorAll('.strength-bar');
        const result = getStrength(password);

        bars.forEach((bar, i) => {
            bar.className = 'strength-bar';
            if (i <= result.level) {
                if (result.level === 0) bar.classList.add('weak');
                else if (result.level === 1) bar.classList.add('fair');
                else bar.classList.add('strong');
            }
        });

        if (labelEl) {
            const colors = { 0: '#f87171', 1: '#fbbf24', 2: '#4ade80' };
            labelEl.textContent = result.label;
            labelEl.style.color = colors[result.level];
        }
    }

    /* ── Password visibility toggle ───────────────────────── */
    function initPasswordToggle(inputId, toggleId, eyeOpenId, eyeClosedId) {
        const input     = $(inputId);
        const toggle    = $(toggleId);
        const eyeOpen   = $(eyeOpenId);
        const eyeClosed = $(eyeClosedId);
        if (!input || !toggle) return;

        toggle.addEventListener('click', () => {
            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            if (eyeOpen)   eyeOpen.style.display   = isHidden ? 'none'  : 'block';
            if (eyeClosed) eyeClosed.style.display  = isHidden ? 'block' : 'none';
            toggle.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
        });
    }

    /* ── Flash auto-dismiss ───────────────────────────────── */
    function initFlashDismiss() {
        const flashes = document.querySelectorAll('.flash');
        flashes.forEach(flash => {
            // Auto remove after 5s
            setTimeout(() => flash.remove(), 5000);

            const closeBtn = flash.querySelector('.flash-close');
            if (closeBtn) closeBtn.addEventListener('click', () => flash.remove());
        });
    }

    /* ══════════════════════════════════════════════════════
       LOGIN PAGE
       ══════════════════════════════════════════════════════ */
    function initLogin() {
        const form      = $('login-form');
        if (!form) return;

        const emailInput  = $('email');
        const passInput   = $('password');
        const passHash    = $('password_hash');
        const submitBtn   = $('submit-btn');
        const emailErr    = $('email-error');
        const passErr     = $('password-error');
        const alertBox    = $('auth-alert');
        const toggleBtn   = $('toggle-password');

        /* Password toggle */
        initPasswordToggle('password', 'toggle-password', 'eye-open', 'eye-closed');

        /* Live validation on blur */
        if (emailInput) {
            emailInput.addEventListener('blur', () => {
                const err = validateEmail(emailInput.value);
                err ? setError(emailInput, emailErr, err) : clearError(emailInput, emailErr);
            });
            emailInput.addEventListener('input', () => clearError(emailInput, emailErr));
        }

        if (passInput) {
            passInput.addEventListener('blur', () => {
                const err = validatePassword(passInput.value);
                err ? setError(passInput, passErr, err) : clearError(passInput, passErr);
            });
            passInput.addEventListener('input', () => clearError(passInput, passErr));
        }

        /* Submit */
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            hideAlert(alertBox);

            const emailErr_v = validateEmail(emailInput ? emailInput.value : '');
            const passErr_v  = validatePassword(passInput ? passInput.value : '');

            if (emailErr_v) setError(emailInput, emailErr, emailErr_v);
            else            clearError(emailInput, emailErr);

            if (passErr_v)  setError(passInput, passErr, passErr_v);
            else            clearError(passInput, passErr);

            if (emailErr_v || passErr_v) return;

            setLoading(submitBtn, true);

            try {
                const hashed = await sha256(passInput.value);
                if (passHash) passHash.value = hashed;

                /* Clear plain-text password before submit */
                passInput.value = '';

                this.submit();
            } catch (err) {
                console.error('[auth.js] Login hash error:', err);
                showAlert(alertBox, 'Something went wrong. Please try again.', 'error');
                setLoading(submitBtn, false);
            }
        });

        /* Server-side flash via data attribute */
        const flashMsg  = form.dataset.flash;
        const flashType = form.dataset.flashType || 'error';
        if (flashMsg) showAlert(alertBox, flashMsg, flashType);
    }

    /* ══════════════════════════════════════════════════════
       SIGNUP PAGE
       ══════════════════════════════════════════════════════ */
    function initSignup() {
        const form = $('signup-form');
        if (!form) return;

        const nameInput     = $('name');
        const emailInput    = $('email');
        const passInput     = $('password');
        const passConfirm   = $('password_confirm');
        const passHash      = $('password_hash');
        const submitBtn     = $('submit-btn');
        const alertBox      = $('auth-alert');
        const nameErr       = $('name-error');
        const emailErr      = $('email-error');
        const passErr       = $('password-error');
        const confirmErr    = $('confirm-error');
        const strengthMeter = $('strength-meter');
        const strengthLabel = $('strength-label');
        const categoryField = $('category-field');
        const roleInputs    = document.querySelectorAll('input[name="role"]');

        /* Password toggle */
        initPasswordToggle('password', 'toggle-password', 'eye-open', 'eye-closed');
        initPasswordToggle('password_confirm', 'toggle-confirm', 'eye-open-2', 'eye-closed-2');

        /* Show/hide category based on role */
        function updateCategoryVisibility() {
            const selected = document.querySelector('input[name="role"]:checked');
            if (!categoryField) return;
            if (selected && selected.value === 'vendor') {
                categoryField.classList.add('visible');
            } else {
                categoryField.classList.remove('visible');
            }
        }

        roleInputs.forEach(r => r.addEventListener('change', updateCategoryVisibility));
        updateCategoryVisibility();

        /* Password strength meter */
        if (passInput && strengthMeter) {
            passInput.addEventListener('input', () => {
                if (passInput.value.length > 0) {
                    strengthMeter.classList.add('visible');
                    renderStrength(passInput.value, strengthMeter, strengthLabel);
                } else {
                    strengthMeter.classList.remove('visible');
                }
            });
        }

        /* Live validation */
        if (nameInput) {
            nameInput.addEventListener('blur', () => {
                const err = validateName(nameInput.value);
                err ? setError(nameInput, nameErr, err) : clearError(nameInput, nameErr);
            });
            nameInput.addEventListener('input', () => clearError(nameInput, nameErr));
        }

        if (emailInput) {
            emailInput.addEventListener('blur', () => {
                const err = validateEmail(emailInput.value);
                err ? setError(emailInput, emailErr, err) : clearError(emailInput, emailErr);
            });
            emailInput.addEventListener('input', () => clearError(emailInput, emailErr));
        }

        if (passInput) {
            passInput.addEventListener('blur', () => {
                const err = validatePassword(passInput.value);
                err ? setError(passInput, passErr, err) : clearError(passInput, passErr);
            });
            passInput.addEventListener('input', () => clearError(passInput, passErr));
        }

        if (passConfirm) {
            passConfirm.addEventListener('blur', () => {
                if (passInput && passConfirm.value !== passInput.value) {
                    setError(passConfirm, confirmErr, 'Passwords do not match.');
                } else {
                    clearError(passConfirm, confirmErr);
                }
            });
            passConfirm.addEventListener('input', () => clearError(passConfirm, confirmErr));
        }

        /* Full validation before submit */
        function validateAll() {
            let valid = true;

            const nErr = validateName(nameInput ? nameInput.value : '');
            if (nErr) { setError(nameInput, nameErr, nErr); valid = false; }
            else        clearError(nameInput, nameErr);

            const eErr = validateEmail(emailInput ? emailInput.value : '');
            if (eErr) { setError(emailInput, emailErr, eErr); valid = false; }
            else        clearError(emailInput, emailErr);

            const pErr = validatePassword(passInput ? passInput.value : '');
            if (pErr) { setError(passInput, passErr, pErr); valid = false; }
            else        clearError(passInput, passErr);

            if (passConfirm && passInput && passConfirm.value !== passInput.value) {
                setError(passConfirm, confirmErr, 'Passwords do not match.');
                valid = false;
            } else {
                clearError(passConfirm, confirmErr);
            }

            const selectedRole = document.querySelector('input[name="role"]:checked');
            if (!selectedRole) {
                showAlert(alertBox, 'Please select a role.', 'error');
                valid = false;
            }

            if (selectedRole && selectedRole.value === 'vendor') {
                const categorySelect = $('category');
                if (categorySelect && !categorySelect.value) {
                    showAlert(alertBox, 'Please select a category for the vendor.', 'error');
                    valid = false;
                }
            }

            return valid;
        }

        /* Submit */
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            hideAlert(alertBox);

            if (!validateAll()) return;

            setLoading(submitBtn, true);

            try {
                const hashed = await sha256(passInput.value);
                if (passHash) passHash.value = hashed;

                /* Clear plain-text passwords before submit */
                passInput.value = '';
                if (passConfirm) passConfirm.value = '';

                this.submit();
            } catch (err) {
                console.error('[auth.js] Signup hash error:', err);
                showAlert(alertBox, 'Something went wrong. Please try again.', 'error');
                setLoading(submitBtn, false);
            }
        });

        /* Server flash */
        const flashMsg  = form.dataset.flash;
        const flashType = form.dataset.flashType || 'error';
        if (flashMsg) showAlert(alertBox, flashMsg, flashType);
    }

    /* ── Init ─────────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', () => {
        initFlashDismiss();
        initLogin();
        initSignup();
    });

})();