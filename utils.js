/**
 * PrivVault – utils.js
 * PrivMITLab | General Utilities
 *
 * Provides: sanitization, date formatting,
 * clipboard management, debounce, and other helpers
 */

'use strict';

const PrivUtils = (() => {

  // ── XSS Sanitization ─────────────────────────────────────────
  /**
   * Sanitize user input to prevent XSS
   * Uses DOM text node approach (no innerHTML)
   * @param {string} input
   * @returns {string}
   */
  function sanitize(input) {
    if (typeof input !== 'string') return '';
    // Limit length
    const limited = input.slice(0, 100000);
    // Use DOM-based escaping
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(limited));
    return div.innerHTML;
  }

  /**
   * Sanitize and truncate display strings
   * @param {string} str
   * @param {number} maxLen
   * @returns {string}
   */
  function truncate(str, maxLen = 40) {
    if (!str) return '';
    const s = String(str);
    return s.length > maxLen ? s.slice(0, maxLen) + '…' : s;
  }

  /**
   * Validate URL (must start with http/https or be empty)
   * @param {string} url
   * @returns {boolean}
   */
  function isValidURL(url) {
    if (!url || url.trim() === '') return true;
    try {
      const u = new URL(url.trim());
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  }

  // ── Clipboard Management ─────────────────────────────────────
  let clipboardTimer = null;
  let clipboardCountdownEl = null;
  let clipboardTimerEl = null;
  let clipboardClearDelaySeconds = 15;

  /**
   * Set clipboard clear delay
   * @param {number} seconds
   */
  function setClipboardDelay(seconds) {
    clipboardClearDelaySeconds = seconds;
  }

  /**
   * Copy text to clipboard with auto-clear
   * @param {string} text - Text to copy
   * @param {string} label - What was copied (for notifications)
   * @returns {Promise<boolean>}
   */
  async function copyToClipboard(text, label = 'Text') {
    if (!text) return false;

    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for older browsers
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      } catch {
        PrivUI.showToast(`Failed to copy ${label}`, 'error');
        return false;
      }
    }

    // Start auto-clear countdown
    startClipboardCountdown(clipboardClearDelaySeconds);

    return true;
  }

  /**
   * Start clipboard auto-clear countdown
   * @param {number} seconds
   */
  function startClipboardCountdown(seconds) {
    // Clear any existing timer
    stopClipboardCountdown();

    clipboardCountdownEl = document.getElementById('clipboard-countdown');
    clipboardTimerEl = document.getElementById('clipboard-timer');

    if (!clipboardCountdownEl || !clipboardTimerEl) return;

    let remaining = seconds;
    clipboardTimerEl.textContent = remaining;
    clipboardCountdownEl.classList.remove('hidden');

    clipboardTimer = setInterval(() => {
      remaining--;
      if (clipboardTimerEl) {
        clipboardTimerEl.textContent = remaining;
      }

      if (remaining <= 0) {
        stopClipboardCountdown();
        clearClipboard();
      }
    }, 1000);
  }

  /**
   * Stop clipboard countdown
   */
  function stopClipboardCountdown() {
    if (clipboardTimer) {
      clearInterval(clipboardTimer);
      clipboardTimer = null;
    }
    if (clipboardCountdownEl) {
      clipboardCountdownEl.classList.add('hidden');
    }
  }

  /**
   * Clear clipboard contents
   */
  async function clearClipboard() {
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // May fail if page loses focus; acceptable
    }
    stopClipboardCountdown();
  }

  // ── UUID Generator ────────────────────────────────────────────
  /**
   * Generate a UUID v4 using crypto.getRandomValues
   * @returns {string}
   */
  function generateUUID() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = Array.from(bytes).map(b =>
      b.toString(16).padStart(2, '0')
    );

    return [
      hex.slice(0, 4).join(''),
      hex.slice(4, 6).join(''),
      hex.slice(6, 8).join(''),
      hex.slice(8, 10).join(''),
      hex.slice(10, 16).join('')
    ].join('-');
  }

  // ── Date Formatting ──────────────────────────────────────────
  /**
   * Format a timestamp for display
   * @param {string|number} timestamp - ISO string or epoch
   * @returns {string}
   */
  function formatDate(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp);
    if (isNaN(d.getTime())) return '';

    const now = new Date();
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;

    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  }

  /**
   * Full formatted date string
   * @param {string|number} timestamp
   * @returns {string}
   */
  function formatDateFull(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  // ── Debounce ──────────────────────────────────────────────────
  /**
   * Debounce a function
   * @param {Function} fn
   * @param {number} delay
   * @returns {Function}
   */
  function debounce(fn, delay = 300) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  // ── Retry Rate Limiting ───────────────────────────────────────
  const retryState = {
    attempts: 0,
    lastAttempt: 0,
    locked: false,
    lockUntil: 0
  };

  const MAX_ATTEMPTS   = 5;
  const LOCKOUT_TIME   = 30000; // 30 seconds
  const ATTEMPT_DELAY  = [0, 0, 1000, 2000, 5000]; // ms delays

  /**
   * Check if login attempt is allowed
   * @returns {{ allowed: boolean, wait: number, attemptsLeft: number }}
   */
  function checkRetryAllowed() {
    const now = Date.now();

    // Check if locked out
    if (retryState.locked && now < retryState.lockUntil) {
      const remaining = Math.ceil((retryState.lockUntil - now) / 1000);
      return { allowed: false, wait: remaining, attemptsLeft: 0 };
    }

    if (retryState.locked && now >= retryState.lockUntil) {
      retryState.locked = false;
      retryState.attempts = 0;
    }

    return {
      allowed: true,
      wait: 0,
      attemptsLeft: MAX_ATTEMPTS - retryState.attempts
    };
  }

  /**
   * Record a failed login attempt
   * @returns {{ delay: number, locked: boolean, lockDuration: number }}
   */
  function recordFailedAttempt() {
    retryState.attempts++;
    retryState.lastAttempt = Date.now();

    if (retryState.attempts >= MAX_ATTEMPTS) {
      retryState.locked = true;
      retryState.lockUntil = Date.now() + LOCKOUT_TIME;
      return { delay: 0, locked: true, lockDuration: LOCKOUT_TIME / 1000 };
    }

    const delay = ATTEMPT_DELAY[Math.min(
      retryState.attempts - 1,
      ATTEMPT_DELAY.length - 1
    )];

    return { delay, locked: false, lockDuration: 0 };
  }

  /**
   * Reset retry counter on success
   */
  function resetRetryState() {
    retryState.attempts = 0;
    retryState.locked = false;
    retryState.lockUntil = 0;
    retryState.lastAttempt = 0;
  }

  // ── Delay Helper ─────────────────────────────────────────────
  /**
   * Artificial delay (for rate limiting UI)
   * @param {number} ms
   * @returns {Promise<void>}
   */
  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ── Data Validation ──────────────────────────────────────────
  /**
   * Validate entry data
   * @param {object} entry
   * @returns {{ valid: boolean, error: string }}
   */
  function validateEntry(entry) {
    if (!entry.title || entry.title.trim().length === 0) {
      return { valid: false, error: 'Title is required' };
    }
    if (entry.title.length > 200) {
      return { valid: false, error: 'Title too long (max 200 chars)' };
    }
    if (entry.url && !isValidURL(entry.url)) {
      return { valid: false, error: 'Invalid URL format' };
    }
    return { valid: true, error: '' };
  }

  /**
   * Validate master password
   * @param {string} password
   * @returns {{ valid: boolean, error: string }}
   */
  function validateMasterPassword(password) {
    if (!password || password.length === 0) {
      return { valid: false, error: 'Password is required' };
    }
    if (password.length < 8) {
      return { valid: false, error: 'Password must be at least 8 characters' };
    }
    return { valid: true, error: '' };
  }

  return Object.freeze({
    sanitize,
    truncate,
    isValidURL,
    copyToClipboard,
    clearClipboard,
    setClipboardDelay,
    stopClipboardCountdown,
    generateUUID,
    formatDate,
    formatDateFull,
    debounce,
    checkRetryAllowed,
    recordFailedAttempt,
    resetRetryState,
    delay,
    validateEntry,
    validateMasterPassword
  });

})();