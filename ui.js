/**
 * PrivVault – ui.js
 * PrivMITLab | UI Module
 *
 * Handles all DOM rendering, toast notifications,
 * entry list, modals, and UI state management
 */

'use strict';

const PrivUI = (() => {

  // ── Toast Notifications ───────────────────────────────────────
  const TOAST_ICONS = {
    success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toast-icon">
                <polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toast-icon">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toast-icon">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="toast-icon">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
  };

  /**
   * Show a toast notification
   * @param {string} message
   * @param {'success'|'error'|'warning'|'info'} type
   * @param {number} duration - ms to show
   */
  function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      ${TOAST_ICONS[type] || TOAST_ICONS.info}
      <span>${PrivUtils.sanitize(message)}</span>
    `;

    container.appendChild(toast);

    const removeToast = () => {
      toast.classList.add('removing');
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 200);
    };

    setTimeout(removeToast, duration);
    toast.addEventListener('click', removeToast);
  }

  // ── Screen Transitions ────────────────────────────────────────
  /**
   * Show the main app screen
   */
  function showApp() {
    document.getElementById('unlock-screen').classList.add('hidden');
    document.getElementById('app-screen').classList.remove('hidden');
    document.getElementById('app-screen').classList.add('active');
    focusSearch();
  }

  /**
   * Show the unlock screen
   */
  function showUnlock() {
    document.getElementById('app-screen').classList.add('hidden');
    document.getElementById('app-screen').classList.remove('active');
    document.getElementById('unlock-screen').classList.remove('hidden');

    // Clear sensitive fields
    const masterPw = document.getElementById('master-password');
    if (masterPw) {
      masterPw.value = '';
      masterPw.focus();
    }

    showLoginView();
  }

  /**
   * Switch to login view
   */
  function showLoginView() {
    document.getElementById('login-view').classList.remove('hidden');
    document.getElementById('create-view').classList.add('hidden');
  }

  /**
   * Switch to create vault view
   */
  function showCreateView() {
    document.getElementById('login-view').classList.add('hidden');
    document.getElementById('create-view').classList.remove('hidden');
    document.getElementById('new-master-pw').focus();
  }

  // ── Panel Views ───────────────────────────────────────────────
  /**
   * Show the welcome/empty panel
   */
  function showWelcomePanel() {
    document.getElementById('welcome-view').classList.remove('hidden');
    document.getElementById('welcome-view').classList.add('active');
    document.getElementById('entry-view').classList.add('hidden');
    document.getElementById('entry-view').classList.remove('active');
  }

  /**
   * Show the entry detail/edit panel
   */
  function showEntryPanel() {
    document.getElementById('welcome-view').classList.add('hidden');
    document.getElementById('welcome-view').classList.remove('active');
    document.getElementById('entry-view').classList.remove('hidden');
    document.getElementById('entry-view').classList.add('active');
  }

  // ── Entry List Rendering ──────────────────────────────────────
  /**
   * Render the sidebar entry list
   * @param {Array} entries - Filtered/sorted entries
   * @param {string} activeId - Currently selected entry ID
   */
  function renderEntryList(entries, activeId) {
    const list = document.getElementById('entry-list');
    if (!list) return;

    list.innerHTML = '';

    if (!entries || entries.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'no-results';
      empty.textContent = 'No entries found';
      list.appendChild(empty);
      return;
    }

    const fragment = document.createDocumentFragment();

    entries.forEach(entry => {
      const item = document.createElement('div');
      item.className = `entry-item ${entry.id === activeId ? 'active' : ''}`;
      item.dataset.id = entry.id;
      item.setAttribute('role', 'listitem');
      item.setAttribute('tabindex', '0');
      item.setAttribute('aria-label', entry.title);

      const icon = document.createElement('div');
      icon.className = `entry-item-icon type-${entry.type || 'password'}`;
      icon.textContent = entry.type === 'note' ? 'N' : getInitials(entry.title);

      const info = document.createElement('div');
      info.className = 'entry-item-info';

      const title = document.createElement('div');
      title.className = 'entry-item-title';
      title.textContent = PrivUtils.truncate(entry.title, 30);

      const sub = document.createElement('div');
      sub.className = 'entry-item-sub';
      sub.textContent = entry.type === 'note'
        ? 'Secure Note'
        : PrivUtils.truncate(entry.username || entry.url || 'No username', 30);

      info.appendChild(title);
      info.appendChild(sub);
      item.appendChild(icon);
      item.appendChild(info);
      fragment.appendChild(item);
    });

    list.appendChild(fragment);
  }

  /**
   * Get initials from a title
   * @param {string} title
   * @returns {string}
   */
  function getInitials(title) {
    if (!title) return '?';
    const words = title.trim().split(/\s+/);
    if (words.length >= 2) {
      return (words[0][0] + words[1][0]).toUpperCase();
    }
    return title.slice(0, 2).toUpperCase();
  }

  // ── Entry Form Rendering ──────────────────────────────────────
  /**
   * Render an entry in the main panel
   * @param {object} entry - Entry data
   * @param {boolean} isNew - Whether this is a new entry
   */
  function renderEntryForm(entry, isNew = false) {
    showEntryPanel();

    // Header
    const titleInput = document.getElementById('entry-title');
    const entryMeta = document.getElementById('entry-meta');
    const typeIcon = document.getElementById('entry-type-icon');
    const typeSelector = document.getElementById('entry-type-selector');

    if (titleInput) titleInput.value = PrivUtils.sanitize(entry.title || '');
    if (entryMeta) {
      entryMeta.textContent = isNew
        ? 'New entry'
        : `Modified ${PrivUtils.formatDate(entry.updated_at || entry.created_at)}`;
    }

    // Type icon
    if (typeIcon) {
      typeIcon.className = `entry-type-icon type-${entry.type || 'password'}`;
      typeIcon.innerHTML = entry.type === 'note'
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" 
               class="icon-sm">
             <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
             <polyline points="14 2 14 8 20 8"/>
           </svg>`
        : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" 
               class="icon-sm">
             <rect x="2" y="7" width="20" height="14" rx="2"/>
             <path d="M8 7V5a4 4 0 0 1 8 0v2"/>
           </svg>`;
    }

    // Show type selector for new entries
    if (typeSelector) {
      typeSelector.className = isNew ? '' : 'hidden';
    }

    // Toggle field sections
    const passwordFields = document.getElementById('password-fields');
    const noteFields = document.getElementById('note-fields');

    if (entry.type === 'note') {
      if (passwordFields) passwordFields.classList.add('hidden');
      if (noteFields) noteFields.classList.remove('hidden');

      const noteContent = document.getElementById('note-content');
      if (noteContent) noteContent.value = entry.content || '';

      renderTags(entry.tags || [], 'note-tags-display', 'note-tag-input');
    } else {
      if (passwordFields) passwordFields.classList.remove('hidden');
      if (noteFields) noteFields.classList.add('hidden');

      // Fill password fields
      const fieldUsername = document.getElementById('field-username');
      const fieldPassword = document.getElementById('field-password');
      const fieldUrl = document.getElementById('field-url');
      const fieldNotes = document.getElementById('field-notes');

      if (fieldUsername) fieldUsername.value = entry.username || '';
      if (fieldPassword) {
        fieldPassword.value = entry.password || '';
        updateFieldStrength(entry.password || '');
      }
      if (fieldUrl) fieldUrl.value = entry.url || '';
      if (fieldNotes) fieldNotes.value = entry.notes || '';

      renderTags(entry.tags || [], 'tags-display', 'tag-input');
    }

    // Focus title input for new entries
    if (isNew && titleInput) {
      setTimeout(() => titleInput.focus(), 50);
    }
  }

  /**
   * Render tags in the tags input area
   * @param {string[]} tags
   * @param {string} displayId
   * @param {string} inputId
   */
  function renderTags(tags, displayId, inputId) {
    const display = document.getElementById(displayId);
    if (!display) return;

    display.innerHTML = '';
    (tags || []).forEach(tag => {
      const chip = document.createElement('span');
      chip.className = 'entry-tag';
      chip.textContent = PrivUtils.sanitize(tag);

      const removeBtn = document.createElement('button');
      removeBtn.className = 'entry-tag-remove';
      removeBtn.textContent = '×';
      removeBtn.setAttribute('aria-label', `Remove tag ${tag}`);
      removeBtn.dataset.tag = tag;
      removeBtn.dataset.displayId = displayId;
      removeBtn.dataset.inputId = inputId;

      chip.appendChild(removeBtn);
      display.appendChild(chip);
    });
  }

  /**
   * Update the password strength bar in the entry form
   * @param {string} password
   */
  function updateFieldStrength(password) {
    const bar = document.getElementById('field-strength-bar');
    const label = document.getElementById('field-strength-label');
    if (!bar || !label) return;

    const { percent, label: lbl, color } = PrivCrypto.calculateStrength(password);
    bar.style.width = percent + '%';
    bar.style.backgroundColor = color;
    label.textContent = lbl;
    label.style.color = color;
  }

  // ── Tag Filter Bar ────────────────────────────────────────────
  /**
   * Render tag filter chips in sidebar
   * @param {string[]} allTags
   * @param {string} activeTag
   */
  function renderTagFilter(allTags, activeTag) {
    const chips = document.getElementById('tag-chips');
    if (!chips) return;

    chips.innerHTML = '';

    if (allTags.length === 0) return;

    allTags.forEach(tag => {
      const chip = document.createElement('button');
      chip.className = `tag-chip ${tag === activeTag ? 'active' : ''}`;
      chip.textContent = tag;
      chip.dataset.tag = tag;
      chips.appendChild(chip);
    });
  }

  // ── Vault Stats ───────────────────────────────────────────────
  /**
   * Update vault statistics display
   * @param {object} stats
   * @param {number} stats.total
   * @param {number} stats.passwords
   * @param {number} stats.notes
   */
  function updateVaultStats(stats) {
    const el = document.getElementById('vault-stats');
    if (!el) return;
    el.textContent = `${stats.total} entries · ${stats.passwords} passwords · ${stats.notes} notes`;
  }

  // ── Auto-Lock Countdown ───────────────────────────────────────
  /**
   * Update the auto-lock countdown display
   * @param {number} secondsLeft
   */
  function updateLockCountdown(secondsLeft) {
    const el = document.getElementById('lock-countdown');
    if (!el) return;

    if (secondsLeft <= 0) {
      el.textContent = '';
      return;
    }

    const mins = Math.floor(secondsLeft / 60);
    const secs = secondsLeft % 60;
    el.textContent = mins > 0
      ? `${mins}m ${secs}s`
      : `${secs}s`;
  }

  // ── Generator UI ─────────────────────────────────────────────
  /**
   * Update password generator strength display
   * @param {string} password
   */
  function updateGeneratorStrength(password) {
    const bar = document.getElementById('gen-strength-bar');
    const label = document.getElementById('gen-strength-label');
    if (!bar || !label) return;

    const { percent, label: lbl, color } = PrivCrypto.calculateStrength(password);
    bar.style.width = percent + '%';
    bar.style.backgroundColor = color;
    label.textContent = lbl;
    label.style.color = color;
  }

  // ── Unlock UI Helpers ─────────────────────────────────────────
  /**
   * Update master password strength on create view
   * @param {string} password
   */
  function updateCreateStrength(password) {
    const bar = document.getElementById('strength-bar');
    const label = document.getElementById('strength-label');
    if (!bar || !label) return;

    const { percent, label: lbl, color } = PrivCrypto.calculateStrength(password);
    bar.style.width = percent + '%';
    bar.style.backgroundColor = color;
    label.textContent = lbl;
    label.style.color = color;
  }

  /**
   * Update change password strength
   * @param {string} password
   */
  function updateChangeStrength(password) {
    const bar = document.getElementById('change-strength-bar');
    const label = document.getElementById('change-strength-label');
    if (!bar || !label) return;

    const { percent, label: lbl, color } = PrivCrypto.calculateStrength(password);
    bar.style.width = percent + '%';
    bar.style.backgroundColor = color;
    label.textContent = lbl;
    label.style.color = color;
  }

  // ── Error Display Helpers ─────────────────────────────────────
  function showError(elementId, message) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = PrivUtils.sanitize(message);
    el.classList.remove('hidden');
  }

  function hideError(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.classList.add('hidden');
  }

  // ── Modal Control ─────────────────────────────────────────────
  function showModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('hidden');
  }

  function hideModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  }

  // ── Password Eye Toggle ───────────────────────────────────────
  /**
   * Toggle password field visibility
   * @param {HTMLInputElement} input
   * @param {HTMLButtonElement} btn
   */
  function togglePasswordVisibility(input, btn) {
    if (!input) return;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';

    if (btn) {
      btn.innerHTML = isHidden
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" 
               stroke-width="2" class="icon-sm">
             <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
             <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
             <line x1="1" y1="1" x2="23" y2="23"/>
           </svg>`
        : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" 
               stroke-width="2" class="icon-sm">
             <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
             <circle cx="12" cy="12" r="3"/>
           </svg>`;
    }
  }

  /**
   * Focus the search input
   */
  function focusSearch() {
    const search = document.getElementById('search-input');
    if (search) search.focus();
  }

  return Object.freeze({
    showToast,
    showApp,
    showUnlock,
    showLoginView,
    showCreateView,
    showWelcomePanel,
    showEntryPanel,
    renderEntryList,
    renderEntryForm,
    renderTags,
    renderTagFilter,
    updateVaultStats,
    updateLockCountdown,
    updateFieldStrength,
    updateGeneratorStrength,
    updateCreateStrength,
    updateChangeStrength,
    showError,
    hideError,
    showModal,
    hideModal,
    togglePasswordVisibility,
    focusSearch
  });

})();