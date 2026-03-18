/**
 * PrivVault – app.js
 * PrivMITLab | Main Application Controller
 *
 * Orchestrates all modules:
 * - PrivCrypto  (crypto.js)
 * - PrivStorage (storage.js)
 * - PrivUtils   (utils.js)
 * - PrivUI      (ui.js)
 *
 * SECURITY NOTICE:
 * - masterKey is kept only in memory (never persisted)
 * - Vault is re-encrypted on every save
 * - All inputs are sanitized before processing
 */

'use strict';

// ── Application State ──────────────────────────────────────────
const AppState = {
  // Vault data (decrypted, in-memory only)
  vault: {
    entries: [],
    settings: {
      autolockMinutes: 5,
      clipboardDelaySecs: 15,
      backupReminder: true,
      backupReminderCount: 0
    },
    created_at: null,
    modified_at: null
  },

  // Crypto state (never persisted)
  masterKey: null,          // CryptoKey object
  salt: null,               // Uint8Array

  // Raw encrypted vault blob (for re-saves)
  rawVaultBlob: null,

  // UI state
  currentEntryId: null,
  currentFilter: 'all',     // 'all' | 'password' | 'note'
  activeTag: null,
  searchQuery: '',
  isLocked: true,

  // Entry being edited (copy – not reference)
  editingEntry: null,
  isNewEntry: false,
  editingTags: [],

  // Auto-lock
  lockTimer: null,
  lockCountdownTimer: null,
  lockSecondsLeft: 0,

  // Password generator
  lastGeneratedPassword: null,
  generatorCalledFrom: null  // 'field' | 'topbar'
};

// ── DOM Ready ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

// ── App Initialization ────────────────────────────────────────
async function initApp() {
  // Register service worker
  registerServiceWorker();

  // Bind all events
  bindUnlockEvents();
  bindAppEvents();
  bindKeyboardShortcuts();

  // Check for stored vault
  await checkStoredVault();

  // Prevent body selection
  document.body.style.userSelect = 'none';
}

// ── Service Worker ────────────────────────────────────────────
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js')
      .then(() => console.info('[PrivVault] Service worker registered'))
      .catch(err => console.warn('[PrivVault] SW registration failed:', err));
  }
}

// ── Stored Vault Check ────────────────────────────────────────
async function checkStoredVault() {
  const hasVault = await PrivStorage.hasStoredVault();
  if (hasVault) {
    AppState.rawVaultBlob = await PrivStorage.loadFromIndexedDB();
  }
}

// ── Unlock & Auth Events ──────────────────────────────────────
function bindUnlockEvents() {
  // Toggle password visibility
  bindTogglePw('toggle-unlock-pw', 'master-password');
  bindTogglePw('toggle-new-pw', 'new-master-pw');

  // Switch views
  getElementById('create-vault-btn')?.addEventListener('click', () => {
    PrivUI.showCreateView();
  });

  getElementById('back-to-login-btn')?.addEventListener('click', () => {
    PrivUI.showLoginView();
    clearCreateForm();
  });

  // Master password strength meter
  getElementById('new-master-pw')?.addEventListener('input', (e) => {
    PrivUI.updateCreateStrength(e.target.value);
  });

  // Change password strength meter
  getElementById('new-master-pw-change')?.addEventListener('input', (e) => {
    PrivUI.updateChangeStrength(e.target.value);
  });

  // Unlock existing vault
  getElementById('unlock-btn')?.addEventListener('click', handleUnlock);
  getElementById('master-password')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });

  // Load vault file
  getElementById('load-vault-btn')?.addEventListener('click', () => {
    getElementById('vault-file-input')?.click();
  });

  getElementById('vault-file-input')?.addEventListener('change', handleVaultFileLoad);

  // Create new vault
  getElementById('create-confirm-btn')?.addEventListener('click', handleCreateVault);
  getElementById('confirm-master-pw')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleCreateVault();
  });
}

// ── Unlock Handler ────────────────────────────────────────────
async function handleUnlock() {
  const btn = getElementById('unlock-btn');
  const password = getElementById('master-password')?.value;
  const errorEl = getElementById('unlock-error');
  const retryEl = getElementById('retry-warning');

  PrivUI.hideError('unlock-error');
  if (retryEl) retryEl.classList.add('hidden');

  if (!password) {
    PrivUI.showError('unlock-error', 'Please enter your master password');
    return;
  }

  // Check rate limit
  const retryCheck = PrivUtils.checkRetryAllowed();
  if (!retryCheck.allowed) {
    PrivUI.showError('unlock-error',
      `Too many failed attempts. Please wait ${retryCheck.wait} seconds.`);
    return;
  }

  // Determine vault source
  let vaultBlob = AppState.rawVaultBlob;
  if (!vaultBlob) {
    PrivUI.showError('unlock-error', 'No vault found. Please load a vault file or create a new vault.');
    return;
  }

  setButtonLoading(btn, true, 'Unlocking...');

  try {
    // Parse vault file to get salt
    let parsed;
    try {
      parsed = JSON.parse(vaultBlob);
    } catch {
      throw new Error('Invalid vault file format');
    }

    const salt = PrivCrypto.fromBase64(parsed.salt);

    // Apply delay based on retry count
    const { delay: retryDelay } = PrivUtils.recordFailedAttempt();
    // Pre-record; reset on success
    if (retryDelay > 0) await PrivUtils.delay(retryDelay);

    // Derive key
    const key = await PrivCrypto.deriveKey(password, salt);

    // Decrypt vault
    const vaultData = await PrivCrypto.parseVaultFile(vaultBlob, key);

    // Success
    PrivUtils.resetRetryState();
    AppState.masterKey = key;
    AppState.salt = salt;
    AppState.vault = mergeVaultDefaults(vaultData);
    AppState.isLocked = false;

    // Apply settings
    applySettings(AppState.vault.settings);

    // Launch app
    launchApp();

  } catch (err) {
    const check = PrivUtils.checkRetryAllowed();
    if (!check.allowed) {
      PrivUI.showError('unlock-error',
        `Too many failed attempts. Please wait ${check.wait} seconds.`);
    } else {
      PrivUI.showError('unlock-error', 'Wrong password or corrupted vault file.');
      if (check.attemptsLeft <= 2) {
        if (retryEl) {
          retryEl.textContent =
            `${check.attemptsLeft} attempt(s) remaining before temporary lockout.`;
          retryEl.classList.remove('hidden');
        }
      }
    }
  } finally {
    setButtonLoading(btn, false, 'Unlock Vault');
    const masterPwEl = getElementById('master-password');
    if (masterPwEl) masterPwEl.value = '';
  }
}

// ── Create Vault Handler ──────────────────────────────────────
async function handleCreateVault() {
  const btn = getElementById('create-confirm-btn');
  const newPw = getElementById('new-master-pw')?.value;
  const confirmPw = getElementById('confirm-master-pw')?.value;

  PrivUI.hideError('create-error');

  const validation = PrivUtils.validateMasterPassword(newPw);
  if (!validation.valid) {
    PrivUI.showError('create-error', validation.error);
    return;
  }

  if (newPw !== confirmPw) {
    PrivUI.showError('create-error', 'Passwords do not match');
    return;
  }

  setButtonLoading(btn, true, 'Creating Vault...');

  try {
    const salt = PrivCrypto.generateSalt();
    const key = await PrivCrypto.deriveKey(newPw, salt);

    const newVault = createEmptyVault();
    const vaultBlob = await PrivCrypto.createVaultFile(newVault, key, salt);

    AppState.masterKey = key;
    AppState.salt = salt;
    AppState.vault = newVault;
    AppState.rawVaultBlob = vaultBlob;
    AppState.isLocked = false;

    // Auto-save to IndexedDB
    await PrivStorage.saveToIndexedDB(vaultBlob);

    applySettings(newVault.settings);
    launchApp();

    PrivUI.showToast('Vault created successfully!', 'success');

    // Clear form
    clearCreateForm();

  } catch (err) {
    PrivUI.showError('create-error', 'Failed to create vault: ' + err.message);
  } finally {
    setButtonLoading(btn, false, 'Create Vault');
  }
}

// ── Vault File Load Handler ───────────────────────────────────
async function handleVaultFileLoad(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  try {
    const contents = await PrivStorage.readVaultFile(file);

    // Basic validation
    JSON.parse(contents); // Will throw if invalid JSON

    AppState.rawVaultBlob = contents;
    await PrivStorage.saveToIndexedDB(contents);

    PrivUI.showToast('Vault file loaded. Enter your master password.', 'info');
    getElementById('master-password')?.focus();

  } catch (err) {
    PrivUI.showError('unlock-error', `Failed to load vault: ${err.message}`);
  }

  // Reset file input
  event.target.value = '';
}

// ── App Launch ────────────────────────────────────────────────
function launchApp() {
  PrivUI.showApp();
  renderSidebar();
  PrivUI.showWelcomePanel();
  startAutoLock();
  setupActivityTracking();

  // Backup reminder
  checkBackupReminder();
}

// ── App Events ────────────────────────────────────────────────
function bindAppEvents() {
  // Lock button
  getElementById('lock-btn')?.addEventListener('click', lockVault);

  // Sidebar toggle
  getElementById('sidebar-toggle')?.addEventListener('click', () => {
    const sidebar = getElementById('sidebar');
    sidebar?.classList.toggle('collapsed');
  });

  // Search
  const searchInput = getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', PrivUtils.debounce((e) => {
      AppState.searchQuery = e.target.value;
      const clearBtn = getElementById('search-clear');
      if (clearBtn) {
        clearBtn.classList.toggle('hidden', !e.target.value);
      }
      renderSidebar();
    }, 200));
  }

  getElementById('search-clear')?.addEventListener('click', () => {
    const si = getElementById('search-input');
    if (si) si.value = '';
    AppState.searchQuery = '';
    getElementById('search-clear')?.classList.add('hidden');
    renderSidebar();
  });

  // Filter tabs
  document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab').forEach(t =>
        t.classList.remove('active')
      );
      tab.classList.add('active');
      AppState.currentFilter = tab.dataset.filter;
      AppState.activeTag = null;
      renderSidebar();
    });
  });

  // Tag filter chips (delegated)
  getElementById('tag-chips')?.addEventListener('click', (e) => {
    const chip = e.target.closest('.tag-chip');
    if (!chip) return;
    const tag = chip.dataset.tag;
    AppState.activeTag = AppState.activeTag === tag ? null : tag;
    renderSidebar();
  });

  // Entry list click (delegated)
  getElementById('entry-list')?.addEventListener('click', (e) => {
    const item = e.target.closest('.entry-item');
    if (!item) return;
    selectEntry(item.dataset.id);
  });

  // Entry list keyboard
  getElementById('entry-list')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const item = e.target.closest('.entry-item');
      if (item) selectEntry(item.dataset.id);
    }
  });

  // Add new entry
  getElementById('add-entry-btn')?.addEventListener('click', () => newEntry());

  // Save entry
  getElementById('save-entry-btn')?.addEventListener('click', saveCurrentEntry);

  // Delete entry
  getElementById('delete-entry-btn')?.addEventListener('click', () => {
    if (!AppState.currentEntryId && !AppState.isNewEntry) return;
    showConfirmDialog(
      'Delete this entry? This cannot be undone.',
      deleteCurrentEntry
    );
  });

  // Entry title changes
  getElementById('entry-title')?.addEventListener('input', (e) => {
    if (AppState.editingEntry) {
      AppState.editingEntry.title = e.target.value;
    }
  });

  // Password field changes
  getElementById('field-password')?.addEventListener('input', (e) => {
    PrivUI.updateFieldStrength(e.target.value);
  });

  // Toggle password visibility in entry
  bindTogglePw('toggle-field-pw', 'field-password');

  // Copy buttons (delegated)
  document.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('.btn-icon-copy');
    if (copyBtn) handleCopyButton(copyBtn.dataset.copy);

    // Tag remove button
    const removeBtn = e.target.closest('.entry-tag-remove');
    if (removeBtn) handleTagRemove(removeBtn);
  });

  // Open URL button
  getElementById('open-url-btn')?.addEventListener('click', () => {
    const url = getElementById('field-url')?.value?.trim();
    if (!url) return;
    if (PrivUtils.isValidURL(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      PrivUI.showToast('Invalid URL', 'error');
    }
  });

  // Generate password in field
  getElementById('gen-field-pw')?.addEventListener('click', () => {
    AppState.generatorCalledFrom = 'field';
    openGenerator();
  });

  // Generator - top bar
  getElementById('gen-pw-topbar')?.addEventListener('click', () => {
    AppState.generatorCalledFrom = 'topbar';
    openGenerator();
  });

  // Generator controls
  bindGeneratorEvents();

  // Type selector buttons
  document.querySelectorAll('.type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.type-btn').forEach(b =>
        b.classList.remove('active')
      );
      btn.classList.add('active');

      if (AppState.editingEntry) {
        AppState.editingEntry.type = btn.dataset.type;
        AppState.editingTags = [];
        PrivUI.renderEntryForm(AppState.editingEntry, AppState.isNewEntry);
      }
    });
  });

  // Tag input
  bindTagInputEvents('tag-input', 'tags-display');
  bindTagInputEvents('note-tag-input', 'note-tags-display');

  // Export vault
  getElementById('export-vault-btn')?.addEventListener('click', handleExportVault);

  // Import vault
  getElementById('import-vault-btn')?.addEventListener('click', () => {
    getElementById('import-file-input')?.click();
  });

  getElementById('import-file-input')?.addEventListener('change',
    handleImportVault);

  // Settings
  getElementById('settings-btn')?.addEventListener('click', () => {
    loadSettingsToUI();
    PrivUI.showModal('settings-modal');
  });

  getElementById('close-settings')?.addEventListener('click', () => {
    saveSettingsFromUI();
    PrivUI.hideModal('settings-modal');
  });

  getElementById('autolock-select')?.addEventListener('change', saveSettingsFromUI);
  getElementById('clipboard-delay-select')?.addEventListener('change',
    saveSettingsFromUI);
  getElementById('backup-reminder')?.addEventListener('change', saveSettingsFromUI);

  // Change master password
  getElementById('change-master-pw-btn')?.addEventListener('click', () => {
    PrivUI.showModal('change-pw-modal');
  });

  getElementById('close-change-pw')?.addEventListener('click', () => {
    PrivUI.hideModal('change-pw-modal');
    clearChangePwForm();
  });

  getElementById('confirm-change-pw-btn')?.addEventListener('click',
    handleChangeMasterPassword);

  // Confirm modal
  getElementById('confirm-cancel')?.addEventListener('click', () => {
    PrivUI.hideModal('confirm-modal');
    AppState._confirmCallback = null;
  });

  getElementById('confirm-ok')?.addEventListener('click', () => {
    PrivUI.hideModal('confirm-modal');
    if (typeof AppState._confirmCallback === 'function') {
      AppState._confirmCallback();
      AppState._confirmCallback = null;
    }
  });

  // Modal overlay click to close
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.add('hidden');
      }
    });
  });

  // Close generator
  getElementById('close-generator')?.addEventListener('click', () => {
    PrivUI.hideModal('generator-modal');
  });
}

// ── Keyboard Shortcuts ────────────────────────────────────────
function bindKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (AppState.isLocked) return;

    const ctrl = e.ctrlKey || e.metaKey;

    if (ctrl && e.key === 'l') { e.preventDefault(); lockVault(); }
    if (ctrl && e.key === 'n') { e.preventDefault(); newEntry(); }
    if (ctrl && e.key === 'g') { e.preventDefault(); openGenerator(); }
    if (ctrl && e.key === 's') {
      e.preventDefault();
      if (AppState.editingEntry) saveCurrentEntry();
    }
    if (ctrl && e.key === 'f') {
      e.preventDefault();
      getElementById('search-input')?.focus();
    }

    // Escape closes modals / deselects
    if (e.key === 'Escape') {
      const modals = document.querySelectorAll('.modal-overlay:not(.hidden)');
      if (modals.length > 0) {
        modals[modals.length - 1].classList.add('hidden');
      }
    }
  });
}

// ── Entry Operations ──────────────────────────────────────────
/**
 * Select and display an entry
 * @param {string} entryId
 */
function selectEntry(entryId) {
  const entry = AppState.vault.entries.find(e => e.id === entryId);
  if (!entry) return;

  AppState.currentEntryId = entryId;
  AppState.isNewEntry = false;
  AppState.editingEntry = deepCopy(entry);
  AppState.editingTags = [...(entry.tags || [])];

  PrivUI.renderEntryForm(AppState.editingEntry, false);
  renderSidebar(); // Update active state
}

/**
 * Create a new entry
 */
function newEntry() {
  const newEnt = {
    id: PrivUtils.generateUUID(),
    type: 'password',
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    content: '',
    tags: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  AppState.currentEntryId = newEnt.id;
  AppState.isNewEntry = true;
  AppState.editingEntry = newEnt;
  AppState.editingTags = [];

  PrivUI.renderEntryForm(newEnt, true);
}

/**
 * Save the currently editing entry
 */
async function saveCurrentEntry() {
  if (!AppState.editingEntry) return;

  // Collect form data
  const entry = collectFormData();
  if (!entry) return;

  // Validate
  const validation = PrivUtils.validateEntry(entry);
  if (!validation.valid) {
    PrivUI.showToast(validation.error, 'error');
    return;
  }

  entry.updated_at = new Date().toISOString();

  if (AppState.isNewEntry) {
    // Add to vault
    AppState.vault.entries.push(entry);
    AppState.isNewEntry = false;
  } else {
    // Update existing
    const idx = AppState.vault.entries.findIndex(e => e.id === entry.id);
    if (idx !== -1) {
      AppState.vault.entries[idx] = entry;
    }
  }

  AppState.editingEntry = entry;
  AppState.vault.modified_at = new Date().toISOString();

  // Re-encrypt and save
  await persistVault();

  renderSidebar();
  PrivUI.showToast('Entry saved', 'success');
}

/**
 * Delete the currently selected entry
 */
async function deleteCurrentEntry() {
  if (!AppState.currentEntryId) return;

  AppState.vault.entries = AppState.vault.entries.filter(
    e => e.id !== AppState.currentEntryId
  );

  AppState.currentEntryId = null;
  AppState.editingEntry = null;
  AppState.isNewEntry = false;

  AppState.vault.modified_at = new Date().toISOString();
  await persistVault();

  renderSidebar();
  PrivUI.showWelcomePanel();
  PrivUI.showToast('Entry deleted', 'success');
}

/**
 * Collect form data from the entry panel
 * @returns {object|null}
 */
function collectFormData() {
  if (!AppState.editingEntry) return null;

  const entry = deepCopy(AppState.editingEntry);

  entry.title = sanitizeField('entry-title') || '';

  if (entry.type === 'note') {
    entry.content = getElementById('note-content')?.value || '';
    entry.tags = [...AppState.editingTags];
  } else {
    entry.username = sanitizeField('field-username') || '';
    entry.password = getElementById('field-password')?.value || '';
    entry.url = sanitizeField('field-url') || '';
    entry.notes = getElementById('field-notes')?.value || '';
    entry.tags = [...AppState.editingTags];
  }

  return entry;
}

/**
 * Sanitize a form field value
 * @param {string} id
 * @returns {string}
 */
function sanitizeField(id) {
  const el = getElementById(id);
  if (!el) return '';
  return PrivUtils.sanitize(el.value.trim());
}

// ── Tag Management ────────────────────────────────────────────
/**
 * Bind tag input events for a specific tag area
 * @param {string} inputId
 * @param {string} displayId
 */
function bindTagInputEvents(inputId, displayId) {
  const input = getElementById(inputId);
  if (!input) return;

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const tag = input.value.trim().replace(/,/g, '').slice(0, 30);
      if (tag && !AppState.editingTags.includes(tag)) {
        AppState.editingTags.push(tag);
        PrivUI.renderTags(AppState.editingTags, displayId, inputId);
      }
      input.value = '';
    }

    if (e.key === 'Backspace' && !input.value && AppState.editingTags.length > 0) {
      AppState.editingTags.pop();
      PrivUI.renderTags(AppState.editingTags, displayId, inputId);
    }
  });
}

/**
 * Handle tag removal
 * @param {HTMLElement} btn
 */
function handleTagRemove(btn) {
  const tag = btn.dataset.tag;
  const displayId = btn.dataset.displayId;
  const inputId = btn.dataset.inputId;

  AppState.editingTags = AppState.editingTags.filter(t => t !== tag);
  PrivUI.renderTags(AppState.editingTags, displayId, inputId);
}

// ── Copy Functionality ────────────────────────────────────────
/**
 * Handle copy button clicks
 * @param {string} field - 'username' | 'password'
 */
async function handleCopyButton(field) {
  if (!AppState.editingEntry) return;

  let value = '';
  let label = '';

  if (field === 'username') {
    value = getElementById('field-username')?.value || '';
    label = 'Username';
  } else if (field === 'password') {
    value = getElementById('field-password')?.value || '';
    label = 'Password';
  }

  if (!value) {
    PrivUI.showToast(`No ${label.toLowerCase()} to copy`, 'warning');
    return;
  }

  const success = await PrivUtils.copyToClipboard(value, label);
  if (success) {
    PrivUI.showToast(`${label} copied – auto-clears in ${AppState.vault.settings.clipboardDelaySecs}s`, 'success');
  }
}

// ── Password Generator ────────────────────────────────────────
function bindGeneratorEvents() {
  const lengthSlider = getElementById('pw-length');
  const lengthValue = getElementById('length-value');

  lengthSlider?.addEventListener('input', () => {
    if (lengthValue) lengthValue.textContent = lengthSlider.value;
    generateAndDisplay();
  });

  ['include-uppercase', 'include-lowercase', 'include-numbers',
   'include-symbols', 'exclude-ambiguous'].forEach(id => {
    getElementById(id)?.addEventListener('change', generateAndDisplay);
  });

  getElementById('generate-btn')?.addEventListener('click', generateAndDisplay);

  getElementById('copy-generated-pw')?.addEventListener('click', async () => {
    const pw = AppState.lastGeneratedPassword;
    if (!pw) return;
    await PrivUtils.copyToClipboard(pw, 'Password');
    PrivUI.showToast('Password copied!', 'success');
  });

  getElementById('use-generated-pw')?.addEventListener('click', () => {
    const pw = AppState.lastGeneratedPassword;
    if (!pw) return;

    if (AppState.generatorCalledFrom === 'field') {
      const field = getElementById('field-password');
      if (field) {
        field.value = pw;
        field.type = 'text';
        PrivUI.updateFieldStrength(pw);
      }
    }

    PrivUI.hideModal('generator-modal');
    PrivUI.showToast('Password applied', 'success');
  });
}

/**
 * Open the password generator modal
 */
function openGenerator() {
  PrivUI.showModal('generator-modal');
  generateAndDisplay();
}

/**
 * Generate a password and display it
 */
function generateAndDisplay() {
  const options = {
    length: parseInt(getElementById('pw-length')?.value || '20', 10),
    uppercase: getElementById('include-uppercase')?.checked ?? true,
    lowercase: getElementById('include-lowercase')?.checked ?? true,
    numbers: getElementById('include-numbers')?.checked ?? true,
    symbols: getElementById('include-symbols')?.checked ?? true,
    excludeAmbiguous: getElementById('exclude-ambiguous')?.checked ?? false
  };

  const pw = PrivCrypto.generatePassword(options);
  AppState.lastGeneratedPassword = pw;

  const display = getElementById('generated-password');
  if (display) display.textContent = pw;

  PrivUI.updateGeneratorStrength(pw);
}

// ── Export / Import ───────────────────────────────────────────
async function handleExportVault() {
  if (!AppState.masterKey || !AppState.salt) {
    PrivUI.showToast('No vault to export', 'error');
    return;
  }

  try {
    // Always re-encrypt fresh for export
    const blob = await PrivCrypto.createVaultFile(
      AppState.vault,
      AppState.masterKey,
      AppState.salt
    );

    PrivStorage.exportVaultFile(blob, 'privvault');
    PrivUI.showToast('Vault exported successfully', 'success');

    // Increment reminder counter
    AppState.vault.settings.backupReminderCount = 0;

  } catch (err) {
    PrivUI.showToast('Export failed: ' + err.message, 'error');
  }
}

async function handleImportVault(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  try {
    const contents = await PrivStorage.readVaultFile(file);
    JSON.parse(contents); // Validate JSON

    showConfirmDialog(
      'Importing will replace your current vault session. ' +
      'Make sure you know the master password for the imported vault. Continue?',
      async () => {
        AppState.rawVaultBlob = contents;
        await PrivStorage.saveToIndexedDB(contents);
        lockVault();
        PrivUI.showToast('Vault loaded. Enter the master password to unlock.', 'info');
      }
    );
  } catch (err) {
    PrivUI.showToast('Import failed: ' + err.message, 'error');
  }

  event.target.value = '';
}

// ── Settings ──────────────────────────────────────────────────
function loadSettingsToUI() {
  const s = AppState.vault.settings;
  const autolockEl = getElementById('autolock-select');
  const clipEl = getElementById('clipboard-delay-select');
  const reminderEl = getElementById('backup-reminder');

  if (autolockEl) autolockEl.value = String(s.autolockMinutes);
  if (clipEl) clipEl.value = String(s.clipboardDelaySecs);
  if (reminderEl) reminderEl.checked = s.backupReminder;
}

function saveSettingsFromUI() {
  const autolockEl = getElementById('autolock-select');
  const clipEl = getElementById('clipboard-delay-select');
  const reminderEl = getElementById('backup-reminder');

  if (autolockEl) {
    AppState.vault.settings.autolockMinutes = parseInt(autolockEl.value, 10);
  }
  if (clipEl) {
    AppState.vault.settings.clipboardDelaySecs = parseInt(clipEl.value, 10);
    PrivUtils.setClipboardDelay(AppState.vault.settings.clipboardDelaySecs);
  }
  if (reminderEl) {
    AppState.vault.settings.backupReminder = reminderEl.checked;
  }

  // Restart auto-lock with new settings
  startAutoLock();

  // Persist settings
  persistVault().catch(console.warn);
}

function applySettings(settings) {
  PrivUtils.setClipboardDelay(settings.clipboardDelaySecs || 15);
}

// ── Change Master Password ────────────────────────────────────
async function handleChangeMasterPassword() {
  const currentPw = getElementById('current-master-pw')?.value;
  const newPw = getElementById('new-master-pw-change')?.value;
  const confirmPw = getElementById('confirm-new-master-pw')?.value;
  const btn = getElementById('confirm-change-pw-btn');

  PrivUI.hideError('change-pw-error');

  if (!currentPw || !newPw || !confirmPw) {
    PrivUI.showError('change-pw-error', 'All fields are required');
    return;
  }

  if (newPw !== confirmPw) {
    PrivUI.showError('change-pw-error', 'New passwords do not match');
    return;
  }

  const validation = PrivUtils.validateMasterPassword(newPw);
  if (!validation.valid) {
    PrivUI.showError('change-pw-error', validation.error);
    return;
  }

  setButtonLoading(btn, true, 'Updating...');

  try {
    // Verify current password by trying to decrypt
    let parsed;
    try { parsed = JSON.parse(AppState.rawVaultBlob); } catch {
      throw new Error('Vault data corrupted');
    }

    const currentSalt = PrivCrypto.fromBase64(parsed.salt);
    const testKey = await PrivCrypto.deriveKey(currentPw, currentSalt);
    await PrivCrypto.parseVaultFile(AppState.rawVaultBlob, testKey);

    // Generate new salt and key
    const newSalt = PrivCrypto.generateSalt();
    const newKey = await PrivCrypto.deriveKey(newPw, newSalt);

    // Re-encrypt vault
    const newBlob = await PrivCrypto.createVaultFile(
      AppState.vault, newKey, newSalt
    );

    AppState.masterKey = newKey;
    AppState.salt = newSalt;
    AppState.rawVaultBlob = newBlob;

    await PrivStorage.saveToIndexedDB(newBlob);

    PrivUI.hideModal('change-pw-modal');
    clearChangePwForm();
    PrivUI.showToast('Master password updated!', 'success');

  } catch (err) {
    PrivUI.showError('change-pw-error',
      'Incorrect current password or error: ' + err.message);
  } finally {
    setButtonLoading(btn, false, 'Update Master Password');
  }
}

// ── Vault Persistence ─────────────────────────────────────────
/**
 * Re-encrypt and save vault to IndexedDB
 */
async function persistVault() {
  if (!AppState.masterKey || !AppState.salt) return;

  try {
    const blob = await PrivCrypto.createVaultFile(
      AppState.vault,
      AppState.masterKey,
      AppState.salt
    );

    AppState.rawVaultBlob = blob;
    await PrivStorage.saveToIndexedDB(blob);
  } catch (err) {
    console.error('[PrivVault] Persist failed:', err);
    PrivUI.showToast('Auto-save failed: ' + err.message, 'error');
  }
}

// ── Sidebar Rendering ─────────────────────────────────────────
/**
 * Render sidebar with current filter/search
 */
function renderSidebar() {
  const { entries } = AppState.vault;

  // Collect all tags
  const allTags = [...new Set(
    entries.flatMap(e => e.tags || [])
  )].sort();

  PrivUI.renderTagFilter(allTags, AppState.activeTag);

  // Filter entries
  let filtered = entries;

  // Type filter
  if (AppState.currentFilter !== 'all') {
    filtered = filtered.filter(e => e.type === AppState.currentFilter);
  }

  // Tag filter
  if (AppState.activeTag) {
    filtered = filtered.filter(e =>
      (e.tags || []).includes(AppState.activeTag)
    );
  }

  // Search filter
  if (AppState.searchQuery.trim()) {
    const q = AppState.searchQuery.toLowerCase().trim();
    filtered = filtered.filter(e =>
      (e.title || '').toLowerCase().includes(q) ||
      (e.username || '').toLowerCase().includes(q) ||
      (e.url || '').toLowerCase().includes(q) ||
      (e.notes || '').toLowerCase().includes(q) ||
      (e.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }

  // Sort by title
  filtered.sort((a, b) => (a.title || '').localeCompare(b.title || ''));

  PrivUI.renderEntryList(filtered, AppState.currentEntryId);

  // Update stats
  const passwords = entries.filter(e => e.type !== 'note').length;
  const notes = entries.filter(e => e.type === 'note').length;
  PrivUI.updateVaultStats({ total: entries.length, passwords, notes });
}

// ── Auto-Lock ─────────────────────────────────────────────────
/**
 * Start auto-lock timer
 */
function startAutoLock() {
  clearAutoLock();

  const minutes = AppState.vault.settings.autolockMinutes;
  if (!minutes || minutes === 0) {
    PrivUI.updateLockCountdown(0);
    return;
  }

  AppState.lockSecondsLeft = minutes * 60;
  PrivUI.updateLockCountdown(AppState.lockSecondsLeft);

  AppState.lockCountdownTimer = setInterval(() => {
    AppState.lockSecondsLeft--;
    PrivUI.updateLockCountdown(AppState.lockSecondsLeft);

    if (AppState.lockSecondsLeft <= 0) {
      lockVault();
    }
  }, 1000);
}

/**
 * Clear auto-lock timer
 */
function clearAutoLock() {
  if (AppState.lockTimer) {
    clearTimeout(AppState.lockTimer);
    AppState.lockTimer = null;
  }
  if (AppState.lockCountdownTimer) {
    clearInterval(AppState.lockCountdownTimer);
    AppState.lockCountdownTimer = null;
  }
}

/**
 * Reset auto-lock on user activity
 */
function resetAutoLock() {
  if (AppState.isLocked) return;
  startAutoLock();
}

/**
 * Setup activity tracking for auto-lock reset
 */
function setupActivityTracking() {
  const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
  const reset = PrivUtils.debounce(resetAutoLock, 500);
  events.forEach(evt =>
    document.addEventListener(evt, reset, { passive: true })
  );
}

// ── Lock Vault ────────────────────────────────────────────────
/**
 * Lock the vault and clear all sensitive data
 */
function lockVault() {
  clearAutoLock();
  PrivUtils.clearClipboard();
  PrivUtils.stopClipboardCountdown();

  // Clear sensitive state
  AppState.masterKey = null;
  AppState.salt = null;
  AppState.vault = createEmptyVault();
  AppState.currentEntryId = null;
  AppState.editingEntry = null;
  AppState.isNewEntry = false;
  AppState.editingTags = [];
  AppState.isLocked = true;
  AppState.lastGeneratedPassword = null;
  AppState.searchQuery = '';

  // Clear all input fields
  clearSensitiveInputs();

  // Close modals
  document.querySelectorAll('.modal-overlay').forEach(m =>
    m.classList.add('hidden')
  );

  PrivUI.showUnlock();
  PrivUI.showToast('Vault locked', 'info');
}

/**
 * Clear all sensitive form fields
 */
function clearSensitiveInputs() {
  const sensitiveIds = [
    'field-password', 'master-password', 'new-master-pw',
    'confirm-master-pw', 'current-master-pw', 'new-master-pw-change',
    'confirm-new-master-pw', 'field-username', 'field-notes',
    'field-url', 'entry-title', 'note-content', 'generated-password',
    'search-input'
  ];
  sensitiveIds.forEach(id => {
    const el = getElementById(id);
    if (el) el.value = '';
  });
}

// ── Backup Reminder ───────────────────────────────────────────
function checkBackupReminder() {
  if (!AppState.vault.settings.backupReminder) return;

  const count = AppState.vault.settings.backupReminderCount || 0;
  const threshold = 10;

  if (count >= threshold) {
    setTimeout(() => {
      PrivUI.showToast(
        '💾 Reminder: Export your vault for a backup!',
        'warning',
        8000
      );
      AppState.vault.settings.backupReminderCount = 0;
    }, 3000);
  } else {
    AppState.vault.settings.backupReminderCount = count + 1;
  }
}

// ── Helpers ───────────────────────────────────────────────────
/**
 * Get element by ID (cached)
 * @param {string} id
 * @returns {HTMLElement|null}
 */
function getElementById(id) {
  return document.getElementById(id);
}

/**
 * Bind toggle password visibility
 * @param {string} btnId
 * @param {string} inputId
 */
function bindTogglePw(btnId, inputId) {
  const btn = getElementById(btnId);
  const input = getElementById(inputId);
  if (!btn || !input) return;
  btn.addEventListener('click', () =>
    PrivUI.togglePasswordVisibility(input, btn)
  );
}

/**
 * Set button loading state
 * @param {HTMLButtonElement} btn
 * @param {boolean} loading
 * @param {string} text
 */
function setButtonLoading(btn, loading, text) {
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = text;
}

/**
 * Show confirm dialog
 * @param {string} message
 * @param {Function} callback
 */
function showConfirmDialog(message, callback) {
  const msgEl = getElementById('confirm-message');
  if (msgEl) msgEl.textContent = message;
  AppState._confirmCallback = callback;
  PrivUI.showModal('confirm-modal');
}

/**
 * Create an empty vault structure
 * @returns {object}
 */
function createEmptyVault() {
  return {
    entries: [],
    settings: {
      autolockMinutes: 5,
      clipboardDelaySecs: 15,
      backupReminder: true,
      backupReminderCount: 0
    },
    created_at: new Date().toISOString(),
    modified_at: new Date().toISOString()
  };
}

/**
 * Merge vault data with defaults
 * @param {object} data
 * @returns {object}
 */
function mergeVaultDefaults(data) {
  const defaults = createEmptyVault();
  return {
    ...defaults,
    ...data,
    settings: {
      ...defaults.settings,
      ...(data.settings || {})
    },
    entries: Array.isArray(data.entries) ? data.entries : []
  };
}

/**
 * Deep copy an object
 * @param {object} obj
 * @returns {object}
 */
function deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Clear create vault form
 */
function clearCreateForm() {
  const ids = ['new-master-pw', 'confirm-master-pw'];
  ids.forEach(id => {
    const el = getElementById(id);
    if (el) el.value = '';
  });

  const bar = getElementById('strength-bar');
  if (bar) { bar.style.width = '0'; }
  const lbl = getElementById('strength-label');
  if (lbl) lbl.textContent = '';

  PrivUI.hideError('create-error');
}

/**
 * Clear change password form
 */
function clearChangePwForm() {
  ['current-master-pw', 'new-master-pw-change', 'confirm-new-master-pw']
    .forEach(id => {
      const el = getElementById(id);
      if (el) el.value = '';
    });
  PrivUI.hideError('change-pw-error');
}