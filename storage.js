/**
 * PrivVault – storage.js
 * PrivMITLab | Storage Module
 *
 * Handles:
 * - IndexedDB session storage (encrypted key + vault in memory)
 * - Vault file export/import
 * - Auto-save to IndexedDB (encrypted only)
 */

'use strict';

const PrivStorage = (() => {

  const DB_NAME    = 'privvault_db';
  const DB_VERSION = 1;
  const STORE_NAME = 'vault_session';

  let db = null;

  /**
   * Initialize IndexedDB
   * @returns {Promise<IDBDatabase>}
   */
  async function initDB() {
    if (db) return db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => {
        console.error('[PrivStorage] IndexedDB error:', request.error);
        reject(request.error);
      };

      request.onsuccess = () => {
        db = request.result;
        resolve(db);
      };

      request.onupgradeneeded = (event) => {
        const database = event.target.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          database.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };
    });
  }

  /**
   * Save encrypted vault blob to IndexedDB
   * (Only stores encrypted data – never plaintext)
   *
   * @param {string} encryptedBlob - JSON string of vault file
   * @returns {Promise<void>}
   */
  async function saveToIndexedDB(encryptedBlob) {
    try {
      const database = await initDB();
      return new Promise((resolve, reject) => {
        const tx = database.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.put({
          id: 'vault',
          data: encryptedBlob,
          timestamp: Date.now()
        });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch (err) {
      console.warn('[PrivStorage] IndexedDB save failed:', err.message);
    }
  }

  /**
   * Load encrypted vault blob from IndexedDB
   * @returns {Promise<string|null>}
   */
  async function loadFromIndexedDB() {
    try {
      const database = await initDB();
      return new Promise((resolve, reject) => {
        const tx = database.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const request = store.get('vault');
        request.onsuccess = () => {
          resolve(request.result?.data || null);
        };
        request.onerror = () => reject(request.error);
      });
    } catch (err) {
      console.warn('[PrivStorage] IndexedDB load failed:', err.message);
      return null;
    }
  }

  /**
   * Clear IndexedDB session data
   * Called on lock or close
   * @returns {Promise<void>}
   */
  async function clearIndexedDB() {
    try {
      const database = await initDB();
      return new Promise((resolve, reject) => {
        const tx = database.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.delete('vault');
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch (err) {
      console.warn('[PrivStorage] IndexedDB clear failed:', err.message);
    }
  }

  /**
   * Export vault to downloadable .privvault file
   * @param {string} encryptedBlob - Encrypted vault contents
   * @param {string} filename - Optional filename
   */
  function exportVaultFile(encryptedBlob, filename) {
    const safeName = (filename || 'vault').replace(/[^a-zA-Z0-9_-]/g, '_');
    const finalName = `${safeName}_${formatDateForFilename()}.privvault`;

    const blob = new Blob([encryptedBlob], {
      type: 'application/octet-stream'
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = finalName;
    anchor.style.display = 'none';

    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);

    // Revoke object URL after short delay
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  /**
   * Read a vault file from a File input
   * @param {File} file
   * @returns {Promise<string>}
   */
  function readVaultFile(file) {
    return new Promise((resolve, reject) => {
      if (!file) {
        reject(new Error('No file provided'));
        return;
      }

      // Validate file extension
      if (!file.name.endsWith('.privvault')) {
        reject(new Error('Invalid file type – expected .privvault'));
        return;
      }

      // Limit file size (32 MB max)
      const MAX_SIZE = 32 * 1024 * 1024;
      if (file.size > MAX_SIZE) {
        reject(new Error('Vault file too large'));
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file, 'UTF-8');
    });
  }

  /**
   * Format current date for filename
   * @returns {string} e.g. "2025-01-15"
   * @private
   */
  function formatDateForFilename() {
    const d = new Date();
    const year  = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day   = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  /**
   * Check if vault exists in IndexedDB
   * @returns {Promise<boolean>}
   */
  async function hasStoredVault() {
    const data = await loadFromIndexedDB();
    return data !== null;
  }

  return Object.freeze({
    initDB,
    saveToIndexedDB,
    loadFromIndexedDB,
    clearIndexedDB,
    exportVaultFile,
    readVaultFile,
    hasStoredVault
  });

})();