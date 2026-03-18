/**
 * PrivVault – crypto.js
 * PrivMITLab | Zero-Knowledge Cryptography Module
 *
 * Algorithm: AES-256-GCM (encryption) + Argon2id (KDF)
 * All operations use Web Crypto API (native browser)
 * Argon2id is stubbed with PBKDF2 fallback when WASM unavailable
 *
 * SECURITY NOTICE:
 * - Never log keys, passwords, or plaintext data
 * - IVs are random per encryption operation
 * - Salt is random per vault creation
 */

'use strict';

const PrivCrypto = (() => {

  // ── Constants ────────────────────────────────────────────────
  const ALGO        = 'AES-GCM';
  const KEY_LENGTH  = 256;
  const IV_LENGTH   = 12;   // 96 bits for GCM
  const SALT_LENGTH = 32;   // 256 bits
  const TAG_LENGTH  = 128;  // GCM auth tag bits

  // Argon2id params (OWASP recommended minimums)
  const ARGON2_TIME_COST    = 3;
  const ARGON2_MEMORY_COST  = 65536; // 64 MiB
  const ARGON2_PARALLELISM  = 4;

  // PBKDF2 fallback params (when Argon2 WASM unavailable)
  const PBKDF2_ITERATIONS   = 600000;
  const PBKDF2_HASH         = 'SHA-256';

  // Vault file format version
  const VAULT_VERSION       = 1;

  // Track if Argon2 WASM is available
  let argon2Available = false;

  /**
   * Attempt to load Argon2 WASM
   * Falls back to PBKDF2 if unavailable
   */
  async function initArgon2() {
    try {
      // Try loading argon2-browser WASM (if present)
      if (typeof window.argon2 !== 'undefined') {
        argon2Available = true;
        console.info('[PrivVault] Argon2 WASM loaded successfully');
      } else {
        console.warn('[PrivVault] Argon2 WASM not found – using PBKDF2 fallback');
        argon2Available = false;
      }
    } catch {
      argon2Available = false;
    }
  }

  /**
   * Generate cryptographically random bytes
   * @param {number} length - Number of bytes
   * @returns {Uint8Array}
   */
  function randomBytes(length) {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return buffer;
  }

  /**
   * Generate a new random salt
   * @returns {Uint8Array}
   */
  function generateSalt() {
    return randomBytes(SALT_LENGTH);
  }

  /**
   * Generate a new random IV for AES-GCM
   * @returns {Uint8Array}
   */
  function generateIV() {
    return randomBytes(IV_LENGTH);
  }

  /**
   * Convert ArrayBuffer to Base64 string
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {string}
   */
  function toBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 string to Uint8Array
   * @param {string} base64
   * @returns {Uint8Array}
   */
  function fromBase64(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Encode string to UTF-8 bytes
   * @param {string} str
   * @returns {Uint8Array}
   */
  function encodeText(str) {
    return new TextEncoder().encode(str);
  }

  /**
   * Decode UTF-8 bytes to string
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function decodeText(bytes) {
    return new TextDecoder().decode(bytes);
  }

  /**
   * Derive an AES-256 key from a master password
   * Uses Argon2id (WASM) if available, otherwise PBKDF2-SHA256
   *
   * @param {string} password - Master password
   * @param {Uint8Array|string} salt - Random salt (b64 or bytes)
   * @returns {Promise<CryptoKey>} AES-GCM key
   */
  async function deriveKey(password, salt) {
    if (!password || typeof password !== 'string') {
      throw new Error('Invalid password');
    }

    // Normalize salt
    const saltBytes = typeof salt === 'string' ? fromBase64(salt) : salt;

    if (argon2Available && typeof window.argon2 !== 'undefined') {
      return await deriveKeyArgon2(password, saltBytes);
    } else {
      return await deriveKeyPBKDF2(password, saltBytes);
    }
  }

  /**
   * Key derivation using Argon2id (WASM)
   * @private
   */
  async function deriveKeyArgon2(password, saltBytes) {
    const result = await window.argon2.hash({
      pass: password,
      salt: saltBytes,
      time: ARGON2_TIME_COST,
      mem: ARGON2_MEMORY_COST,
      parallelism: ARGON2_PARALLELISM,
      hashLen: 32,
      type: window.argon2.ArgonType.Argon2id
    });

    const rawKey = result.hash;

    return await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: ALGO, length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Key derivation using PBKDF2-SHA256 (fallback)
   * @private
   */
  async function deriveKeyPBKDF2(password, saltBytes) {
    const passwordBytes = encodeText(password);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH
      },
      baseKey,
      { name: ALGO, length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt plaintext data with AES-256-GCM
   * Each call generates a fresh random IV
   *
   * @param {string|object} data - Data to encrypt
   * @param {CryptoKey} key - Derived AES key
   * @returns {Promise<{iv: string, ciphertext: string}>}
   */
  async function encryptData(data, key) {
    if (!key) throw new Error('No encryption key provided');

    const plaintext = typeof data === 'string'
      ? data
      : JSON.stringify(data);

    const iv = generateIV();
    const encoded = encodeText(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: ALGO, iv, tagLength: TAG_LENGTH },
      key,
      encoded
    );

    return {
      iv: toBase64(iv),
      ciphertext: toBase64(ciphertextBuffer)
    };
  }

  /**
   * Decrypt AES-256-GCM ciphertext
   *
   * @param {string} ciphertext - Base64 encoded ciphertext
   * @param {string} iv - Base64 encoded IV
   * @param {CryptoKey} key - Derived AES key
   * @returns {Promise<string>} Decrypted plaintext
   */
  async function decryptData(ciphertext, iv, key) {
    if (!key) throw new Error('No decryption key provided');

    const ivBytes = fromBase64(iv);
    const ciphertextBytes = fromBase64(ciphertext);

    try {
      const plaintextBuffer = await crypto.subtle.decrypt(
        { name: ALGO, iv: ivBytes, tagLength: TAG_LENGTH },
        key,
        ciphertextBytes
      );

      return decodeText(new Uint8Array(plaintextBuffer));
    } catch {
      throw new Error('Decryption failed – wrong password or corrupted data');
    }
  }

  /**
   * Create a complete encrypted vault blob
   * Ready to be saved as .privvault file
   *
   * @param {object} vaultData - The vault contents
   * @param {CryptoKey} key - Derived AES key
   * @param {Uint8Array} salt - The salt used for key derivation
   * @returns {Promise<string>} JSON string of vault file
   */
  async function createVaultFile(vaultData, key, salt) {
    const { iv, ciphertext } = await encryptData(vaultData, key);

    const vaultFile = {
      version: VAULT_VERSION,
      kdf: argon2Available ? 'argon2id' : 'pbkdf2',
      kdf_params: argon2Available
        ? {
            time_cost: ARGON2_TIME_COST,
            memory_cost: ARGON2_MEMORY_COST,
            parallelism: ARGON2_PARALLELISM
          }
        : {
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
          },
      salt: toBase64(salt),
      iv,
      ciphertext,
      created_at: new Date().toISOString(),
      app: 'PrivVault by PrivMITLab'
    };

    return JSON.stringify(vaultFile, null, 2);
  }

  /**
   * Parse and decrypt a vault file
   *
   * @param {string} fileContents - Raw .privvault file contents
   * @param {CryptoKey} key - Derived AES key
   * @returns {Promise<object>} Decrypted vault data
   */
  async function parseVaultFile(fileContents, key) {
    let parsed;

    try {
      parsed = JSON.parse(fileContents);
    } catch {
      throw new Error('Invalid vault file format');
    }

    if (!parsed.version || !parsed.salt || !parsed.iv || !parsed.ciphertext) {
      throw new Error('Vault file is missing required fields');
    }

    if (parsed.version > VAULT_VERSION) {
      throw new Error(`Vault version ${parsed.version} not supported`);
    }

    const plaintext = await decryptData(parsed.ciphertext, parsed.iv, key);

    try {
      return JSON.parse(plaintext);
    } catch {
      throw new Error('Vault data is corrupted');
    }
  }

  /**
   * Generate a secure password
   *
   * @param {object} options
   * @param {number} options.length
   * @param {boolean} options.uppercase
   * @param {boolean} options.lowercase
   * @param {boolean} options.numbers
   * @param {boolean} options.symbols
   * @param {boolean} options.excludeAmbiguous
   * @returns {string}
   */
  function generatePassword(options = {}) {
    const {
      length = 20,
      uppercase = true,
      lowercase = true,
      numbers = true,
      symbols = true,
      excludeAmbiguous = false
    } = options;

    let charset = '';
    const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
    const NUMS    = '0123456789';
    const SYMS    = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    const AMBIG   = /[0Ol1I]/g;

    let required = [];

    if (uppercase) {
      let chars = uppercase ? UPPER : '';
      if (excludeAmbiguous) chars = chars.replace(AMBIG, '');
      charset += chars;
      if (chars) required.push(chars[secureRandomInt(chars.length)]);
    }

    if (lowercase) {
      let chars = LOWER;
      if (excludeAmbiguous) chars = chars.replace(AMBIG, '');
      charset += chars;
      if (chars) required.push(chars[secureRandomInt(chars.length)]);
    }

    if (numbers) {
      let chars = NUMS;
      if (excludeAmbiguous) chars = chars.replace(AMBIG, '');
      charset += chars;
      if (chars) required.push(chars[secureRandomInt(chars.length)]);
    }

    if (symbols) {
      charset += SYMS;
      required.push(SYMS[secureRandomInt(SYMS.length)]);
    }

    if (!charset) {
      charset = LOWER + NUMS;
      required.push(LOWER[secureRandomInt(LOWER.length)]);
    }

    // Fill rest randomly
    const randomPart = [];
    const remaining = Math.max(0, length - required.length);

    for (let i = 0; i < remaining; i++) {
      randomPart.push(charset[secureRandomInt(charset.length)]);
    }

    // Combine and shuffle
    const all = [...required, ...randomPart];
    return secureShuffleArray(all).join('');
  }

  /**
   * Generate a secure random integer in [0, max)
   * Uses crypto.getRandomValues for true randomness
   * @param {number} max
   * @returns {number}
   */
  function secureRandomInt(max) {
    const range = 256 - (256 % max);
    const bytes = new Uint8Array(1);
    let val;
    do {
      crypto.getRandomValues(bytes);
      val = bytes[0];
    } while (val >= range);
    return val % max;
  }

  /**
   * Fisher-Yates shuffle using crypto-random swaps
   * @param {Array} arr
   * @returns {Array}
   */
  function secureShuffleArray(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  /**
   * Calculate password strength score
   *
   * @param {string} password
   * @returns {{ score: number, label: string, color: string }}
   */
  function calculateStrength(password) {
    if (!password) {
      return { score: 0, percent: 0, label: '', color: '' };
    }

    let score = 0;

    // Length scoring
    if (password.length >= 8)   score += 1;
    if (password.length >= 12)  score += 1;
    if (password.length >= 16)  score += 1;
    if (password.length >= 24)  score += 1;

    // Complexity
    if (/[a-z]/.test(password))     score += 1;
    if (/[A-Z]/.test(password))     score += 1;
    if (/[0-9]/.test(password))     score += 1;
    if (/[^a-zA-Z0-9]/.test(password)) score += 2;

    // Penalize repeating chars
    if (/(.)\1{2,}/.test(password))  score -= 1;
    // Penalize common patterns
    if (/12345|abcde|qwerty|password|letmein/i.test(password)) score -= 2;

    score = Math.max(0, Math.min(10, score));

    const levels = [
      { min: 0, max: 2,  label: 'Very Weak', color: '#ff4d6d' },
      { min: 3, max: 4,  label: 'Weak',      color: '#ff8c42' },
      { min: 5, max: 6,  label: 'Fair',      color: '#ffd166' },
      { min: 7, max: 8,  label: 'Good',      color: '#06d6a0' },
      { min: 9, max: 10, label: 'Strong',    color: '#00ffa3' }
    ];

    const level = levels.find(l => score >= l.min && score <= l.max)
      || levels[0];

    return {
      score,
      percent: (score / 10) * 100,
      label: level.label,
      color: level.color
    };
  }

  /**
   * Securely zero out a string reference
   * (Best-effort in JavaScript – GC will eventually collect)
   * @param {string} _ - The sensitive string (hint to GC)
   */
  function secureWipe(_) {
    // JavaScript strings are immutable; we cannot truly wipe memory.
    // This function exists as a semantic marker for sensitive data.
    // In production, use WebAssembly for truly sensitive operations.
    void _;
  }

  // Initialize Argon2
  initArgon2();

  // Public API
  return Object.freeze({
    generateSalt,
    generateIV,
    deriveKey,
    encryptData,
    decryptData,
    createVaultFile,
    parseVaultFile,
    generatePassword,
    calculateStrength,
    secureWipe,
    toBase64,
    fromBase64,
    VAULT_VERSION
  });

})();