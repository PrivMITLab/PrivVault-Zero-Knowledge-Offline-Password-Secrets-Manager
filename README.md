# PrivVault – Zero-Knowledge Offline Password Manager

**by PrivMITLab**  
_Your Data. Your Control. Zero Compromise._

---

## Overview

PrivVault is a fully client-side, zero-knowledge, offline-first password manager.  
Your data **never leaves your device** unless you explicitly export it.  
No accounts. No servers. No telemetry. No tracking. Ever.

---

## Features

### Core
- 🔐 **AES-256-GCM Encryption** – Military-grade symmetric encryption
- 🔑 **Argon2id / PBKDF2 Key Derivation** – Memory-hard KDF, resistant to brute-force
- 🌐 **100% Offline** – Works without internet (PWA installable)
- 📁 **Local Vault File** – Encrypted `.privvault` file you own
- 🚫 **Zero Knowledge** – Developer cannot access your data

### Password Management
- ✅ Add, edit, delete entries
- 🏷️ Tag system for organization
- 🔍 Real-time search
- 📋 One-click copy with auto-clear clipboard
- 🌐 URL launcher
- 📝 Per-entry notes

### Security Features
- 🔒 Auto-lock after inactivity (configurable)
- ⏱️ Clipboard auto-clear (configurable 10–60s)
- 🛡️ Brute-force protection (progressive delays + lockout)
- 🧹 Memory clearing on lock
- 🚫 XSS prevention via DOM text nodes

### Generator
- 🎲 Cryptographically secure password generator
- ⚙️ Length, character sets, ambiguous char exclusion
- 💪 Real-time strength meter

### Vault Management
- 📤 Export encrypted vault file
- 📥 Import existing vault
- 💾 Auto-save to IndexedDB (encrypted)
- 📅 Backup reminders
- 🔄 Master password change (re-encryption)

---

## How Encryption Works