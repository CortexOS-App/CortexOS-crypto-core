![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)
![Swift](https://img.shields.io/badge/Swift-100%25-cyan.svg)
![Encryption](https://img.shields.io/badge/AES--256--GCM-✓-cyan.svg)
![Key Derivation](https://img.shields.io/badge/Argon2id-64MB%20·%203iter%20·%204p-cyan.svg)
![Zero Knowledge](https://img.shields.io/badge/Zero--Knowledge-Verified-cyan.svg)
![Platform](https://img.shields.io/badge/iOS-17%2B-cyan.svg)

# CortexOS Cryptographic Core

This repository contains the cryptographic layer of [CortexOS](https://cortexos.app) — the code that handles key derivation, encryption, recovery phrase management, and zero-knowledge vault operations.

The full app is proprietary. This subset is published so users and security researchers can verify that the encryption claims in our [whitepaper](https://cortexos.app/whitepaper) match the actual implementation.

**Your Mind, Encrypted.**

## What's Here

| File | Purpose |
|------|---------|
| **KeyDerivation.swift** | Argon2id key derivation (t=3, m=64MB, p=4). v3 scheme: a 32-byte per-user vault salt is mixed into ALL derived values (accountId, encryptionKey, authToken), plus a phrase-only lookupId (lightweight profile) and a saltKey that encrypts the vault salt at rest on the server. Includes SaltManager: fetch/decrypt distinguishes wrong-phrase from network failure so keys are never derived against a wrong salt. |
| **RecoveryPhraseManager.swift** | BIP39-compliant 6-word + 4-digit PIN recovery phrase. Generation, validation, challenge verification, and cross-platform hashing (SHA-256). |
| **EncryptionManager.swift** | AES-256-GCM encryption/decryption with thread-safe initialization. Two-key model: the phrase-derived master key wraps the portable vault; a separate device-local at-rest key (iOS Keychain) encrypts local columns and never leaves the device. |
| **VaultManager.swift** | Zero-knowledge encrypted backup/restore (blob format v5, key scheme v3). Server never sees plaintext. Includes the v2 to v3 migration path with a half-migration guard (an account is never stamped v3 while any entry failed re-key), a clobber guard on uploads, and full account deletion. |

## Architecture

```
Recovery Phrase (6 words + PIN)
        │
        ▼
┌─────────────────────────────────┐
│       KeyDerivation.swift       │
│         Argon2id (64MB)         │
│                                 │
│  Fixed salt ──► accountId       │  ← Server lookup identifier
│  Per-user salt ──► encKey       │  ← AES-256-GCM master key
│  Per-user salt ──► authToken    │  ← API authentication
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│     EncryptionManager.swift     │
│        AES-256-GCM              │
│                                 │
│  plaintext ──► encrypted blob   │
│  encrypted blob ──► plaintext   │
│  Master key in iOS Keychain     │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│       VaultManager.swift        │
│    Zero-Knowledge Backup        │
│                                 │
│  Entries + Pattern Snapshots    │
│  ──► JSON ──► Encrypt           │
│  ──► Upload to Cloudflare R2    │
│                                 │
│  Download ──► Decrypt ──► JSON  │
│  ──► Restore entries + patterns │
│                                 │
│  Per-user salt synced to server │
│  for cross-device restore       │
└─────────────────────────────────┘
```

## Key Derivation Details

CortexOS derives three distinct keys from a single recovery phrase using **Argon2id** with domain-separated salts:

| Key | Salt | Purpose |
|-----|------|---------|
| `accountId` | Fixed: `cortexos-account-id-v2-argon2id` | Deterministic server lookup (same on all devices) |
| `encryptionKey` | `cortexos-encryption-key-v2-argon2id` + per-user salt | AES-256-GCM master key (unique per user) |
| `authToken` | `cortexos-auth-token-v2-argon2id` + per-user salt | API authentication (unique per user) |

**Argon2id parameters:**
- Memory: 65,536 KB (64 MB)
- Iterations: 3
- Parallelism: 4
- Output: 32 bytes (256 bits)

The `accountId` uses a fixed salt so the same phrase always produces the same identifier on any device or platform — this is how the server finds the user's vault without knowing who they are.

The `encryptionKey` and `authToken` use the fixed purpose-prefix concatenated with a 32-byte random per-user salt. This ensures that even if two users chose the same recovery phrase (astronomically unlikely), their encryption keys would differ.

## Cross-Device Restore

When a user restores on a new device, they only have their recovery phrase. The per-user salt is stored on the server (alongside the encrypted vault) so the new device can:

1. Derive `accountId` (fixed salt — no per-user salt needed)
2. Fetch per-user salt from server using `accountId`
3. Re-derive `encryptionKey` and `authToken` with the fetched salt
4. Download and decrypt the vault

The server stores the salt but cannot use it — the salt is meaningless without the recovery phrase, and the recovery phrase never leaves the device.

## Recovery Phrase

- **Format:** 6 BIP39 words + 4-digit PIN (e.g., `apple banana cherry dog elephant fox-1234`)
- **Entropy:** 6 words × 11 bits = ~66 bits + ~13 bits (PIN) ≈ 79 bits
- **Combinations:** ~7.2 × 10²³
- **Challenge:** Login requires 2 random words (by position) + PIN — not the full phrase
- **Hashing:** Word hashes use `SHA-256("position:word")`, PIN uses `SHA-256("cortexos:pin:XXXX")` with optional per-user salt

The recovery phrase is generated on-device and never transmitted to any server. Word and PIN hashes are stored in the iOS Keychain for local verification.

## What's NOT Here

This is the security layer only. The following are not included:

- UI / SwiftUI views
- AI analysis pipeline (sentiment, emotions, patterns)
- On-device LLM (Llama 3.2 for reflections)
- Network layer / API endpoints
- SwiftData models
- Widget extensions

## Cross-Platform Verification

The test vector in `KeyDerivation.swift` can be run on both iOS and Android to confirm byte-identical output:

```
Input: "apple banana cherry dog elephant fox-1234"

KeyDerivation.runCrossPlatformTests()
// Outputs accountId, authToken, key length
// Must match Android EXACTLY
```

`RecoveryPhraseManager` also includes cross-platform hash verification:

```
RecoveryPhraseManager.runCrossPlatformTests()
// Outputs word hashes, PIN hash (with and without salt)
// Must match Android EXACTLY
```

## License

MIT — see [LICENSE](LICENSE).

## Links

- **Download:** [App Store](https://apps.apple.com/mt/app/cortexos/id6759070325) [Google Play Store](https://play.google.com/store/apps/details?id=com.cortexos.app)
- **Website:** [cortexos.app](https://cortexos.app)
- **Whitepaper:** [cortexos.app/whitepaper](https://cortexos.app/whitepaper)
- **Product Hunt:** [producthunt.com/@cortexos](https://www.producthunt.com/@cortexos)

## Version parity

The code in this repository matches the shipping apps: **iOS v1.7.0 and Android v1.5.0** (both live). When the crypto layer changes in a release, this repository is updated alongside it. RecoveryPhraseManager, KeyDerivation, EncryptionManager, and VaultManager are copied verbatim from the iOS source tree.

## Independent verification (golden vector)

Both platforms and this repository derive byte-identical keys. Verify with the permanent test vector (a test constant, not a real account):

```
Phrase:     apple banana cherry dog elephant fox-1234
Vault salt: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Argon2id:   64 MB, 3 iterations, parallelism 4, 32-byte output
Salt composition (v3): vaultSalt || purpose suffix (UTF-8), suffixes:
  accountId:  "cortexos-account-id-v3"
  encKey:     "cortexos-encryption-key-v3"
  authToken:  "cortexos-auth-token-v3"
lookupId:   phrase-only, lightweight Argon2id (16 MB, 1 iteration), suffix "cortexos-lookup-id-v3"
Expected:   lookupId e719eb7b..., accountId a82db13d..., encryptionKey ef6b0ecd..., authToken 4547d10a...
```

Any Argon2id reference implementation (argon2-cffi, BouncyCastle, the C reference) reproduces these values, which is exactly the point: nothing about the scheme is secret except the phrase.
