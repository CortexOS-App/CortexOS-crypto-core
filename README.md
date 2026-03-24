![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)
![Swift](https://img.shields.io/badge/Swift-100%25-cyan.svg)
![Encryption](https://img.shields.io/badge/AES--256--GCM-✓-cyan.svg)
![Key Derivation](https://img.shields.io/badge/Argon2id-64MB%20·%203iter%20·%204p-cyan.svg)
![Zero Knowledge](https://img.shields.io/badge/Zero--Knowledge-Verified-cyan.svg)
![Platform](https://img.shields.io/badge/iOS-17%2B-cyan.svg)
  
# CortexOS Cryptographic Core

  This repository contains the cryptographic layer of CortexOS — the code that
  handles key derivation, encryption, and vault operations.

  The full app is proprietary. This subset is published so users and security
  researchers can verify that the encryption claims in our whitepaper match the
  actual implementation.

## What's here

  - KeyDerivation.swift — Argon2id key derivation (t=3, m=64MB, p=4)
  - RecoveryPhraseManager.swift — BIP39 phrase generation and challenge verification
  - EncryptionManager.swift — AES-256-GCM encryption/decryption
  - VaultManager.swift — Zero-knowledge vault backup/restore logic

## What's not here

  This is the security layer only. The UI, AI pipeline, and network endpoints
  are not included.

## Verification

  The cross-platform test vector in KeyDerivation.swift can be run on both
  iOS and Android to confirm byte-identical output:

  Input:  "apple banana cherry dog elephant fox-1234"
  Run KeyDerivation.runCrossPlatformTests() on both platforms.
  Outputs must match exactly for login to work cross-platform.

## Whitepaper

  Full technical documentation: https://cortexos.app/whitepaper
