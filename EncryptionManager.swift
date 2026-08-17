import Foundation
import CryptoKit

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTION MANAGER
//
// Handles AES-256-GCM encryption for journal entries and vault data.
// Uses iOS Keychain for secure key storage.
//
// IMPORTANT: Call `initialize()` before any encryption/decryption operations
// to avoid race conditions during app startup.
// ═══════════════════════════════════════════════════════════════════════════════

public final class EncryptionManager {

    public static let shared = EncryptionManager()

    private let keychainManager = KeychainManager.shared
    /// The phrase-derived key. Used ONLY to wrap the portable vault blob + encrypt the salt
    /// (via `getEncryptionKey()`). Set by `setupWithDerivedKeys`; changes on v2→v3 migration.
    private let masterKeyIdentifier = "com.cortexos.master_encryption_key"
    /// The device-local at-rest key. Encrypts entry/analysis/reflection columns on THIS device.
    /// Never leaves the device, never reproduced across devices, never overwritten by key
    /// derivation. Portability goes through plaintext-in-blob (v5), not by shipping this key.
    /// Seeded from the master key for existing installs (so existing data needs NO
    /// re-encryption); freshly random for new installs. This is what closes the historical
    /// random-master-key hazard: the random key is now explicitly the stable at-rest key,
    /// never confused with (or overwritten by) the derived key.
    private let atRestKeyIdentifier = "com.cortexos.at_rest_key"

    // MARK: - Initialization State

    /// Whether the encryption manager has been initialized
    public private(set) var isInitialized = false

    /// Lock to prevent concurrent initialization
    private let initLock = NSLock()

    /// Continuation for callers waiting on initialization
    private var initializationTask: Task<Void, Error>?

    public enum EncryptionError: Error, LocalizedError {
        case keyGenerationFailed
        case keyRetrievalFailed
        case encryptionFailed
        case decryptionFailed
        case invalidData
        case keychainError(String)
        case notInitialized

        public var errorDescription: String? {
            switch self {
            case .keyGenerationFailed: return "Failed to generate encryption key"
            case .keyRetrievalFailed: return "Failed to retrieve encryption key"
            case .encryptionFailed: return "Failed to encrypt data"
            case .decryptionFailed: return "Failed to decrypt data"
            case .invalidData: return "Invalid data format"
            case .keychainError(let message): return "Keychain error: \(message)"
            case .notInitialized: return "Encryption manager not initialized. Call initialize() first."
            }
        }
    }

    private init() {
        // Don't auto-initialize in init - wait for explicit initialize() call
        // This prevents race conditions
    }

    // MARK: - Initialization

    /// Initialize the encryption manager. Call this early in app launch.
    /// Safe to call multiple times - subsequent calls will wait for first initialization.
    @discardableResult
    public func initialize() async throws -> Bool {
        // Fast path: already initialized
        if isInitialized { return true }

        // Ensure only one initialization happens
        initLock.lock()
        if let existingTask = initializationTask {
            initLock.unlock()
            try await existingTask.value
            return isInitialized
        }

        let task = Task {
            try await ensureMasterKey()
            isInitialized = true
        }
        initializationTask = task
        initLock.unlock()

        try await task.value
        return isInitialized
    }

    /// Synchronous check and auto-initialize if needed (for backward compatibility)
    /// Prefer using initialize() async in app startup
    private func ensureInitialized() throws {
        if isInitialized { return }

        // At-rest encryption depends on the at-rest key (not the derived master key), so
        // either the at-rest key or the master key being present means we can proceed.
        if (try? keychainManager.load(forKey: atRestKeyIdentifier)) != nil
            || (try? getMasterKeySync()) != nil {
            isInitialized = true
            return
        }

        // If no key exists, we need async initialization
        throw EncryptionError.notInitialized
    }

    // MARK: - Key Management

    /// Ensure the device-local at-rest key exists. This REPLACES the old behaviour of
    /// minting a random *master* key (the §6 landmine, where a random key could precede
    /// `setupWithDerivedKeys` and then be overwritten, orphaning entries). We never touch the
    /// master (derived) key here — it is owned exclusively by `setupWithDerivedKeys`.
    private func ensureMasterKey() async throws {
        _ = try getAtRestKey()
    }

    private func getMasterKeySync() throws -> SymmetricKey {
        let keyData = try keychainManager.load(forKey: masterKeyIdentifier)
        return SymmetricKey(data: keyData)
    }

    /// The device-local at-rest key, seeded on first use and stable thereafter.
    /// - Existing install: adopt the current master-key BYTES so already-encrypted columns
    ///   stay decryptable with zero re-encryption (the two were identical before this change).
    /// - Brand-new install: generate a fresh random device-local key.
    /// Once set it is NEVER overwritten, so v2→v3 migration (which changes the derived/master
    /// key) leaves local data untouched.
    ///
    /// PERF: the key is cached in memory after the first Keychain load. Every encrypt/decrypt
    /// previously did a fresh SecItemCopyMatching (IPC to securityd) — at N entries that was
    /// N round-trips per bulk operation (search, Insights, vault backup, echo backfill). The
    /// key is stable by design (see above), so caching is safe; the cache is dropped whenever
    /// keys are reset/wiped.
    private var cachedAtRestKey: SymmetricKey?
    private let atRestKeyLock = NSLock()

    private func getAtRestKey() throws -> SymmetricKey {
        atRestKeyLock.lock()
        defer { atRestKeyLock.unlock() }

        if let cached = cachedAtRestKey {
            return cached
        }

        if let keyData = try? keychainManager.load(forKey: atRestKeyIdentifier) {
            let key = SymmetricKey(data: keyData)
            cachedAtRestKey = key
            return key
        }
        // Seed from the existing master key if present (existing user — same bytes, no
        // re-encryption); otherwise mint a fresh device-local key (new install).
        if let masterData = try? keychainManager.load(forKey: masterKeyIdentifier) {
            try keychainManager.save(masterData, forKey: atRestKeyIdentifier)
            let key = SymmetricKey(data: masterData)
            cachedAtRestKey = key
            return key
        }
        let fresh = SymmetricKey(size: .bits256)
        let freshData = fresh.withUnsafeBytes { Data($0) }
        try keychainManager.save(freshData, forKey: atRestKeyIdentifier)
        cachedAtRestKey = fresh
        return fresh
    }

    /// Get encryption key for vault operations
    public func getEncryptionKey() -> SymmetricKey? {
        return try? getMasterKeySync()
    }

    /// Check if encryption key exists (useful for onboarding flow)
    public var hasEncryptionKey: Bool {
        (try? getMasterKeySync()) != nil
    }

    /// Setup encryption with derived keys from recovery phrase (used during onboarding)
    /// - Parameters:
    ///   - keys: The derived keys from the recovery phrase
    ///   - recoveryPhrase: The full recovery phrase (stored separately for verification)
    ///   - userSalt: Per-user salt used for key derivation (stored in Keychain for future re-derivation)
    public func setupWithDerivedKeys(_ keys: KeyDerivation.DerivedKeys, recoveryPhrase: String, userSalt: Data? = nil) throws {
        // ORDERING SAFETY: seed the at-rest key from the CURRENT master key BEFORE we
        // overwrite the master key with a (possibly different, e.g. v3) derived key. This
        // guarantees existing at-rest columns stay decryptable — the at-rest key captures
        // the value the columns were encrypted with. No-op if already seeded.
        _ = try? getAtRestKey()

        // Store the derived encryption key as the master (blob/salt) key
        let keyData = keys.encryptionKey.withUnsafeBytes { Data($0) }
        try keychainManager.save(keyData, forKey: masterKeyIdentifier)

        // Store per-user salt if provided (for future re-derivation on restore)
        if let salt = userSalt, !salt.isEmpty {
            try storeUserSalt(salt)
        }

        // Store auth token for cloud backup API authentication
        UserPreferencesManager.shared.authToken = keys.authToken
        print("EncryptionManager: Auth token stored for cloud backup")

        isInitialized = true
    }

    // MARK: - User Salt Management

    /// Store per-user salt in Keychain
    public func storeUserSalt(_ salt: Data) throws {
        try keychainManager.save(salt, forKey: Constants.KeychainKeys.userSalt)
    }

    /// Load per-user salt from Keychain
    /// Returns nil if no salt is stored (existing users or new device without server sync)
    public func loadUserSalt() -> Data? {
        try? keychainManager.load(forKey: Constants.KeychainKeys.userSalt)
    }
    
    // MARK: - Encryption

    public func encryptForStorage(_ text: String) throws -> Data {
        try ensureInitialized()
        guard let data = text.data(using: .utf8) else {
            throw EncryptionError.invalidData
        }
        return try encryptData(data)
    }

    public func encryptData(_ data: Data) throws -> Data {
        try ensureInitialized()
        let key = try getAtRestKey()
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw EncryptionError.encryptionFailed
        }
        return combined
    }

    // MARK: - Decryption

    public func decryptFromStorage(_ data: Data) throws -> String {
        try ensureInitialized()
        let decryptedData = try decryptData(data)
        guard let text = String(data: decryptedData, encoding: .utf8) else {
            throw EncryptionError.invalidData
        }
        return text
    }

    public func decryptData(_ data: Data) throws -> Data {
        try ensureInitialized()
        let key = try getAtRestKey()
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    // MARK: - Key Reset

    public func resetMasterKey() throws {
        try keychainManager.delete(forKey: masterKeyIdentifier)
        isInitialized = false
        initializationTask = nil
        // At-rest key itself is untouched here, but drop the cache anyway —
        // a spurious re-load costs one Keychain read, a stale key costs data.
        atRestKeyLock.lock()
        cachedAtRestKey = nil
        atRestKeyLock.unlock()
    }

    /// Full account deletion: removes BOTH the master key and the device-local at-rest key.
    /// Used only by the explicit "Delete cloud backup & account" flow — after this, nothing
    /// on this device can decrypt any previously-stored data.
    public func wipeAllEncryptionKeys() {
        try? keychainManager.delete(forKey: masterKeyIdentifier)
        try? keychainManager.delete(forKey: atRestKeyIdentifier)
        isInitialized = false
        initializationTask = nil
        atRestKeyLock.lock()
        cachedAtRestKey = nil
        atRestKeyLock.unlock()
    }
}
