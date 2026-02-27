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
    private let masterKeyIdentifier = "com.cortexos.master_encryption_key"

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

        // Synchronous fallback - try to load existing key
        if let _ = try? getMasterKeySync() {
            isInitialized = true
            return
        }

        // If no key exists, we need async initialization
        throw EncryptionError.notInitialized
    }

    // MARK: - Key Management

    private func ensureMasterKey() async throws {
        if let _ = try? getMasterKeySync() { return }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try keychainManager.save(keyData, forKey: masterKeyIdentifier)
    }

    private func getMasterKeySync() throws -> SymmetricKey {
        let keyData = try keychainManager.load(forKey: masterKeyIdentifier)
        return SymmetricKey(data: keyData)
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
        // Store the derived encryption key as the master key
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
        let key = try getMasterKeySync()
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
        let key = try getMasterKeySync()
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    // MARK: - Key Reset

    public func resetMasterKey() throws {
        try keychainManager.delete(forKey: masterKeyIdentifier)
        isInitialized = false
        initializationTask = nil
    }
}
