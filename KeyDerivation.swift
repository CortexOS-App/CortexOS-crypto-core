import Foundation
import CryptoKit

// ═══════════════════════════════════════════════════════════════════════════════
// KEY DERIVATION - CROSS-PLATFORM CRITICAL (Argon2id)
//
// This implementation MUST produce identical output to Android's KeyDerivation.kt
// Android uses BouncyCastle's Argon2 which is based on the reference C implementation.
// iOS uses the reference C implementation directly (embedded in project).
//
// Android Implementation Reference:
// - Algorithm: Argon2id
// - Version: 1.3 (0x13)
// - Memory: 65,536 KB (64 MB)
// - Time Cost (iterations): 3
// - Parallelism: 4
// - Hash Length: 32 bytes (256 bits)
// - Salt: Raw UTF-8 bytes (NO hashing, variable length)
//
// VERIFICATION:
// Input: "apple banana cherry dog elephant fox-1234"
// Run on both iOS and Android - outputs must match exactly.
// ═══════════════════════════════════════════════════════════════════════════════

public final class KeyDerivation {

    // MARK: - Constants (MUST match Android EXACTLY)

    private static let argon2Memory: UInt32 = 65536         // 64 MB in KB
    private static let argon2TimeCost: UInt32 = 3           // iterations
    private static let argon2Parallelism: UInt32 = 4        // threads
    private static let hashLength: Int = 32                  // 256 bits

    // Lightweight Argon2 profile — used ONLY for the phrase-only lookupId (v3).
    // Cheaper because the lookupId is not a secret-bearing key, just a discovery index.
    private static let argon2LookupMemory: UInt32 = 16384   // 16 MB in KB
    private static let argon2LookupTimeCost: UInt32 = 1     // iterations

    // Salts - CRITICAL: These strings must be EXACTLY the same as Android
    // Android uses raw UTF-8 bytes directly: saltString.toByteArray(Charsets.UTF_8)
    // NO hashing, NO padding - just raw UTF-8 bytes
    private static let saltAccountId = "cortexos-account-id-v2-argon2id"         // 31 bytes UTF-8
    private static let saltEncryptionKey = "cortexos-encryption-key-v2-argon2id" // 35 bytes UTF-8
    private static let saltAuthToken = "cortexos-auth-token-v2-argon2id"         // 31 bytes UTF-8

    // v3 salt suffix strings — MUST match Android KeyDerivation.kt v3 constants byte-for-byte.
    // v3 mixes the per-user vault salt into ALL keys (account/enc/auth), stores the salt
    // ENCRYPTED on the server under saltKey, keyed by the phrase-only lookupId.
    // Verified byte-identical to Android + argon2-cffi reference (2026-07-02).
    private static let saltAccountIdV3     = "cortexos-account-id-v3"     // 22 bytes UTF-8
    private static let saltEncryptionKeyV3 = "cortexos-encryption-key-v3" // 26 bytes UTF-8
    private static let saltAuthTokenV3     = "cortexos-auth-token-v3"     // 22 bytes UTF-8
    private static let saltLookupId        = "cortexos-lookup-id-v3"      // 21 bytes UTF-8 (lightweight)
    private static let saltKeyForSalt      = "cortexos-salt-key-v3"       // 20 bytes UTF-8 (encrypts the salt)

    // MARK: - Types

    public struct DerivedKeys: Equatable {
        public let accountId: String        // 64-char hex string
        public let encryptionKey: SymmetricKey
        public let authToken: String        // 64-char hex string
    }

    public enum KeyDerivationError: Error, LocalizedError {
        case invalidPassword
        case invalidSalt
        case derivationFailed(message: String)
        case argon2Error(code: Int32)

        public var errorDescription: String? {
            switch self {
            case .invalidPassword:
                return "Password cannot be converted to UTF-8"
            case .invalidSalt:
                return "Salt cannot be converted to UTF-8"
            case .derivationFailed(let message):
                return "Argon2id derivation failed: \(message)"
            case .argon2Error(let code):
                return "Argon2id error code: \(code)"
            }
        }
    }

    // MARK: - Public API

    /// Generate a 32-byte cryptographically secure random salt for per-user key derivation
    public static func generateUserSalt() -> Data {
        return generateRandomBytes(count: 32)
    }

    /// Derive all keys from recovery phrase with per-user salt
    /// - Parameters:
    ///   - fullPhrase: Format "word1 word2 word3 word4 word5 word6-1234"
    ///   - userSalt: Per-user random salt (32 bytes). Empty Data falls back to static-only salts for backward compatibility.
    /// - Returns: DerivedKeys containing accountId, encryptionKey, and authToken
    public static func deriveAllKeys(from fullPhrase: String, userSalt: Data) throws -> DerivedKeys {
        let normalized = normalizePhrase(fullPhrase)

        // accountId: FIXED salt only (cross-platform server lookup identifier)
        let accountIdBytes = try argon2id(
            password: normalized,
            salt: saltAccountId
        )

        // encryptionKey: purpose prefix + per-user salt (domain separation + uniqueness)
        let encSalt = saltEncryptionKey.data(using: .utf8)! + userSalt
        let encryptionKeyBytes = try argon2id(
            password: normalized,
            saltData: encSalt
        )

        // authToken: purpose prefix + per-user salt (domain separation + uniqueness)
        let authSalt = saltAuthToken.data(using: .utf8)! + userSalt
        let authTokenBytes = try argon2id(
            password: normalized,
            saltData: authSalt
        )

        return DerivedKeys(
            accountId: accountIdBytes.hexString,
            encryptionKey: SymmetricKey(data: encryptionKeyBytes),
            authToken: authTokenBytes.hexString
        )
    }

    /// Derive all keys from recovery phrase (phrase + PIN combined)
    /// Backward-compatible wrapper — uses empty salt (equivalent to static salts only).
    /// - Parameter fullPhrase: Format "word1 word2 word3 word4 word5 word6-1234"
    /// - Returns: DerivedKeys containing accountId, encryptionKey, and authToken
    public static func deriveAllKeys(from fullPhrase: String) throws -> DerivedKeys {
        return try deriveAllKeys(from: fullPhrase, userSalt: Data())
    }

    // MARK: - v3 Derivation (true ZKE: salt-mixed keys + encrypted-salt transport)

    /// Derive all keys with the v3 scheme. The 32-byte per-user `userVaultSalt` is mixed
    /// into ALL three keys (account/enc/auth), so a stolen server DB is inert without the
    /// phrase — no precomputation across users. Salt composition is `userVaultSalt ‖ suffix`
    /// (userSalt FIRST), matching Android v3 exactly. Do NOT reorder — the byte order is
    /// part of the cross-platform contract (verified against Android + argon2-cffi).
    public static func deriveAllKeysV3(from fullPhrase: String, userVaultSalt: Data) throws -> DerivedKeys {
        guard userVaultSalt.count == 32 else {
            throw KeyDerivationError.invalidSalt
        }
        let normalized = normalizePhrase(fullPhrase)

        let accountSalt = userVaultSalt + saltAccountIdV3.data(using: .utf8)!
        let encSalt     = userVaultSalt + saltEncryptionKeyV3.data(using: .utf8)!
        let authSalt    = userVaultSalt + saltAuthTokenV3.data(using: .utf8)!

        let accountIdBytes     = try argon2id(password: normalized, saltData: accountSalt)
        let encryptionKeyBytes = try argon2id(password: normalized, saltData: encSalt)
        let authTokenBytes     = try argon2id(password: normalized, saltData: authSalt)

        return DerivedKeys(
            accountId: accountIdBytes.hexString,
            encryptionKey: SymmetricKey(data: encryptionKeyBytes),
            authToken: authTokenBytes.hexString
        )
    }

    /// lookupId — the phrase-only discovery index used to fetch the encrypted salt.
    /// Lightweight Argon2 (16MB/1/4), salt-independent, hex-encoded. Leaks nothing on its
    /// own: it only points at an AES-GCM ciphertext that needs the phrase-derived saltKey.
    public static func deriveLookupId(from fullPhrase: String) throws -> String {
        let normalized = normalizePhrase(fullPhrase)
        let bytes = try argon2idLightweight(password: normalized, saltData: saltLookupId.data(using: .utf8)!)
        return bytes.hexString
    }

    /// saltKey — the phrase-derived AES-256 key that encrypts the per-user vault salt at
    /// rest on the server. Standard Argon2 (64MB/3/4), salt-independent.
    public static func deriveSaltEncryptionKey(from fullPhrase: String) throws -> SymmetricKey {
        let normalized = normalizePhrase(fullPhrase)
        let bytes = try argon2id(password: normalized, saltData: saltKeyForSalt.data(using: .utf8)!)
        return SymmetricKey(data: bytes)
    }

    /// Generate a fresh 32-byte per-user vault salt (v3). Alias of `generateUserSalt`,
    /// named for the v3 vocabulary.
    public static func generateVaultSalt() -> Data {
        return generateRandomBytes(count: 32)
    }

    /// Derive only account ID (for login verification)
    public static func deriveAccountId(from fullPhrase: String) throws -> String {
        let normalized = normalizePhrase(fullPhrase)
        let bytes = try argon2id(password: normalized, salt: saltAccountId)
        return bytes.hexString
    }

    /// Derive only encryption key (for vault operations)
    public static func deriveEncryptionKey(from fullPhrase: String) throws -> SymmetricKey {
        let normalized = normalizePhrase(fullPhrase)
        let bytes = try argon2id(password: normalized, salt: saltEncryptionKey)
        return SymmetricKey(data: bytes)
    }

    /// Derive only auth token (for API authentication)
    public static func deriveAuthToken(from fullPhrase: String) throws -> String {
        let normalized = normalizePhrase(fullPhrase)
        let bytes = try argon2id(password: normalized, salt: saltAuthToken)
        return bytes.hexString
    }

    /// Convenience method - same as deriveAllKeys but returns nil on error.
    /// Callers MUST handle the nil case to avoid encrypting with a zero key.
    public static func deriveKeys(from fullPhrase: String) -> DerivedKeys? {
        do {
            return try deriveAllKeys(from: fullPhrase)
        } catch {
            print("KeyDerivation: Failed to derive keys - \(error)")
            return nil
        }
    }

    /// Generate cryptographically secure random bytes
    public static func generateRandomBytes(count: Int) -> Data {
        var bytes = Data(count: count)
        let result = bytes.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, count, pointer.baseAddress!)
        }

        guard result == errSecSuccess else {
            return Data((0..<count).map { _ in UInt8.random(in: 0...255) })
        }

        return bytes
    }

    // MARK: - Private Implementation

    /// Argon2id key derivation using embedded C reference implementation
    /// CRITICAL: Output must be byte-identical to Android's BouncyCastle implementation
    ///
    /// Android uses raw UTF-8 salt bytes directly:
    /// - SALT_ACCOUNT_ID = "cortexos-account-id-v2-argon2id".toByteArray(Charsets.UTF_8)
    /// - SALT_ENCRYPTION_KEY = "cortexos-encryption-key-v2-argon2id".toByteArray(Charsets.UTF_8)
    /// - SALT_AUTH_TOKEN = "cortexos-auth-token-v2-argon2id".toByteArray(Charsets.UTF_8)
    private static func argon2id(password: String, salt: String) throws -> Data {
        // Convert password to UTF-8 bytes
        guard let passwordData = password.data(using: .utf8) else {
            throw KeyDerivationError.invalidPassword
        }

        // Convert salt to raw UTF-8 bytes - NO hashing, NO padding
        // This matches Android's: saltString.toByteArray(Charsets.UTF_8)
        guard let saltData = salt.data(using: .utf8) else {
            throw KeyDerivationError.invalidSalt
        }

        // Prepare output buffer
        var hashOutput = Data(count: hashLength)

        // Call the C reference implementation
        let result = passwordData.withUnsafeBytes { passwordPtr in
            saltData.withUnsafeBytes { saltPtr in
                hashOutput.withUnsafeMutableBytes { hashPtr in
                    argon2id_hash_raw(
                        argon2TimeCost,                              // t_cost (iterations)
                        argon2Memory,                                // m_cost (memory in KB)
                        argon2Parallelism,                           // parallelism
                        passwordPtr.baseAddress,                     // password
                        passwordData.count,                          // password length
                        saltPtr.baseAddress,                         // salt (raw UTF-8 bytes)
                        saltData.count,                              // salt length (variable!)
                        hashPtr.baseAddress,                         // output hash
                        hashLength                                   // hash length
                    )
                }
            }
        }

        // Check for errors (ARGON2_OK = 0)
        guard result == 0 else {
            throw KeyDerivationError.argon2Error(code: result)
        }

        return hashOutput
    }

    /// Argon2id key derivation using raw Data salt
    /// Used for per-user salts where the salt is composed of a purpose prefix + random bytes
    private static func argon2id(password: String, saltData: Data) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw KeyDerivationError.invalidPassword
        }

        guard !saltData.isEmpty else {
            throw KeyDerivationError.invalidSalt
        }

        var hashOutput = Data(count: hashLength)

        let result = passwordData.withUnsafeBytes { passwordPtr in
            saltData.withUnsafeBytes { saltPtr in
                hashOutput.withUnsafeMutableBytes { hashPtr in
                    argon2id_hash_raw(
                        argon2TimeCost,
                        argon2Memory,
                        argon2Parallelism,
                        passwordPtr.baseAddress,
                        passwordData.count,
                        saltPtr.baseAddress,
                        saltData.count,
                        hashPtr.baseAddress,
                        hashLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw KeyDerivationError.argon2Error(code: result)
        }

        return hashOutput
    }

    /// Argon2id with the LIGHTWEIGHT profile (16MB/1/4) — lookupId only.
    /// Same reference C implementation as `argon2id`, only the cost params differ.
    private static func argon2idLightweight(password: String, saltData: Data) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw KeyDerivationError.invalidPassword
        }
        guard !saltData.isEmpty else {
            throw KeyDerivationError.invalidSalt
        }

        var hashOutput = Data(count: hashLength)

        let result = passwordData.withUnsafeBytes { passwordPtr in
            saltData.withUnsafeBytes { saltPtr in
                hashOutput.withUnsafeMutableBytes { hashPtr in
                    argon2id_hash_raw(
                        argon2LookupTimeCost,
                        argon2LookupMemory,
                        argon2Parallelism,
                        passwordPtr.baseAddress,
                        passwordData.count,
                        saltPtr.baseAddress,
                        saltData.count,
                        hashPtr.baseAddress,
                        hashLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw KeyDerivationError.argon2Error(code: result)
        }

        return hashOutput
    }

    /// Normalize phrase to match Android's normalizePhrase() exactly
    private static func normalizePhrase(_ phrase: String) -> String {
        phrase
            .lowercased()
            .trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "-+", with: "-", options: .regularExpression)
    }
}

// MARK: - Data Extension for Hex Conversion

extension Data {
    /// Convert to lowercase hex string (matches Android's "%02x".format())
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from hex string
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex

        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    var bytes: [UInt8] { Array(self) }
}

// MARK: - Salt Transport (v3 encrypted-salt-at-lookupId)

/// v3 zero-knowledge salt registration/fetch. The per-user vault salt is stored on the
/// server ENCRYPTED (AES-GCM under the phrase-derived saltKey), keyed by a `lookupId` that
/// is a different Argon2 output than `accountId`. The server holds only ciphertext it cannot
/// use. Mirrors Android's SaltManager. Wire format = the same combined `IV‖ct‖tag` base64
/// blob VaultEncryption already produces (verified byte-compatible with Android 2026-07-02).
public enum SaltManager {

    public enum SaltResult {
        case success(vaultSalt: Data)   // salt retrieved/created (32 bytes)
        case notFound                    // genuine 404 → legacy/v2 account
        case decryptionError             // salt existed but AES-GCM open failed → WRONG PHRASE
        case networkError(Error)         // transient; retry, NEVER downgrade to v2
    }

    /// Register a 32-byte vault salt for this phrase: encrypt it under saltKey and PUT it to
    /// /salt/{lookupId}. Used at onboarding and during v2→v3 migration.
    @discardableResult
    public static func registerSalt(vaultSalt: Data, fullPhrase: String) async -> SaltResult {
        do {
            let saltKey = try KeyDerivation.deriveSaltEncryptionKey(from: fullPhrase)
            let lookupId = try KeyDerivation.deriveLookupId(from: fullPhrase)
            let encrypted = try VaultEncryption.encrypt(data: vaultSalt, key: saltKey)
            try await VaultAPI.shared.uploadSalt(encrypted, accountId: lookupId)
            persistLookupId(lookupId)
            return .success(vaultSalt: vaultSalt)
        } catch {
            return .networkError(error)
        }
    }

    /// Fetch + decrypt the vault salt for this phrase. Distinguishes genuinely-absent
    /// (404 → v2), wrong-phrase (decrypt fail), and transient network errors — so the caller
    /// never derives keys with the wrong salt on a network blip.
    public static func fetchAndDecryptSalt(fullPhrase: String) async -> SaltResult {
        let lookupId: String
        let saltKey: SymmetricKey
        do {
            lookupId = try KeyDerivation.deriveLookupId(from: fullPhrase)
            saltKey = try KeyDerivation.deriveSaltEncryptionKey(from: fullPhrase)
        } catch {
            return .networkError(error)
        }

        let blob: Data?
        do {
            blob = try await VaultAPI.shared.downloadSalt(accountId: lookupId)
        } catch {
            return .networkError(error)   // network/5xx — retry, do not treat as "no salt"
        }

        guard let blob = blob, !blob.isEmpty else {
            return .notFound              // genuine 404 → legacy v2 account
        }

        do {
            let salt = try VaultEncryption.decrypt(encryptedData: blob, key: saltKey)
            guard salt.count == 32 else { return .decryptionError }
            persistLookupId(lookupId)
            return .success(vaultSalt: salt)
        } catch {
            return .decryptionError       // salt exists but won't open → wrong phrase
        }
    }

    /// Existence check for the schemaGen marker: an encrypted salt at /salt/{lookupId}
    /// means this is a v3 account (200 → v3, absent → v2).
    public static func saltExists(fullPhrase: String) async -> Bool {
        guard let lookupId = try? KeyDerivation.deriveLookupId(from: fullPhrase) else { return false }
        if let blob = ((try? await VaultAPI.shared.downloadSalt(accountId: lookupId)) ?? nil), !blob.isEmpty {
            return true
        }
        return false
    }

    // MARK: - Reliable salt registration (onboarding hole fix)
    //
    // ENCRYPTING the salt needs the phrase (available only at onboarding/restore); UPLOADING
    // it needs only the encrypted blob + lookupId. So we split the two: encrypt once with the
    // phrase, then upload with retry. If the upload fails (network blip at onboarding), we
    // stash (lookupId, blob) in the Keychain and re-upload on the next backup/launch — no
    // phrase required. This closes the "v3 account with no server salt, un-registerable
    // forever" hole where onboarding used to just proceed after 3 failed attempts.

    private static let pendingSaltLookupKey = "com.cortexos.pending_salt_lookup_id"
    private static let pendingSaltBlobKey   = "com.cortexos.pending_salt_blob"

    /// Encrypt the salt for this phrase → (lookupId, encrypted blob). Phrase required here.
    public static func prepareEncryptedSalt(vaultSalt: Data, fullPhrase: String) -> (lookupId: String, blob: Data)? {
        guard let saltKey = try? KeyDerivation.deriveSaltEncryptionKey(from: fullPhrase),
              let lookupId = try? KeyDerivation.deriveLookupId(from: fullPhrase),
              let blob = try? VaultEncryption.encrypt(data: vaultSalt, key: saltKey) else {
            return nil
        }
        return (lookupId, blob)
    }

    /// PUT an already-encrypted salt blob to /salt/{lookupId}. No phrase needed.
    @discardableResult
    public static func uploadPreparedSalt(lookupId: String, blob: Data) async -> Bool {
        do {
            try await VaultAPI.shared.uploadSalt(blob, accountId: lookupId)
            return true
        } catch {
            return false
        }
    }

    /// Register the salt at onboarding/migration. If the upload fails, the encrypted blob is
    /// stashed for automatic retry. Returns true when the salt is confirmed on the server,
    /// false when it was deferred (stashed).
    @discardableResult
    public static func registerSaltReliably(vaultSalt: Data, fullPhrase: String) async -> Bool {
        guard let prepared = prepareEncryptedSalt(vaultSalt: vaultSalt, fullPhrase: fullPhrase) else {
            return false
        }
        persistLookupId(prepared.lookupId)
        if await uploadPreparedSalt(lookupId: prepared.lookupId, blob: prepared.blob) {
            clearPendingSalt()
            return true
        }
        stashPendingSalt(lookupId: prepared.lookupId, blob: prepared.blob)
        return false
    }

    /// Retry a stashed salt upload. Called from backup (and safe to call at launch/foreground).
    /// No-op when nothing is pending. Clears the stash on success.
    public static func retryPendingSaltUpload() async {
        guard let pending = loadPendingSalt() else { return }
        if await uploadPreparedSalt(lookupId: pending.lookupId, blob: pending.blob) {
            clearPendingSalt()
        }
    }

    /// True when a salt upload is still pending (used by UI/telemetry if needed).
    public static var hasPendingSalt: Bool { loadPendingSalt() != nil }

    private static func stashPendingSalt(lookupId: String, blob: Data) {
        try? KeychainManager.shared.saveString(lookupId, forKey: pendingSaltLookupKey)
        try? KeychainManager.shared.save(blob, forKey: pendingSaltBlobKey)
    }
    private static func loadPendingSalt() -> (lookupId: String, blob: Data)? {
        guard let lookupId = try? KeychainManager.shared.loadString(forKey: pendingSaltLookupKey),
              let blob = try? KeychainManager.shared.load(forKey: pendingSaltBlobKey) else { return nil }
        return (lookupId, blob)
    }
    private static func clearPendingSalt() {
        try? KeychainManager.shared.delete(forKey: pendingSaltLookupKey)
        try? KeychainManager.shared.delete(forKey: pendingSaltBlobKey)
    }

    // MARK: - Persisted lookupId (for account-deletion salt cleanup)
    //
    // The lookupId is a non-secret Argon2 discovery hash that only points at an ENCRYPTED
    // salt blob. Persisting it lets full account deletion remove /salt/{lookupId} on the
    // server without needing the phrase (which is never stored) at delete time.

    public static func persistLookupId(_ lookupId: String) {
        UserDefaults.standard.set(lookupId, forKey: Constants.UserDefaultsKeys.saltLookupId)
    }
    public static func storedLookupId() -> String? {
        UserDefaults.standard.string(forKey: Constants.UserDefaultsKeys.saltLookupId)
    }
    /// Full-deletion cleanup: drop the persisted lookupId + any pending salt stash.
    public static func clearPersistedState() {
        UserDefaults.standard.removeObject(forKey: Constants.UserDefaultsKeys.saltLookupId)
        clearPendingSalt()
    }
}

// MARK: - Cross-Platform Verification Tests

#if DEBUG
extension KeyDerivation {

    /// v3 parity self-test against the LOCKED reference vectors (phrase
    /// "apple banana cherry dog elephant fox-1234" + userVaultSalt 0001…1e1f).
    /// These were verified byte-for-byte against Android BouncyCastle and the
    /// argon2-cffi reference on 2026-07-02. If this ever fails, the embedded
    /// Argon2 or a constant drifted — treat as a blocking cross-platform bug.
    @discardableResult
    static func runV3ParityTest() -> Bool {
        let phrase = "apple banana cherry dog elephant fox-1234"
        let salt = Data((0..<32).map { UInt8($0) })   // 000102…1e1f
        do {
            let keys = try deriveAllKeysV3(from: phrase, userVaultSalt: salt)
            let lookupId = try deriveLookupId(from: phrase)
            let saltKey = try deriveSaltEncryptionKey(from: phrase)
            let saltKeyHex = saltKey.withUnsafeBytes { Data(Array($0)).hexString }
            let encKeyHex = keys.encryptionKey.withUnsafeBytes { Data(Array($0)).hexString }

            let expected: [(String, String)] = [
                ("lookupId",      "e719eb7bbd2e2d82426d8cfde016628981147fd1784812db925dd2a397b007d8"),
                ("saltKey",       "a364e80f2d4c3936e087830baf91580df2ccb2f8ad6fb966099cc6b9a93c2ca0"),
                ("accountId",     "a82db13dcc2e770f03e7abc9d851c2cc16746640b3aa8b8bece047b6bd63e37c"),
                ("encryptionKey", "ef6b0ecdcb10cf984a838f99aa2d4d35e6ac5a168a3575697d60263830c7d03d"),
                ("authToken",     "4547d10a5398410c8f4b7c7c358bb7a363c8a054ae289d62c3fb3d2e54e92007"),
            ]
            let actual: [String: String] = [
                "lookupId": lookupId,
                "saltKey": saltKeyHex,
                "accountId": keys.accountId,
                "encryptionKey": encKeyHex,
                "authToken": keys.authToken,
            ]
            var ok = true
            print("═══════ v3 CROSS-PLATFORM PARITY TEST ═══════")
            for (name, exp) in expected {
                let got = actual[name] ?? "nil"
                let match = got == exp
                print("  \(name): \(match ? "✓" : "✗ MISMATCH")")
                if !match { print("    expected \(exp)\n    actual   \(got)"); ok = false }
            }
            print("  RESULT: \(ok ? "ALL MATCH ✓" : "FAILED ✗")")
            print("═════════════════════════════════════════════")
            return ok
        } catch {
            print("v3 parity test threw: \(error)")
            return false
        }
    }

    /// Verify cross-platform compatibility
    /// Run on both iOS and Android - outputs must match exactly
    static func runCrossPlatformTests() -> Bool {
        let testPhrase = "apple banana cherry dog elephant fox-1234"

        do {
            let keys = try deriveAllKeys(from: testPhrase)

            print("═══════════════════════════════════════════════════════════")
            print("CROSS-PLATFORM VERIFICATION (Argon2id)")
            print("═══════════════════════════════════════════════════════════")
            print("Test Phrase: \(testPhrase)")
            print("Account ID:  \(keys.accountId)")
            print("Auth Token:  \(keys.authToken)")
            print("Key Length:  \(keys.encryptionKey.bitCount) bits")
            print("═══════════════════════════════════════════════════════════")
            print("Compare with Android output - must match EXACTLY")
            print("═══════════════════════════════════════════════════════════")

            return true
        } catch {
            print("Cross-platform test failed: \(error)")
            return false
        }
    }
}
#endif
