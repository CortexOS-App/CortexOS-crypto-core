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

    // Salts - CRITICAL: These strings must be EXACTLY the same as Android
    // Android uses raw UTF-8 bytes directly: saltString.toByteArray(Charsets.UTF_8)
    // NO hashing, NO padding - just raw UTF-8 bytes
    private static let saltAccountId = "cortexos-account-id-v2-argon2id"         // 31 bytes UTF-8
    private static let saltEncryptionKey = "cortexos-encryption-key-v2-argon2id" // 35 bytes UTF-8
    private static let saltAuthToken = "cortexos-auth-token-v2-argon2id"         // 31 bytes UTF-8

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

// MARK: - Cross-Platform Verification Tests

#if DEBUG
extension KeyDerivation {
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
