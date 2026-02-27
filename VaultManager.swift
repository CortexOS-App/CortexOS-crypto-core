import Foundation
import SwiftData

// ═══════════════════════════════════════════════════════════════════════════════
// VAULT MANAGER
//
// Zero-knowledge backup and restore to Cloudflare R2.
// Server NEVER sees unencrypted data.
// Matches Android's VaultManager.kt
// ═══════════════════════════════════════════════════════════════════════════════

public final class VaultManager {
    
    public static let shared = VaultManager()
    private init() {}
    
    // MARK: - Dependencies
    
    private let encryption = EncryptionManager.shared
    private let api = VaultAPI.shared
    
    // MARK: - Types
    
    public struct VaultData: Codable {
        let version: Int
        let exportedAt: TimeInterval
        let platform: String
        let entries: [EntryDTO]
        let insights: [InsightDTO]?
        
        static let currentVersion = 2
    }
    
    public struct InsightDTO: Codable {
        let id: String
        let type: String
        let title: String
        let message: String
        let createdAt: TimeInterval
    }
    
    public enum VaultError: Error, LocalizedError {
        case noEncryptionKey
        case serializationFailed
        case encryptionFailed
        case uploadFailed(Error)
        case downloadFailed(Error)
        case decryptionFailed
        case deserializationFailed
        case noBackupFound
        case versionMismatch(serverVersion: Int)
        
        public var errorDescription: String? {
            switch self {
            case .noEncryptionKey: return "No encryption key available"
            case .serializationFailed: return "Failed to serialize vault data"
            case .encryptionFailed: return "Failed to encrypt vault"
            case .uploadFailed(let e): return "Upload failed: \(e.localizedDescription)"
            case .downloadFailed(let e): return "Download failed: \(e.localizedDescription)"
            case .decryptionFailed: return "Failed to decrypt vault - wrong recovery phrase?"
            case .deserializationFailed: return "Failed to parse vault data"
            case .noBackupFound: return "No backup found for this account"
            case .versionMismatch(let v): return "Vault version \(v) not supported"
            }
        }
    }
    
    // MARK: - Backup
    
    /// Create encrypted backup and upload to cloud
    @MainActor
    public func backup(entries: [Entry], modelContext: ModelContext) async throws {
        guard let key = encryption.getEncryptionKey() else {
            throw VaultError.noEncryptionKey
        }
        
        // 1. Collect data
        let entryDTOs = entries.map { $0.toDTO() }
        
        let vaultData = VaultData(
            version: VaultData.currentVersion,
            exportedAt: Date().timeIntervalSince1970,
            platform: "ios",
            entries: entryDTOs,
            insights: nil // TODO: Add insights export
        )
        
        // 2. Serialize to JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys // Deterministic output
        guard let jsonData = try? encoder.encode(vaultData) else {
            throw VaultError.serializationFailed
        }
        
        // 3. Encrypt
        let encryptedData: Data
        do {
            encryptedData = try VaultEncryption.encrypt(data: jsonData, key: key)
        } catch {
            throw VaultError.encryptionFailed
        }
        
        // 4. Upload
        do {
            try await api.uploadVault(data: encryptedData)
            UserPreferencesManager.shared.lastSyncTimestamp = Date().timeIntervalSince1970
        } catch {
            throw VaultError.uploadFailed(error)
        }
    }
    
    // MARK: - Restore
    
    /// Download and decrypt backup, return entries to import
    public func restore() async throws -> [Entry] {
        guard let key = encryption.getEncryptionKey() else {
            throw VaultError.noEncryptionKey
        }
        
        // 1. Download
                let encryptedData: Data
                do {
                    encryptedData = try await api.downloadVault()
                } catch let error as VaultError {
                    throw error
                } catch {
                    throw VaultError.downloadFailed(error)
                }
        // 2. Decrypt
        let jsonData: Data
        do {
            jsonData = try VaultEncryption.decrypt(encryptedData: encryptedData, key: key)
        } catch {
            throw VaultError.decryptionFailed
        }
        
        // 3. Deserialize
        let decoder = JSONDecoder()
        guard let vaultData = try? decoder.decode(VaultData.self, from: jsonData) else {
            throw VaultError.deserializationFailed
        }
        
        // 4. Version check
        guard vaultData.version <= VaultData.currentVersion else {
            throw VaultError.versionMismatch(serverVersion: vaultData.version)
        }
        
        // 5. Convert DTOs to Entry objects
        return vaultData.entries.map { Entry.fromDTO($0) }
    }
    
    // MARK: - Check Backup Status
    
    public func hasBackup() async -> Bool {
        do {
            return try await api.checkVaultExists()
        } catch {
            return false
        }
    }
    
    public func getBackupInfo() async -> (exists: Bool, lastModified: Date?)? {
        do {
            return try await api.getVaultInfo()
        } catch {
            return nil
        }
    }
    
    // MARK: - Delete
    
    public func deleteBackup() async throws {
        try await api.deleteVault()
    }
}
