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
        /// 1.3.0: 365-day pattern history. Optional for backward-compat with
        /// v2 backups (no snapshots field present → restored as empty array).
        let patternSnapshots: [PatternSnapshotDTO]?

        static let currentVersion = 3
    }

    public struct InsightDTO: Codable {
        let id: String
        let type: String
        let title: String
        let message: String
        let createdAt: TimeInterval
    }

    /// Serialization form for `PatternSnapshot` (SwiftData @Model → Codable DTO).
    /// Matches Android's PatternSnapshotDTO field-for-field so a single vault
    /// blob round-trips cross-platform.
    public struct PatternSnapshotDTO: Codable {
        let id: String                 // UUID.uuidString
        let snapshotDate: TimeInterval
        let patternName: String
        let patternType: String
        let confidence: Float
        let detectionSource: String
        let occurrenceCount: Int
        let windowSizeDays: Int
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

    /// Create encrypted backup and upload to cloud.
    /// `entries` and `patternSnapshots` must be fetched from a ModelContext
    /// before calling this. Snapshots default to empty for legacy call sites;
    /// pass the full 365-day history so cross-device restore preserves trend
    /// continuity (1.3.0+).
    public func backup(entries: [Entry], patternSnapshots: [PatternSnapshot] = []) async throws {
        guard let key = encryption.getEncryptionKey() else {
            throw VaultError.noEncryptionKey
        }

        // 1. Collect data
        let entryDTOs = entries.map { $0.toDTO() }
        let snapshotDTOs: [PatternSnapshotDTO]? = patternSnapshots.isEmpty ? nil : patternSnapshots.map {
            PatternSnapshotDTO(
                id: $0.id.uuidString,
                snapshotDate: $0.snapshotDate.timeIntervalSince1970,
                patternName: $0.patternName,
                patternType: $0.patternType,
                confidence: $0.confidence,
                detectionSource: $0.detectionSource,
                occurrenceCount: $0.occurrenceCount,
                windowSizeDays: $0.windowSizeDays
            )
        }

        let vaultData = VaultData(
            version: VaultData.currentVersion,
            exportedAt: Date().timeIntervalSince1970,
            platform: "ios",
            entries: entryDTOs,
            insights: nil, // TODO: Add insights export
            patternSnapshots: snapshotDTOs
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

        // 5. Upload per-user salt for cross-device restore
        if let userSalt = encryption.loadUserSalt(),
           let accountId = UserDefaults.standard.string(forKey: Constants.UserDefaultsKeys.accountId) {
            try? await api.uploadSalt(userSalt, accountId: accountId)
        }
    }
    
    // MARK: - Restore
    
    /// Download and decrypt backup, return entries + pattern snapshots to import.
    /// 1.3.0+: tuple return. Snapshots array is empty when restoring a v2
    /// backup (pre-1.3.0). Caller is responsible for inserting both into
    /// SwiftData via ModelContext.
    public func restoreAll() async throws -> (entries: [Entry], snapshots: [PatternSnapshot]) {
        let (entriesOut, snapsOut) = try await _downloadAndDecode()
        return (entriesOut, snapsOut)
    }

    /// Legacy single-type restore. Kept for back-compat; prefer `restoreAll()`.
    public func restore() async throws -> [Entry] {
        let (entriesOut, _) = try await _downloadAndDecode()
        return entriesOut
    }

    private func _downloadAndDecode() async throws -> ([Entry], [PatternSnapshot]) {
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
        let entries = vaultData.entries.map { Entry.fromDTO($0) }

        // 6. Convert pattern snapshot DTOs (nil for v2 backups).
        let snapshots: [PatternSnapshot] = (vaultData.patternSnapshots ?? []).compactMap { dto in
            guard let uuid = UUID(uuidString: dto.id) else { return nil }
            return PatternSnapshot(
                id: uuid,
                snapshotDate: Date(timeIntervalSince1970: dto.snapshotDate),
                patternName: dto.patternName,
                patternType: dto.patternType,
                confidence: dto.confidence,
                detectionSource: dto.detectionSource,
                occurrenceCount: dto.occurrenceCount,
                windowSizeDays: dto.windowSizeDays
            )
        }
        return (entries, snapshots)
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
