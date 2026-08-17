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

    // MARK: - v5 Converged Interchange Blob (cross-platform, plaintext-in-blob)
    //
    // The v5 schema is a SUPERSET both platforms read (accept version >= 4, ignore unknown
    // fields). Field NAMES are the contract and MUST match Android's Kotlin property names
    // byte-for-byte (Swift Codable uses property names as JSON keys; nil optionals are
    // omitted, matching Gson serializeNulls=off). Timestamps are epoch MILLISECONDS.
    // Entry `content` is PLAINTEXT inside the (AES-GCM-encrypted) blob. iOS packs its rich
    // per-entry analysis into `analysisJson` (opaque to Android, lossless for iOS↔iOS).

    public struct EntryDataV5: Codable {
        let uid: String?             // canonical stable id (uuid string). Optional so iOS can
                                     // still restore an Android blob written before Android
                                     // adds `uid` (Android v4 keys entries by Long `id`); a
                                     // fresh uuid is synthesized on import when absent.
        let content: String          // PLAINTEXT entry body
        let createdAt: Int64         // epoch ms
        let updatedAt: Int64         // epoch ms
        let sentiment: String?
        let sentimentConfidence: Float?
        let analysisJson: String?    // iOS: JSON of AIAnalysisBundle; Android: its own analysis
        let wordCount: Int
        let isFavorite: Bool
        let hasReminder: Bool
        let reminderCreatedAt: Int64?
        let kind: String?            // "full" | "pulse"; nil -> "full"
    }

    public struct ChapterDataV5: Codable {
        let id: String
        let name: String?
        let status: String
        let startDate: Int64         // ms
        let endDate: Int64           // ms
        let entryIds: String?        // comma-joined uuid strings
        let entryCount: Int
        let aggregatedEmotions: String?
        let dominantEmotion: String?
        let aggregatedThemes: String?
        let moodTrajectory: String?
        let averageSentiment: Float?
        let totalWords: Int
        let journalingDays: Int
        let summaryPlain: String?    // decrypted chapter summary; re-encrypted on import
        let healthSummary: String?
        let createdAt: Int64         // ms
        let finalizedAt: Int64?      // ms
        let updatedAt: Int64         // ms
        let isYearEndChapter: Bool
        let celebrationShown: Bool
        let isAIGenerated: Bool
    }

    public struct ReflectionDataV5: Codable {
        let id: String
        let userId: String
        let startedAt: Int64         // ms
        let endedAt: Int64?          // ms
        let messagesPlain: String?   // decrypted messages JSON; re-encrypted on import
        let theme: String?
        let dominantEmotion: String?
        let sentimentShift: String?
        let emotionsDetected: String?
        let patterns: String?
        let keyInsights: String?
        let wasHelpful: Bool?
        let savedAsEntryId: String?
        let relatedTopicIds: String?
        let messageCount: Int
        let summary: String?
        let comprehensiveAnalysis: String?
        let isAIGenerated: Bool
    }

    public struct VaultDataV5: Codable {
        let version: Int             // 5
        let platform: String         // "ios"
        let exportedAt: Int64        // epoch ms
        let entries: [EntryDataV5]
        // Cross-platform record types (mapped into native models on both sides).
        let chapters: [ChapterDataV5]?
        let reflections: [ReflectionDataV5]?
        let psycheProfileJson: String?
        // iOS-owned; Android ignores (kept so an iOS↔iOS round-trip is lossless).
        let insights: [InsightDTO]?
        let patternSnapshots: [PatternSnapshotDTO]?

        static let currentVersion = 5
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
        case clobberBlocked
        case backupVerificationFailed
        case phraseMismatch

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
            case .clobberBlocked: return "Upload blocked: local data is empty but a cloud backup exists. Restore first."
            case .backupVerificationFailed: return "Upload paused: couldn't verify the cloud backup. Will retry."
            case .phraseMismatch: return "That recovery phrase does not match this account."
            }
        }
    }
    
    // MARK: - Backup

    /// Create encrypted backup and upload to cloud.
    /// `entries` and `patternSnapshots` must be fetched from a ModelContext
    /// before calling this. Snapshots default to empty for legacy call sites;
    /// pass the full 365-day history so cross-device restore preserves trend
    /// continuity (1.3.0+).
    public func backup(entries: [Entry],
                       chapters: [Chapter] = [],
                       reflections: [ReflectionSession] = [],
                       patternSnapshots: [PatternSnapshot] = []) async throws {
        guard encryption.getEncryptionKey() != nil else {
            throw VaultError.noEncryptionKey
        }

        // 0. CLOBBER GUARD (data-integrity critical, mirrors Android VaultManager).
        //    Never overwrite a populated server vault with an empty local one. If local
        //    has zero entries, the device most likely failed to restore — uploading now
        //    would destroy the real, still-encrypted vault sitting in the cloud.
        //    - server state unknown (check threw) -> abort, do not upload (retry later)
        //    - server HAS a vault              -> refuse, force restore-first
        //    - server empty                    -> safe to proceed
        if entries.isEmpty {
            let serverHasVault: Bool
            do {
                serverHasVault = try await api.checkVaultExists()
            } catch {
                throw VaultError.backupVerificationFailed
            }
            if serverHasVault {
                throw VaultError.clobberBlocked
            }
        }

        // 1-3. Build the encrypted v5 blob (plaintext-in-blob so a restore on any device can
        //      re-key locally regardless of at-rest-key divergence). Carries entries + mapped
        //      chapters + reflections + pattern history + the psyche profile (iOS↔iOS carry).
        let encryptedData = try buildV5Blob(
            entries: entries,
            chapters: chapters,
            reflections: reflections,
            patternSnapshots: patternSnapshots,
            psycheProfileJson: PsycheProfileManager.shared.exportProfileJSON()
        )

        // 4. Upload
        do {
            try await api.uploadVault(data: encryptedData)
            UserPreferencesManager.shared.lastSyncTimestamp = Date().timeIntervalSince1970
        } catch {
            throw VaultError.uploadFailed(error)
        }

        // 5. Salt handling.
        //    - v3 accounts: retry any salt upload that was deferred at onboarding (the encrypted
        //      blob was stashed; re-uploading needs no phrase). This closes the onboarding hole
        //      where a network blip left a v3 account with no server salt.
        await SaltManager.retryPendingSaltUpload()
        //    - v2 (legacy) accounts: keep the RAW salt at /salt/{accountId} so the v2 restore
        //      fallback can still reconstruct keys until the user migrates to v3.
        //    - v3 accounts: the ENCRYPTED salt lives at /salt/{lookupId}, registered at
        //      onboarding/migration with the phrase. NEVER upload the raw v3 salt (that would
        //      defeat the zero-knowledge property).
        if !UserPreferencesManager.shared.isV3Account,
           let userSalt = encryption.loadUserSalt(),
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

    /// Download + decode the vault into full iOS models. Tries the v5 converged blob first
    /// (the format all backups write going forward); falls back to the legacy v3 blob,
    /// re-keying entry content from the derived key onto THIS device's at-rest key so display
    /// works after the Phase 3 key split. Caller inserts the returned models into SwiftData.
    public func restoreAllV5() async throws -> RestoredVault {
        let encryptedData: Data
        do {
            encryptedData = try await api.downloadVault()
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.downloadFailed(error)
        }

        #if DEBUG
        print("VaultRestore: downloaded blob \(encryptedData.count) bytes")
        #endif

        // v5 (plaintext-in-blob) — common path.
        do {
            let v5 = try parseV5Blob(encryptedData)
            #if DEBUG
            print("VaultRestore: parsed as v5 — \(v5.entries.count) entries, \(v5.chapters.count) chapters, \(v5.reflections.count) reflections")
            #endif
            return v5
        } catch {
            #if DEBUG
            print("VaultRestore: v5 parse did not apply (\(error)) — trying legacy v3 blob")
            #endif
        }

        // Legacy v3 blob — decode + re-key entry content.
        let legacy = try decodeLegacyV3Blob(encryptedData)
        #if DEBUG
        print("VaultRestore: parsed as legacy v3 — \(legacy.entries.count) entries")
        #endif
        return legacy
    }

    private func decodeLegacyV3Blob(_ encryptedData: Data) throws -> RestoredVault {
        guard let key = encryption.getEncryptionKey() else { throw VaultError.noEncryptionKey }

        let jsonData: Data
        do {
            jsonData = try VaultEncryption.decrypt(encryptedData: encryptedData, key: key)
        } catch {
            throw VaultError.decryptionFailed
        }

        guard let vaultData = try? JSONDecoder().decode(VaultData.self, from: jsonData) else {
            throw VaultError.deserializationFailed
        }
        guard vaultData.version <= VaultData.currentVersion else {
            throw VaultError.versionMismatch(serverVersion: vaultData.version)
        }

        var reKeyFailures = 0
        let entries: [Entry] = vaultData.entries.map { dto in
            let entry = Entry.fromDTO(dto)
            // The derived key decrypted the outer blob AND was the source device's at-rest
            // key, so it decrypts the entry body too. Re-encrypt under THIS device's at-rest
            // key. No-op when they're identical (same-device restore).
            if let ct = Data(base64Encoded: entry.encryptedContent),
               let plain = try? VaultEncryption.decrypt(encryptedData: ct, key: key),
               let text = String(data: plain, encoding: .utf8),
               let reEnc = try? encryption.encryptForStorage(text) {
                entry.encryptedContent = reEnc.base64EncodedString()
            } else {
                // Entry body did not decrypt under the derived key (foreign at-rest key or
                // corrupt ciphertext). Keep the original bytes and count it: the caller uses
                // this to refuse the v3 stamp so the account never half-migrates.
                reKeyFailures += 1
            }
            return entry
        }

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

        return RestoredVault(entries: entries, chapters: [], reflections: [], patternSnapshots: snapshots, psycheProfileJson: nil, reKeyFailures: reKeyFailures)
    }

    /// Upgrade a freshly-restored v2 (legacy) account to v3 in place: register the ENCRYPTED
    /// salt at /salt/{lookupId}, switch the local account keys/id/version to v3, and re-upload
    /// the vault as v5 under the NEW v3 accountId. The old v2 salt + vault objects are LEFT in
    /// place (retention window) so an un-migrated device can still restore. Requires the phrase
    /// (available only at restore/onboarding). Throws if the salt can't be registered — we do
    /// NOT half-migrate.
    public func migrateV2toV3(fullPhrase: String,
                              existingSalt: Data,
                              entries: [Entry],
                              chapters: [Chapter] = [],
                              reflections: [ReflectionSession] = [],
                              patternSnapshots: [PatternSnapshot] = []) async throws {
        // Reuse the existing 32-byte salt as the v3 vault salt when possible; else fresh.
        let vaultSalt: Data = existingSalt.count == 32 ? existingSalt : KeyDerivation.generateVaultSalt()

        // 1. Register the encrypted salt at /salt/{lookupId}. Abort the whole migration if this
        //    fails — a v3 account with no server salt would be un-restorable.
        let saltResult = await SaltManager.registerSalt(vaultSalt: vaultSalt, fullPhrase: fullPhrase)
        guard case .success = saltResult else {
            throw VaultError.uploadFailed(NSError(domain: "CortexOS.SaltRegister", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Could not register encrypted salt"]))
        }

        // 2. Derive v3 keys and switch the local account over (at-rest key is untouched, so
        //    local entries stay valid; only the blob/salt key + accountId change).
        let keys = try KeyDerivation.deriveAllKeysV3(from: fullPhrase, userVaultSalt: vaultSalt)
        try encryption.setupWithDerivedKeys(keys, recoveryPhrase: fullPhrase, userSalt: vaultSalt)
        UserPreferencesManager.shared.accountId = keys.accountId
        UserPreferencesManager.shared.keyDerivationVersion = 3

        // 3. Re-upload as v5 under the new v3 accountId (getEncryptionKey/authToken/accountId
        //    are now v3). The old v2 objects are untouched.
        let blob = try buildV5Blob(entries: entries, chapters: chapters, reflections: reflections, patternSnapshots: patternSnapshots)
        try await api.uploadVault(data: blob)
    }

    /// USER-INITIATED in-place v2→v3 upgrade (the opt-in Settings path for existing-device
    /// users who would otherwise never migrate, since login is a 2-word challenge and the
    /// phrase is only available at onboarding/restore). Validates the entered phrase against
    /// the stored v2 accountId FIRST — so a wrong phrase can never corrupt the account — then
    /// migrates using the existing local vault salt. The phrase is used in memory only and is
    /// never persisted.
    public func migrateInPlace(fullPhrase: String,
                               entries: [Entry],
                               chapters: [Chapter] = [],
                               reflections: [ReflectionSession] = [],
                               patternSnapshots: [PatternSnapshot] = []) async throws {
        // Already v3 — nothing to do.
        if UserPreferencesManager.shared.isV3Account { return }

        // Validate: the phrase-only v2 accountId derived from the entered phrase must match
        // the account stored on this device.
        let v2 = try KeyDerivation.deriveAllKeys(from: fullPhrase, userSalt: Data())
        guard let stored = UserDefaults.standard.string(forKey: Constants.UserDefaultsKeys.accountId),
              stored == v2.accountId else {
            throw VaultError.phraseMismatch
        }

        // Reuse the existing local vault salt (32 bytes) so identity stays stable.
        let existingSalt = encryption.loadUserSalt() ?? Data()
        try await migrateV2toV3(
            fullPhrase: fullPhrase,
            existingSalt: existingSalt,
            entries: entries,
            chapters: chapters,
            reflections: reflections,
            patternSnapshots: patternSnapshots
        )
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

    // MARK: - v5 Converged Blob (build + parse)

    /// Everything a v5 restore reconstructs. Entries are the portable core; chapters and
    /// reflections are mapped into native iOS models; psyche regenerates but is carried.
    public struct RestoredVault {
        public let entries: [Entry]
        public let chapters: [Chapter]
        public let reflections: [ReflectionSession]
        public let patternSnapshots: [PatternSnapshot]
        public let psycheProfileJson: String?
        /// Legacy-blob restores only: number of entries whose content could NOT be re-keyed
        /// onto this device's at-rest key. Non-zero means the restore is not fully readable
        /// locally, so callers must NOT proceed with the v2→v3 migration (stamping v3 would
        /// hide the "Upgrade encryption" path and freeze a half-migrated account).
        public var reKeyFailures: Int = 0
    }

    /// Build an encrypted v5 interchange blob from portable data. Caller fetches the models
    /// from a ModelContext. Returns AES-GCM-encrypted bytes ready for `api.uploadVault`.
    public func buildV5Blob(entries: [Entry],
                            chapters: [Chapter] = [],
                            reflections: [ReflectionSession] = [],
                            patternSnapshots: [PatternSnapshot] = [],
                            psycheProfileJson: String? = nil) throws -> Data {
        guard let key = encryption.getEncryptionKey() else { throw VaultError.noEncryptionKey }

        let entryDTOs = entries.map { $0.toEntryDataV5() }
        let chapterDTOs = chapters.isEmpty ? nil : chapters.map { $0.toChapterDataV5() }
        let reflectionDTOs = reflections.isEmpty ? nil : reflections.map { $0.toReflectionDataV5() }
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

        let exportedMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
        let vault = VaultDataV5(
            version: VaultDataV5.currentVersion,
            platform: "ios",
            exportedAt: exportedMs,
            entries: entryDTOs,
            chapters: chapterDTOs,
            reflections: reflectionDTOs,
            psycheProfileJson: psycheProfileJson,
            insights: nil,
            patternSnapshots: snapshotDTOs
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let jsonData = try? encoder.encode(vault) else { throw VaultError.serializationFailed }
        do {
            return try VaultEncryption.encrypt(data: jsonData, key: key)
        } catch {
            throw VaultError.encryptionFailed
        }
    }

    /// Decrypt + decode a converged blob (version >= 4) into iOS models. Unknown top-level
    /// fields are ignored (JSONDecoder default). Chapters are numbered by sorted startDate so
    /// the iOS narrative order is stable. Throws `.deserializationFailed` on an older-shape
    /// (v3) blob so the caller can fall back to the legacy `_downloadAndDecode` path.
    public func parseV5Blob(_ encryptedData: Data) throws -> RestoredVault {
        guard let key = encryption.getEncryptionKey() else { throw VaultError.noEncryptionKey }

        let jsonData: Data
        do {
            jsonData = try VaultEncryption.decrypt(encryptedData: encryptedData, key: key)
        } catch {
            throw VaultError.decryptionFailed
        }

        let decoder = JSONDecoder()
        guard let vault = try? decoder.decode(VaultDataV5.self, from: jsonData) else {
            throw VaultError.deserializationFailed
        }
        guard vault.version >= 4 else {
            throw VaultError.versionMismatch(serverVersion: vault.version)
        }

        #if DEBUG
        print("VaultRestore: v5 blob decoded — version \(vault.version), \(vault.entries.count) raw entries in blob")
        #endif

        let entries = vault.entries.map { Entry.fromEntryDataV5($0) }

        let sortedChapters = (vault.chapters ?? []).sorted { $0.startDate < $1.startDate }
        let chapters = sortedChapters.enumerated().map { idx, dto in
            Chapter.fromChapterDataV5(dto, chapterNumber: idx + 1)
        }

        let reflections = (vault.reflections ?? []).map { ReflectionSession.fromReflectionDataV5($0) }

        let snapshots: [PatternSnapshot] = (vault.patternSnapshots ?? []).compactMap { dto in
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

        return RestoredVault(
            entries: entries,
            chapters: chapters,
            reflections: reflections,
            patternSnapshots: snapshots,
            psycheProfileJson: vault.psycheProfileJson
        )
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

    /// Full account deletion — local side. Wipes every credential, key, and account marker
    /// on this device, but DELIBERATELY preserves the device-level trial anti-abuse tokens
    /// (hasStartedTrial / trialStartDate / hasSeenTrialEndedCard) so delete + reinstall can't
    /// farm a fresh free trial. Does NOT delete SwiftData rows — the caller does that with
    /// its own ModelContext. Call AFTER the server-side delete (which still needs the auth
    /// token this wipes). Idempotent and non-throwing.
    @MainActor
    public func wipeLocalCredentials() {
        // Encryption keys (master + device-local at-rest)
        EncryptionManager.shared.wipeAllEncryptionKeys()
        // Account credentials in Keychain (keeps trial tokens)
        KeychainManager.shared.wipeAccountCredentials()
        // PIN + phrase word hashes (Keychain + legacy UserDefaults)
        RecoveryPhraseManager.shared.clearStoredData()
        // Pending-salt stash + persisted lookupId
        SaltManager.clearPersistedState()
        // Encrypted Psyche profile
        UserDefaults.standard.removeObject(forKey: "psyche_profile_encrypted")
        // Account markers
        let prefs = UserPreferencesManager.shared
        prefs.authToken = nil          // also deletes the Keychain auth token
        prefs.accountId = nil
        prefs.subscriptionTier = Constants.Tier.freemium
        UserDefaults.standard.removeObject(forKey: Constants.UserDefaultsKeys.keyDerivationVersion)
        prefs.hasCompletedOnboarding = false
    }
}
