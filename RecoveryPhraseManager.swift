import Foundation
import CryptoKit
import Combine

// ═══════════════════════════════════════════════════════════════════════════════
// RECOVERY PHRASE MANAGER - CROSS-PLATFORM CRITICAL
//
// BIP39-compliant recovery phrase generation and validation.
// Format: 6 words + 4-digit PIN (e.g., "apple banana cherry dog elephant fox-1234")
//
// Security: 6 words = ~77 bits of entropy (2048^6 combinations)
//
// MUST match Android's RecoveryPhraseManager.kt exactly for:
// - Word list (same BIP39 2048 words)
// - Phrase format (6 words)
// - Hash generation for challenge verification
// - PIN hashing
//
// The same recovery phrase must produce identical derived keys on both platforms.
// ═══════════════════════════════════════════════════════════════════════════════

public final class RecoveryPhraseManager {

    // MARK: - Constants (MUST match Android)

    /// Word count for recovery phrase
    /// 6 words = 2048^6 = ~7.2 × 10^19 combinations
    /// Combined with 4-digit PIN (10,000) = ~7.2 × 10^23 combinations
    /// With Argon2id key derivation, brute-force is computationally infeasible
    public static let wordCount = 6

    /// PIN length (4 digits)
    private static let pinLength = 4
    
    // MARK: - Singleton
    
    public static let shared = RecoveryPhraseManager()
    
    // MARK: - Properties
    
    private var wordList: [String] = []
    private var wordSet: Set<String> = []
    private let userDefaults = UserDefaults.standard
    
    // MARK: - Types

    public struct RecoveryPhrase: Equatable {
        public let phrase: String   // "word1 word2 word3 word4 word5 word6"
        public let pin: String      // "1234"

        public var fullPhrase: String {
            "\(phrase)-\(pin)"
        }

        public var words: [String] {
            phrase.split(separator: " ").map(String.init)
        }

        /// Whether this phrase has the correct word count (6 words)
        public var isValid: Bool {
            words.count == RecoveryPhraseManager.wordCount
        }

        public init(phrase: String, pin: String) {
            self.phrase = phrase
            self.pin = pin
        }
    }

    public enum RecoveryPhraseError: Error, LocalizedError {
        case wordListNotLoaded
        case invalidWordCount
        case invalidPinLength
        case invalidWord(String)
        case phraseParseError

        public var errorDescription: String? {
            switch self {
            case .wordListNotLoaded:
                return "BIP39 word list not loaded"
            case .invalidWordCount:
                return "Phrase must contain exactly 6 words"
            case .invalidPinLength:
                return "PIN must be exactly 4 digits"
            case .invalidWord(let word):
                // Don't reveal which word is invalid - security
                return "Invalid word in recovery phrase"
            case .phraseParseError:
                return "Could not parse recovery phrase"
            }
        }
    }
    
    // MARK: - Initialization
    
    private init() {
        loadWordList()
    }
    
    // MARK: - Word List Management
    
    private func loadWordList() {
        // Try to load from bundle
        if let url = Bundle.main.url(forResource: "bip39_wordlist", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let wrapper = try? JSONDecoder().decode(WordListWrapper.self, from: data) {
            wordList = wrapper.words
            wordSet = Set(wrapper.words)
            print("RecoveryPhraseManager: Loaded \(wordList.count) BIP39 words")
            return
        }
        
        // Fallback: Load embedded word list
        wordList = Self.embeddedWordList
        wordSet = Set(Self.embeddedWordList)
        print("RecoveryPhraseManager: Using embedded word list (\(wordList.count) words)")
    }
    
    public var isWordListLoaded: Bool {
        !wordList.isEmpty
    }
    
    // MARK: - Phrase Generation
    
    /// Generate a new recovery phrase with 6 random words and 4-digit PIN
    public func generateRecoveryPhrase() throws -> RecoveryPhrase {
        guard !wordList.isEmpty else {
            throw RecoveryPhraseError.wordListNotLoaded
        }
        
        // Generate 6 random words
        var words: [String] = []
        for _ in 0..<Self.wordCount {
            let randomIndex = Int.random(in: 0..<wordList.count)
            words.append(wordList[randomIndex])
        }
        
        // Generate 4-digit PIN
        let pin = (0..<Self.pinLength)
            .map { _ in String(Int.random(in: 0...9)) }
            .joined()
        
        return RecoveryPhrase(
            phrase: words.joined(separator: " "),
            pin: pin
        )
    }
    
    // MARK: - Validation

    /// Check if a word is in the BIP39 word list
    public func isValidWord(_ word: String) -> Bool {
        wordSet.contains(word.lowercased().trimmingCharacters(in: .whitespaces))
    }

    /// Validate phrase format and words (6 words required)
    public func isValidPhrase(_ phrase: String, pin: String) -> Bool {
        let words = phrase
            .trimmingCharacters(in: .whitespaces)
            .split(separator: " ")
            .map(String.init)

        // Check word count - must be exactly 6 words
        guard words.count == Self.wordCount else {
            return false
        }

        // Check PIN format - must be exactly 4 digits
        guard pin.count == Self.pinLength,
              pin.allSatisfy({ $0.isNumber }) else { return false }

        // Check all words are valid BIP39 words
        return words.allSatisfy { isValidWord($0) }
    }

    /// Validate a complete phrase and throw descriptive errors (6 words required)
    public func validatePhrase(_ phrase: String, pin: String) throws {
        let words = phrase
            .trimmingCharacters(in: .whitespaces)
            .split(separator: " ")
            .map(String.init)

        // Must be exactly 6 words
        guard words.count == Self.wordCount else {
            throw RecoveryPhraseError.invalidWordCount
        }

        // PIN must be exactly 4 digits
        guard pin.count == Self.pinLength,
              pin.allSatisfy({ $0.isNumber }) else {
            throw RecoveryPhraseError.invalidPinLength
        }

        // All words must be valid BIP39 words
        for word in words {
            if !isValidWord(word) {
                throw RecoveryPhraseError.invalidWord(word)
            }
        }
    }
    
    // MARK: - Phrase Formatting
    
    /// Get full phrase string (words + PIN)
    /// Format: "word1 word2 word3 word4 word5 word6-1234"
    public func getFullPhrase(_ phrase: String, pin: String) -> String {
        "\(phrase)-\(pin)"
    }
    
    /// Parse full phrase into components
    public func parseFullPhrase(_ fullPhrase: String) -> RecoveryPhrase? {
        let parts = fullPhrase.split(separator: "-")
        guard parts.count == 2 else { return nil }
        
        let phrase = String(parts[0]).trimmingCharacters(in: .whitespaces)
        let pin = String(parts[1]).trimmingCharacters(in: .whitespaces)
        
        guard isValidPhrase(phrase, pin: pin) else { return nil }
        
        return RecoveryPhrase(phrase: phrase, pin: pin)
    }
    
    // MARK: - Word List Access
    
    /// Get all BIP39 words alphabetically sorted
    public func getAllWords() -> [String] {
        wordList.sorted()
    }
    
    /// Get shuffled word list for dropdown selection
    public func getShuffledWordList() -> [String] {
        wordList.shuffled()
    }
    
    // MARK: - Challenge System (2-Word + PIN Verification)

    /// Get 2 random positions for login challenge (positions 0-5)
    /// Returns sorted tuple to match Android behavior
    public func getRandomChallengePositions() -> (Int, Int) {
        let positions = Array(0..<Self.wordCount).shuffled().prefix(2).sorted()
        return (positions[0], positions[1])
    }

    /// Get the word count for stored phrases (always 6)
    public func getStoredPhraseWordCount() -> Int {
        return Self.wordCount
    }
    
    /// Get decoy words for challenge (wrong answers)
    public func getDecoyWords(count: Int = 2) -> [String] {
        guard !wordList.isEmpty else { return [] }
        
        var decoys: [String] = []
        while decoys.count < count {
            let randomWord = wordList.randomElement()!
            if !decoys.contains(randomWord) {
                decoys.append(randomWord)
            }
        }
        return decoys
    }
    
    // MARK: - Secure Hashing (MUST match Android exactly)
    
    /// Hash word at position for secure storage
    /// Format: SHA-256("position:word")
    /// CRITICAL: Must match Android's hashWordAtPosition() exactly
    public func hashWordAtPosition(_ word: String, position: Int) -> String {
        let input = "\(position):\(word.lowercased().trimmingCharacters(in: .whitespaces))"
        let inputData = Data(input.utf8)
        let hash = SHA256.hash(data: inputData)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate all 6 word hashes for storage
    public func generateAllWordHashes(_ phrase: String) -> [String] {
        let words = phrase
            .trimmingCharacters(in: .whitespaces)
            .split(separator: " ")
            .map(String.init)
        
        return words.enumerated().map { index, word in
            hashWordAtPosition(word, position: index)
        }
    }
    
    /// Verify word at position against stored hash
    public func verifyWordAtPosition(_ word: String, position: Int, storedHash: String) -> Bool {
        hashWordAtPosition(word, position: position) == storedHash
    }
    
    /// Hash PIN for secure storage
    /// Format without salt: SHA-256("cortexos:pin:1234") — backward compat for existing users
    /// Format with salt: SHA-256("cortexos:pin:1234:<base64-salt>") — new users with per-user salt
    /// CRITICAL: Without salt, must match Android's hashPin() exactly
    public func hashPin(_ pin: String, userSalt: Data? = nil) -> String {
        var input = "cortexos:pin:\(pin)"
        if let salt = userSalt, !salt.isEmpty {
            input += ":" + salt.base64EncodedString()
        }
        let inputData = Data(input.utf8)
        let hash = SHA256.hash(data: inputData)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - Storage (Keychain — secure)

    private let keychain = KeychainManager.shared

    /// Store PIN hash in Keychain
    /// - Parameters:
    ///   - pin: The 4-digit PIN
    ///   - userSalt: Per-user salt (nil for existing/legacy users)
    public func storePinHash(_ pin: String, userSalt: Data? = nil) {
        let hash = hashPin(pin, userSalt: userSalt)
        try? keychain.saveString(hash, forKey: Constants.KeychainKeys.pinHash)
        userDefaults.set(true, forKey: Constants.UserDefaultsKeys.pinEnabled)
        // Migrate: remove legacy UserDefaults entry if present
        userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.pinHash)
    }

    /// Verify PIN against stored hash (checks Keychain first, falls back to UserDefaults for migration)
    /// Automatically loads per-user salt from Keychain if available
    public func verifyPin(_ pin: String) -> Bool {
        // Load per-user salt if stored (new users), nil for legacy users
        let userSalt: Data? = try? keychain.load(forKey: Constants.KeychainKeys.userSalt)
        let computed = hashPin(pin, userSalt: userSalt)
        // Primary: Keychain
        if let storedHash = try? keychain.loadString(forKey: Constants.KeychainKeys.pinHash) {
            return computed == storedHash
        }
        // Migration fallback: read from UserDefaults, migrate to Keychain
        if let legacyHash = userDefaults.string(forKey: Constants.UserDefaultsKeys.pinHash) {
            try? keychain.saveString(legacyHash, forKey: Constants.KeychainKeys.pinHash)
            userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.pinHash)
            return computed == legacyHash
        }
        return false
    }

    /// Store word hashes for phrase challenge in Keychain
    public func storeWordHashesForChallenge(_ phrase: String) {
        let hashes = generateAllWordHashes(phrase)
        for (index, hash) in hashes.enumerated() {
            try? keychain.saveString(hash, forKey: Constants.KeychainKeys.phraseWordHash(index))
            // Migrate: remove legacy UserDefaults entry
            userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.phraseWordHash(index))
        }
    }

    /// Get stored word hash at position (Keychain primary, UserDefaults migration fallback)
    public func getPhraseWordHash(_ position: Int) -> String? {
        if let hash = try? keychain.loadString(forKey: Constants.KeychainKeys.phraseWordHash(position)) {
            return hash
        }
        // Migration fallback
        if let legacyHash = userDefaults.string(forKey: Constants.UserDefaultsKeys.phraseWordHash(position)) {
            try? keychain.saveString(legacyHash, forKey: Constants.KeychainKeys.phraseWordHash(position))
            userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.phraseWordHash(position))
            return legacyHash
        }
        return nil
    }
    
    /// Verify phrase challenge (2 words + PIN)
    public func verifyPhraseChallenge(
        wordIndex1: Int,
        word1: String,
        wordIndex2: Int,
        word2: String,
        pin: String
    ) -> Bool {
        // Verify PIN first
        guard verifyPin(pin) else {
            #if DEBUG
            print("RecoveryPhraseManager: PIN verification failed")
            #endif
            return false
        }

        // Get stored hashes
        guard let storedHash1 = getPhraseWordHash(wordIndex1),
              let storedHash2 = getPhraseWordHash(wordIndex2) else {
            #if DEBUG
            print("RecoveryPhraseManager: Stored hashes not found")
            #endif
            return false
        }

        // Verify both words
        let word1Valid = verifyWordAtPosition(word1, position: wordIndex1, storedHash: storedHash1)
        let word2Valid = verifyWordAtPosition(word2, position: wordIndex2, storedHash: storedHash2)

        #if DEBUG
        if !word1Valid {
            print("RecoveryPhraseManager: Word at position \(wordIndex1) verification failed")
        }
        if !word2Valid {
            print("RecoveryPhraseManager: Word at position \(wordIndex2) verification failed")
        }
        #endif
        
        return word1Valid && word2Valid
    }
    
    // MARK: - Clear Data

    public func clearStoredData() {
        // Clear from Keychain (primary)
        try? keychain.delete(forKey: Constants.KeychainKeys.pinHash)
        for i in 0..<Self.wordCount {
            try? keychain.delete(forKey: Constants.KeychainKeys.phraseWordHash(i))
        }
        // Clear legacy UserDefaults entries
        userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.pinHash)
        userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.pinEnabled)
        for i in 0..<Self.wordCount {
            userDefaults.removeObject(forKey: Constants.UserDefaultsKeys.phraseWordHash(i))
        }
    }

    // MARK: - Convenience Methods

    /// Store all hashes for phrase and PIN (for initial setup)
    public func storeRecoveryPhraseHashes(phrase: String, pin: String, userSalt: Data? = nil) {
        storeWordHashesForChallenge(phrase)
        storePinHash(pin, userSalt: userSalt)
    }

    /// Generate a phrase string (convenience for setup screen)
    public func generateRecoveryPhrase() -> String {
        guard let phrase = try? generateRecoveryPhrase() as RecoveryPhrase else {
            // Fallback with embedded words (6 words)
            let words = (0..<Self.wordCount).map { _ in Self.embeddedWordList.randomElement()! }
            return words.joined(separator: " ")
        }
        return phrase.phrase
    }
}

// MARK: - Word List Wrapper

private struct WordListWrapper: Decodable {
    let words: [String]
}

// MARK: - Embedded BIP39 Word List (First 100 for fallback - full list in JSON file)

extension RecoveryPhraseManager {
    
    // This is a subset for fallback. The full 2048-word list should be in bip39_wordlist.json
    static let embeddedWordList: [String] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
        "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
        "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
        "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
        "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
        "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
        "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
        "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
        "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
        // ... truncated for brevity - full list in JSON file
        "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
        "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best",
        "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind",
        "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket",
        "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue",
        "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
        "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
        "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave",
        "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
        "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble"
    ]
}

// MARK: - Cross-Platform Verification

#if DEBUG
extension RecoveryPhraseManager {
    
    /// Verify hashing matches Android implementation
    static func runCrossPlatformTests() {
        print("═══════════════════════════════════════════════════════════")
        print("RECOVERY PHRASE CROSS-PLATFORM TEST")
        print("═══════════════════════════════════════════════════════════")
        
        let manager = RecoveryPhraseManager.shared
        
        // Test word hash
        let testWord = "apple"
        let testPosition = 0
        let wordHash = manager.hashWordAtPosition(testWord, position: testPosition)
        print("Word: '\(testWord)' at position \(testPosition)")
        print("Hash: \(wordHash)")
        
        // Test PIN hash
        let testPin = "1234"
        let pinHash = manager.hashPin(testPin)
        print("\nPIN: '\(testPin)'")
        print("Hash: \(pinHash)")
        
        // Test full phrase hashes
        let testPhrase = "apple banana cherry dog elephant fox"
        let allHashes = manager.generateAllWordHashes(testPhrase)
        print("\nPhrase: '\(testPhrase)'")
        print("Hashes:")
        for (i, hash) in allHashes.enumerated() {
            print("  [\(i)]: \(hash)")
        }
        
        print("\n═══════════════════════════════════════════════════════════")
        print("Compare these values with Android's output.")
        print("All hashes must match EXACTLY for login to work cross-platform.")
        print("═══════════════════════════════════════════════════════════")
    }
}
#endif
