import CommonCrypto
import CryptoKit
import Foundation
import Security
import Sodium

struct PasswordVault: Codable, Equatable {
    var secret: String
    var slots: [VaultSecretSlot]? = nil
}

struct VaultSecretSlot: Codable, Equatable, Identifiable {
    var title: String
    var secret: String
    var id: UUID = UUID()
}

struct TagcryptVaultEntry: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var passphrase: String
    var nickname: String
    var destination: String
    var fidoKeyNames: [String]
    // Optional to preserve decoding of existing Vault files. This is already-encrypted tag/QR data.
    var encryptedPayload: Data? = nil
    var createdAt: Date = Date()
    var updatedAt: Date = Date()
}

/// Device-only encrypted recovery index. The AES key never leaves this device;
/// encrypted exports are independent files and must be protected by a recovery passphrase.
enum TagcryptVaultStore {
    private static let service = "com.fishandmedia.tagcrypt"
    private static let account = "encrypted-recovery-vault-key-v1"
    private static let filename = "tagcrypt-recovery-vault-v1.bin"

    static func load() throws -> [TagcryptVaultEntry] {
        let url = try fileURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let encrypted = try Data(contentsOf: url)
        let box = try AES.GCM.SealedBox(combined: encrypted)
        let key = try getOrCreateKey()
        var clear = try AES.GCM.open(box, using: key, authenticating: Data("TagcryptRecoveryVault1".utf8))
        defer { clear.resetBytes(in: 0..<clear.count) }
        return try JSONDecoder().decode([TagcryptVaultEntry].self, from: clear)
    }

    static func save(_ entries: [TagcryptVaultEntry]) throws {
        let key = try getOrCreateKey()
        var clear = try JSONEncoder().encode(entries)
        defer { clear.resetBytes(in: 0..<clear.count) }
        let box = try AES.GCM.seal(clear, using: key, authenticating: Data("TagcryptRecoveryVault1".utf8))
        guard let encrypted = box.combined else { throw VaultError.malformedRecord }
        let url = try fileURL()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encrypted.write(to: url, options: [.atomic, .completeFileProtection])
    }

    static func upsert(passphrase: String, nickname: String, destination: String, fidoKeyNames: [String], encryptedPayload: Data? = nil) throws -> [TagcryptVaultEntry] {
        var entries = try load()
        let cleanName = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        if let index = entries.firstIndex(where: { $0.passphrase == passphrase && $0.nickname == cleanName }) {
            entries[index].destination = destination
            entries[index].fidoKeyNames = fidoKeyNames
            if let encryptedPayload { entries[index].encryptedPayload = encryptedPayload }
            entries[index].updatedAt = Date()
        } else {
            entries.insert(TagcryptVaultEntry(passphrase: passphrase, nickname: cleanName.isEmpty ? "Saved recovery phrase" : cleanName,
                                              destination: destination, fidoKeyNames: fidoKeyNames,
                                              encryptedPayload: encryptedPayload), at: 0)
        }
        try save(entries)
        return entries
    }

    static func delete(_ entry: TagcryptVaultEntry) throws -> [TagcryptVaultEntry] {
        let entries = try load().filter { $0.id != entry.id }
        try save(entries)
        return entries
    }

    static func delete(ids: Set<UUID>) throws -> [TagcryptVaultEntry] {
        let entries = try load().filter { !ids.contains($0.id) }
        try save(entries)
        return entries
    }

    static func rename(_ entry: TagcryptVaultEntry, to nickname: String) throws -> [TagcryptVaultEntry] {
        var entries = try load()
        guard let index = entries.firstIndex(where: { $0.id == entry.id }) else { throw VaultError.malformedRecord }
        let cleanName = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else { throw VaultError.emptyVaultLabel }
        entries[index].nickname = cleanName
        entries[index].updatedAt = Date()
        try save(entries)
        return entries
    }

    private static func fileURL() throws -> URL {
        try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent(filename)
    }

    private static func getOrCreateKey() throws -> SymmetricKey {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound else { throw VaultError.passphrasePersistenceFailed(status) }
        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard randomStatus == errSecSuccess else { throw VaultError.randomGenerationFailed(randomStatus) }
        var item = query
        item.removeValue(forKey: kSecReturnData as String)
        item.removeValue(forKey: kSecMatchLimit as String)
        item[kSecValueData as String] = bytes
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw VaultError.passphrasePersistenceFailed(addStatus) }
        return SymmetricKey(data: bytes)
    }
}

enum VaultError: LocalizedError {
    case randomGenerationFailed(OSStatus)
    case malformedRecord
    case unsupportedVersion
    case recordTooLarge
    case emptyPassphrase
    case emptySecret
    case emptyVaultLabel
    case passphraseTooShort
    case passphrasePersistenceFailed(OSStatus)
    case derivationFailed(Int32)
    case decryptionFailed

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed(let status):
            return "The system random generator failed (status \(status)). No encrypted record was created."
        case .malformedRecord:
            return "This tag does not contain a valid Tagcrypt record."
        case .unsupportedVersion:
            return "This Tagcrypt record uses a version this app does not support."
        case .recordTooLarge:
            return "This secret is too large for Tagcrypt's padded record format. Use a shorter secret or encrypt separate records."
        case .emptyPassphrase:
            return "Enter the vault passphrase used when this tag was encrypted."
        case .emptySecret:
            return "Enter a secret before encrypting."
        case .emptyVaultLabel:
            return "Enter a name for this saved Vault entry."
        case .passphraseTooShort:
            return "This passphrase is below Tagcrypt's minimum strength for a new record. Choose a longer or more varied phrase, or generate a random phrase."
        case .passphrasePersistenceFailed(let status):
            return "The generated passphrase could not be saved securely in this iPhone's Keychain (status \(status)). Copy it to a separate recovery location before continuing."
        case .derivationFailed(let status):
            return "The encryption key could not be derived (status \(status))."
        case .decryptionFailed:
            return "The passphrase is incorrect, or the encrypted record was changed or damaged."
        }
    }
}

/// Stores only generated passphrases on this device. This Keychain item is
/// available while the device is unlocked and is excluded from device migration.
enum VaultPassphraseStore {
    // Preserve the pre-rename service label. The bundle-ID change may still change
    // the default access group, so test migration before removing the old app.
    private static let service = "com.fishandmedia.tagvault"
    private static let account = "generated-vault-passphrase-v1"

    static func load() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let passphrase = String(data: data, encoding: .utf8) else {
            throw VaultError.passphrasePersistenceFailed(status)
        }
        return passphrase
    }

    static func save(_ passphrase: String) throws {
        var data = Data(passphrase.utf8)
        defer { data.resetBytes(in: 0..<data.count) }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let updates: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
        guard updateStatus != errSecItemNotFound else {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw VaultError.passphrasePersistenceFailed(addStatus) }
            return
        }
        guard updateStatus == errSecSuccess else { throw VaultError.passphrasePersistenceFailed(updateStatus) }
    }

    static func clear() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.passphrasePersistenceFailed(status)
        }
    }
}

struct ArchivedVaultPassphrase: Codable, Identifiable, Equatable {
    var id: UUID
    var createdAt: Date
    var passphrase: String
    // Optional for compatibility with archives written before labels existed.
    var label: String? = nil
}

/// Keeps prior generated phrases separately from the active phrase so rotating
/// the default cannot silently make older records inaccessible. Device-only Keychain.
enum VaultPassphraseArchive {
    private static let service = "com.fishandmedia.tagvault"
    private static let account = "generated-vault-passphrase-archive-v1"

    static func load() throws -> [ArchivedVaultPassphrase] {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = result as? Data,
              let entries = try? JSONDecoder().decode([ArchivedVaultPassphrase].self, from: data) else {
            throw VaultError.passphrasePersistenceFailed(status)
        }
        return entries.sorted { $0.createdAt > $1.createdAt }
    }

    static func archive(_ passphrase: String, label: String? = nil) throws -> [ArchivedVaultPassphrase] {
        var entries = try load()
        guard !entries.contains(where: { $0.passphrase == passphrase }) else { return entries }
        entries.insert(ArchivedVaultPassphrase(id: UUID(), createdAt: Date(), passphrase: passphrase,
                                               label: label?.trimmingCharacters(in: .whitespacesAndNewlines)), at: 0)
        try save(entries)
        return entries
    }

    static func delete(_ entry: ArchivedVaultPassphrase) throws -> [ArchivedVaultPassphrase] {
        let entries = try load().filter { $0.id != entry.id }
        try save(entries)
        return entries
    }

    static func delete(ids: Set<UUID>) throws -> [ArchivedVaultPassphrase] {
        let entries = try load().filter { !ids.contains($0.id) }
        try save(entries)
        return entries
    }

    private static func save(_ entries: [ArchivedVaultPassphrase]) throws {
        var data = try JSONEncoder().encode(entries)
        defer { data.resetBytes(in: 0..<data.count) }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw VaultError.passphrasePersistenceFailed(addStatus) }
        } else if status != errSecSuccess {
            throw VaultError.passphrasePersistenceFailed(status)
        }
    }
}

/// TVLT v2 stores one freeform secret. TVLT v3 stores multiple named slots in one
/// encrypted container. Both portable versions use per-record salts and PBKDF2.
enum VaultCrypto {
    private static let portableMagicV2 = Data([0x54, 0x56, 0x4c, 0x54, 0x02]) // TVLT + v2
    private static let portableMagicV3 = Data([0x54, 0x56, 0x4c, 0x54, 0x03]) // TVLT + v3 slot container
    private static let portableMagicV4 = Data([0x54, 0x56, 0x4c, 0x54, 0x04]) // TVLT + v4 envelope with recovery slots
    private static let portableMagicV5 = Data([0x54, 0x56, 0x4c, 0x54, 0x05]) // TVLT + v5 multi-key envelope
    private static let portableMagicV6 = Data([0x54, 0x56, 0x4c, 0x54, 0x06]) // TVLT + v6 explicit unlock policy
    // A non-semantic binary discriminator keeps the legacy plaintext TVLT header
    // out of new records. The format marker is authenticated as AAD.
    private static let portableMarkerV7 = Data([0xa7, 0x9d, 0x42, 0xf1])
    private static let portableMarkerV7FIDO = Data([0x5a, 0xd3, 0x7e, 0x91])
    private static let v7SaltLength = 16
    private static let v7ArgonOps = Sodium().pwHash.OpsLimitInteractive
    private static let v7ArgonMemory = Sodium().pwHash.MemLimitInteractive
    private static let v7PlaintextBuckets = [32, 64, 128, 256, 384, 512, 640, 768]
    private static let v7MaximumPlaintextBytes = 2_048
    private static let v7InnerMarker = Data("TC7\0".utf8)
    private static let kdfIdentifier: UInt8 = 1 // PBKDF2-HMAC-SHA256
    private static let saltLength = 16
    private static let keyLength = 32
    private static let iterations: UInt32 = 600_000
    private static let minimumPassphraseLength = 16
    private static let portableHeaderLength = 5 + 1 + MemoryLayout<UInt32>.size + saltLength
    private static let chachaPolyOverhead = 12 + 16

    /// Generates 24 uniformly selected characters from a 64-character alphabet (144 random bits).
    static func generatePassphrase() throws -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        var output = [Character]()
        output.reserveCapacity(24)
        while output.count < 24 {
            var random = [UInt8](repeating: 0, count: 32)
            let status = SecRandomCopyBytes(kSecRandomDefault, random.count, &random)
            guard status == errSecSuccess else { throw VaultError.randomGenerationFailed(status) }
            for byte in random where byte < 192 {
                output.append(alphabet[Int(byte % 64)])
                if output.count == 24 { break }
            }
            random.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        }
        return String(output)
    }

    /// Binary envelope is Base64 encoded by the NFC writer and stored as NDEF Text.
    /// Layout: magic(5) || KDF-ID(1) || rounds(4, big-endian) || salt(16) ||
    /// ChaChaPoly.combined(nonce || ciphertext || tag).
    static func seal(_ secret: String, passphrase: String) throws -> Data {
        try seal(PasswordVault(secret: secret), passphrase: passphrase)
    }

    static func seal(_ vault: PasswordVault, passphrase: String, padRecord: Bool = true, targetRecordLength: Int? = nil) throws -> Data {
        guard !vault.secret.isEmpty || !(vault.slots?.isEmpty ?? true) else { throw VaultError.emptySecret }
        let normalizedPassphrase = canonicalPassphrase(passphrase)
        guard !normalizedPassphrase.isEmpty else { throw VaultError.emptyPassphrase }
        guard normalizedPassphrase.utf8.count >= minimumPassphraseLength,
              TagcryptPassphraseAssessment.evaluate(normalizedPassphrase).meetsMinimum else {
            throw VaultError.passphraseTooShort
        }

        let json = try encodeVault(vault)
        let prefixLength = v7InnerMarker.count + 1 + 4
        let minimumPlaintextLength = prefixLength + json.count
        guard minimumPlaintextLength <= v7MaximumPlaintextBytes else { throw VaultError.recordTooLarge }
        let paddedLength: Int
        if !padRecord {
            paddedLength = minimumPlaintextLength
        } else if let targetRecordLength {
            // A target record size is supplied only for NFC. Fill its usable NDEF
            // capacity after accounting for the fixed v7 envelope and NDEF headers.
            paddedLength = targetRecordLength - portableMarkerV7.count - v7SaltLength - chachaPolyOverhead
        } else {
            guard let bucket = v7PlaintextBuckets.first(where: { $0 >= minimumPlaintextLength }) else { throw VaultError.recordTooLarge }
            paddedLength = bucket
        }
        guard paddedLength >= minimumPlaintextLength, paddedLength <= v7MaximumPlaintextBytes else { throw VaultError.recordTooLarge }
        let paddingCount = paddedLength - minimumPlaintextLength
        let padding = paddingCount > 0 ? try randomData(count: paddingCount) : Data()
        var plaintext = v7InnerMarker + Data([padRecord ? 1 : 0]) + uint32(UInt32(json.count)) + json + padding
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }

        let salt = try randomData(count: v7SaltLength)
        var keyData = try deriveArgon2idKey(passphrase: normalizedPassphrase, salt: salt)
        defer { keyData.resetBytes(in: 0..<keyData.count) }
        let header = portableMarkerV7 + salt
        let sealedBox = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: keyData), authenticating: header)
        return header + sealedBox.combined
    }

    /// Returns the exact Base64 character count before salt/key generation.
    /// JSON length is calculated with the same encoder used by `seal`.
    static func estimatedBase64TextLength(secret: String) throws -> Int {
        try estimatedBase64TextLength(vault: PasswordVault(secret: secret))
    }

    static func estimatedBase64TextLength(vault: PasswordVault, padded: Bool = true) throws -> Int {
        let envelopeLength = try estimatedRecordByteLength(vault: vault, padded: padded)
        return ((envelopeLength + 2) / 3) * 4
    }

    static func estimatedRecordByteLength(vault: PasswordVault, padded: Bool = true, targetRecordLength: Int? = nil) throws -> Int {
        let jsonLength = try encodeVault(vault).count
        let prefixLength = v7InnerMarker.count + 1 + 4
        let minimumPlaintextLength = prefixLength + jsonLength
        guard minimumPlaintextLength <= v7MaximumPlaintextBytes else { throw VaultError.recordTooLarge }
        let paddedLength: Int
        if !padded {
            paddedLength = minimumPlaintextLength
        } else if let targetRecordLength {
            paddedLength = targetRecordLength - portableMarkerV7.count - v7SaltLength - chachaPolyOverhead
        } else {
            paddedLength = v7PlaintextBuckets.first(where: { $0 >= minimumPlaintextLength }) ?? 0
        }
        guard paddedLength >= minimumPlaintextLength, paddedLength <= v7MaximumPlaintextBytes else { throw VaultError.recordTooLarge }
        return portableMarkerV7.count + v7SaltLength + paddedLength + chachaPolyOverhead
    }

    static func requiresPassphrase(for record: Data) -> Bool {
        record.starts(with: portableMarkerV7) ||
            (record.starts(with: portableMarkerV7FIDO) && ((try? FIDOEnvelopeCrypto.unlockMode(in: record)) == .passphraseAndFIDO)) ||
            record.starts(with: portableMagicV2) || record.starts(with: portableMagicV3) || record.starts(with: portableMagicV4) || record.starts(with: portableMagicV5)
            || (record.starts(with: portableMagicV6) && ((try? FIDOEnvelopeCrypto.unlockMode(in: record)) == .passphraseAndFIDO))
    }

    static func requiresFIDOKey(for record: Data) -> Bool { record.starts(with: portableMarkerV7FIDO) || record.starts(with: portableMagicV4) || record.starts(with: portableMagicV5) || record.starts(with: portableMagicV6) }

    static func isTagcryptRecord(_ record: Data) -> Bool {
        record.starts(with: portableMarkerV7) ||
        record.starts(with: portableMarkerV7FIDO) ||
        record.starts(with: portableMagicV2) || record.starts(with: portableMagicV3) || record.starts(with: portableMagicV4) || record.starts(with: portableMagicV5) || record.starts(with: portableMagicV6)
    }

    static func isV7Record(_ record: Data) -> Bool { record.starts(with: portableMarkerV7) || record.starts(with: portableMarkerV7FIDO) }

    static func open(_ inputRecord: Data, passphrase: String) throws -> PasswordVault {
        // NFC parsers may hand us a Data slice with a non-zero startIndex. Copy to
        // a zero-based buffer before using integer offsets on untrusted bytes.
        let record = Data(inputRecord)
        if record.starts(with: portableMarkerV7FIDO) {
            return try FIDOEnvelopeCrypto.openWithPassphrase(record, passphrase: passphrase)
        }
        if record.starts(with: portableMarkerV7) {
            let headerLength = portableMarkerV7.count + v7SaltLength
            guard record.count > headerLength + 12 + 16 else { throw VaultError.malformedRecord }
            let header = Data(record[..<headerLength])
            let salt = Data(record[portableMarkerV7.count..<headerLength])
            let normalized = canonicalPassphrase(passphrase)
            guard !normalized.isEmpty else { throw VaultError.emptyPassphrase }
            var keyData = try deriveArgon2idKey(passphrase: normalized, salt: salt)
            defer { keyData.resetBytes(in: 0..<keyData.count) }
            do {
                let box = try ChaChaPoly.SealedBox(combined: Data(record[headerLength...]))
                var plaintext = try ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: header)
                defer { plaintext.resetBytes(in: 0..<plaintext.count) }
                guard plaintext.count >= 9, plaintext.starts(with: v7InnerMarker), plaintext[4] <= 1 else { throw VaultError.malformedRecord }
                let padded = plaintext[4] == 1
                let jsonLength = Int(readUInt32(plaintext, at: v7InnerMarker.count + 1))
                let jsonStart = v7InnerMarker.count + 5
                guard jsonLength > 0, jsonStart + jsonLength <= plaintext.count,
                      padded ? plaintext.count <= v7MaximumPlaintextBytes : jsonStart + jsonLength == plaintext.count else { throw VaultError.malformedRecord }
                return try JSONDecoder().decode(PasswordVault.self, from: Data(plaintext[jsonStart..<(jsonStart + jsonLength)]))
            } catch let error as VaultError {
                throw error
            } catch {
                throw VaultError.decryptionFailed
            }
        }
        if record.starts(with: portableMagicV4) || record.starts(with: portableMagicV5) || record.starts(with: portableMagicV6) {
            return try FIDOEnvelopeCrypto.openWithPassphrase(record, passphrase: passphrase)
        }
        if record.starts(with: portableMagicV2) || record.starts(with: portableMagicV3) {
            guard !passphrase.isEmpty else { throw VaultError.emptyPassphrase }
            let formatMagic = record.starts(with: portableMagicV3) ? portableMagicV3 : portableMagicV2
            let kdfOffset = formatMagic.count
            let roundsStart = kdfOffset + 1
            let saltStart = roundsStart + MemoryLayout<UInt32>.size
            let saltEnd = saltStart + saltLength
            guard record.count > saltEnd + 12 + 16,
                  record[kdfOffset] == kdfIdentifier else { throw VaultError.malformedRecord }

            let roundsData = Data(record[roundsStart..<saltStart])
            let recordIterations = roundsData.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            // Bound work from untrusted NFC input; v2 currently defines exactly 600,000 rounds.
            guard recordIterations == iterations else { throw VaultError.unsupportedVersion }

            let salt = Data(record[saltStart..<saltEnd])
            let combined = Data(record[saltEnd...])
            let header = Data(record[..<saltEnd])
            let normalizedPassphrase = canonicalPassphrase(passphrase)
            do {
                return try openPortable(header: header, combined: combined, salt: salt, passphrase: normalizedPassphrase)
            } catch {
                // Earlier v2 records used the exact entered UTF-8 bytes. Retry those
                // bytes only when canonicalisation changed the input.
                guard normalizedPassphrase != passphrase else { throw VaultError.decryptionFailed }
                do {
                    return try openPortable(header: header, combined: combined, salt: salt, passphrase: passphrase)
                } catch {
                    throw VaultError.decryptionFailed
                }
            }
        }

        if record.starts(with: Data([0x54, 0x56, 0x4c, 0x54])) { throw VaultError.unsupportedVersion }
        throw VaultError.malformedRecord
    }

    private static func openPortable(header: Data, combined: Data, salt: Data, passphrase: String) throws -> PasswordVault {
        var keyData = try deriveKey(passphrase: passphrase, salt: salt)
        defer { keyData.resetBytes(in: 0..<keyData.count) }
        let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
        let json = try ChaChaPoly.open(sealedBox, using: SymmetricKey(data: keyData), authenticating: header)
        let vault = try JSONDecoder().decode(PasswordVault.self, from: json)
        return vault
    }

    private static func canonicalPassphrase(_ passphrase: String) -> String {
        passphrase.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
    }

    private static func deriveKey(passphrase: String, salt: Data) throws -> Data {
        var password = Data(passphrase.utf8)
        defer { password.resetBytes(in: 0..<password.count) }
        let derivedLength = keyLength
        var derived = Data(count: derivedLength)
        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                derived.withUnsafeMutableBytes { derivedBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress,
                        password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBytes.bindMemory(to: UInt8.self).baseAddress,
                        derivedLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw VaultError.derivationFailed(status) }
        return derived
    }

    private static func deriveArgon2idKey(passphrase: String, salt: Data) throws -> Data {
        guard salt.count == Sodium().pwHash.SaltBytes else { throw VaultError.malformedRecord }
        var password = Array(passphrase.utf8)
        defer { password.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        guard let derived = Sodium().pwHash.hash(outputLength: keyLength, passwd: password,
                                                  salt: Array(salt), opsLimit: v7ArgonOps,
                                                  memLimit: v7ArgonMemory, alg: .Argon2ID13) else {
            throw VaultError.derivationFailed(-1)
        }
        return Data(derived)
    }

    private static func uint32(_ value: UInt32) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<UInt32>.size)
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        data[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private static func encodeVault(_ vault: PasswordVault) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(vault)
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw VaultError.randomGenerationFailed(status) }
        return data
    }

}
