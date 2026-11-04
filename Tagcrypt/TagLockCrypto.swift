import CryptoKit
import Foundation
import Security

struct TagLockCredentials: Equatable {
    let password: Data
    let pack: Data
}

enum TagLockCryptoError: Error, Equatable {
    case invalidMasterKeyLength
    case invalidUIDLength
}

enum TagLockMode: String, CaseIterable {
    case off = "Off"
    case auto = "Auto"
    case organisation = "Organisation"
}

struct TagLockCredentialCandidate: Equatable {
    enum Source: Equatable { case auto, organisation(label: String) }
    let source: Source
    let masterKey: Data
}

enum TagLockCredentialResolver {
    static func candidates(mode: TagLockMode, autoKey: Data?,
                           organisationKeys: [TagLockOrganisationKey]) -> [TagLockCredentialCandidate] {
        guard mode != .off else { return [] }
        var result = [TagLockCredentialCandidate]()
        if let autoKey, autoKey.count == 32 {
            result.append(TagLockCredentialCandidate(source: .auto, masterKey: autoKey))
        }
        guard mode == .organisation else { return result }
        result += organisationKeys
            .filter { $0.key.count == 32 && !$0.label.isEmpty }
            .sorted { ($0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending) }
            .map { TagLockCredentialCandidate(source: .organisation(label: $0.label), masterKey: $0.key) }
        return result
    }

    /// Every key on this device, Auto first. Used to unlock tags that already
    /// have a password (rewrite with mode Off, password removal); never used to
    /// provision a new password.
    static func allKnownCandidates(autoKey: Data?, organisationKeys: [TagLockOrganisationKey]) -> [TagLockCredentialCandidate] {
        var result = [TagLockCredentialCandidate]()
        if let autoKey, autoKey.count == 32 {
            result.append(TagLockCredentialCandidate(source: .auto, masterKey: autoKey))
        }
        result += organisationKeys
            .filter { $0.key.count == 32 && !$0.label.isEmpty }
            .sorted { ($0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending) }
            .map { TagLockCredentialCandidate(source: .organisation(label: $0.label), masterKey: $0.key) }
        return result
    }

    /// New tags use the key family explicitly selected in Settings. Candidate
    /// order remains Auto-first when authenticating existing tags.
    static func provisioningCandidate(mode: TagLockMode,
                                      candidates: [TagLockCredentialCandidate]) -> TagLockCredentialCandidate? {
        switch mode {
        case .off: nil
        case .auto: candidates.first { $0.source == .auto }
        case .organisation: candidates.first { if case .organisation = $0.source { return true }; return false }
        }
    }
}

/// Deterministic per-tag NTAG21x credentials. No derived credential is persisted
/// or written to a tag; only the master key is kept by TagLockKeyStore.
enum TagLockCrypto {
    private static let domain = Data("tagcrypt-ntag-pwd-v1".utf8)

    static func credentials(masterKey: Data, uid: Data) throws -> TagLockCredentials {
        guard masterKey.count == 32 else { throw TagLockCryptoError.invalidMasterKeyLength }
        guard uid.count == 7 else { throw TagLockCryptoError.invalidUIDLength }
        let digest = HMAC<SHA256>.authenticationCode(for: domain + uid, using: SymmetricKey(data: masterKey))
        let bytes = Data(digest)
        return TagLockCredentials(password: bytes.prefix(4), pack: bytes.dropFirst(4).prefix(2))
    }
}

struct TagLockOrganisationKey: Codable, Equatable, Identifiable {
    var id: UUID
    var label: String
    var key: Data

    init(id: UUID = UUID(), label: String, key: Data) {
        self.id = id
        self.label = label.trimmingCharacters(in: .whitespacesAndNewlines)
        self.key = key
    }
}

struct TagLockKeyBundle: Codable, Equatable {
    var version = 1
    var autoKey: Data?
    var organisationKeys: [TagLockOrganisationKey]
}

enum TagLockKeyStoreError: Error {
    case invalidKey
    case keychainStatus(OSStatus)
    case malformedKeys
    case conflictingAutoKey
}

/// Device-only key storage. The Auto master key is deliberately excluded from
/// iCloud Keychain; portability is provided only by the encrypted Vault export.
enum TagLockKeyStore {
    private static let autoAccount = "ntag-auto-master-v1"
    private static let organisationAccount = "ntag-organisation-keys-v1"
    private static let service = "com.tagcrypt.tag-lock"

    static func loadAutoKey() throws -> Data? { try read(account: autoAccount) }

    static func createAutoKey() throws -> Data {
        if let existing = try loadAutoKey() { return existing }
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw TagLockKeyStoreError.keychainStatus(status) }
        try write(bytes, account: autoAccount)
        return bytes
    }

    static func loadOrganisationKeys() throws -> [TagLockOrganisationKey] {
        guard let data = try read(account: organisationAccount) else { return [] }
        let keys = try JSONDecoder().decode([TagLockOrganisationKey].self, from: data)
        guard keys.allSatisfy({ $0.key.count == 32 && !$0.label.isEmpty }) else {
            throw TagLockKeyStoreError.malformedKeys
        }
        return keys
    }

    static func saveOrganisationKeys(_ keys: [TagLockOrganisationKey]) throws {
        guard keys.allSatisfy({ $0.key.count == 32 && !$0.label.isEmpty }) else {
            throw TagLockKeyStoreError.invalidKey
        }
        try write(try JSONEncoder().encode(keys), account: organisationAccount)
    }

    static func createOrganisationKey(label: String) throws -> TagLockOrganisationKey {
        let cleanLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanLabel.isEmpty else { throw TagLockKeyStoreError.invalidKey }
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw TagLockKeyStoreError.keychainStatus(status) }
        let entry = TagLockOrganisationKey(label: cleanLabel, key: key)
        var existing = try loadOrganisationKeys()
        existing.append(entry)
        try saveOrganisationKeys(existing)
        return entry
    }

    /// Removes one Organisation key from this device only. Tags protected with
    /// it can no longer be rewritten here unless the key is imported again.
    static func deleteOrganisationKey(id: UUID) throws {
        var keys = try loadOrganisationKeys()
        guard keys.contains(where: { $0.id == id }) else { return }
        keys.removeAll { $0.id == id }
        try saveOrganisationKeys(keys)
    }

    /// Replaces the device-only Auto master key with a new random key. Tags
    /// protected with the old key can no longer be rewritten by this device
    /// unless an encrypted backup containing the old key is restored first.
    static func rotateAutoKey() throws -> Data {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw TagLockKeyStoreError.keychainStatus(status) }
        try write(bytes, account: autoAccount)
        return bytes
    }

    static func exportBundle(includeAutoKey: Bool) throws -> TagLockKeyBundle {
        TagLockKeyBundle(autoKey: includeAutoKey ? try loadAutoKey() : nil,
                         organisationKeys: try loadOrganisationKeys())
    }

    static func importBundle(_ bundle: TagLockKeyBundle) throws {
        guard bundle.version == 1,
              bundle.autoKey == nil || bundle.autoKey?.count == 32,
              bundle.organisationKeys.allSatisfy({ $0.key.count == 32 && !$0.label.isEmpty }) else {
            throw TagLockKeyStoreError.malformedKeys
        }
        if let incomingAutoKey = bundle.autoKey,
           let currentAutoKey = try loadAutoKey(),
           currentAutoKey != incomingAutoKey {
            // Do not silently replace the derivation key on a device that may
            // already manage protected tags; that could strand those tags.
            throw TagLockKeyStoreError.conflictingAutoKey
        }
        // Validate everything before changing Keychain, then merge labels by ID.
        var organisations = try loadOrganisationKeys()
        for incoming in bundle.organisationKeys where !organisations.contains(where: { $0.id == incoming.id }) {
            organisations.append(incoming)
        }
        if let key = bundle.autoKey { try write(key, account: autoAccount) }
        try saveOrganisationKeys(organisations)
    }

    private static func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw TagLockKeyStoreError.keychainStatus(status)
        }
        return data
    }

    private static func write(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw TagLockKeyStoreError.keychainStatus(addStatus) }
        } else if status != errSecSuccess {
            throw TagLockKeyStoreError.keychainStatus(status)
        }
    }

    private static func baseQuery(account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }
}
