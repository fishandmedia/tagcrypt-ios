import CommonCrypto
import CryptoKit
import Foundation
import Security
import Sodium

/// Legacy v4-v6 envelopes remain readable. New FIDO envelopes use a binary v7
/// discriminator, Argon2id for passphrase slots, and the same padded plaintext
/// profile as passphrase-only v7 records.
enum FIDOEnvelopeCrypto {
    private static let magicV4 = Data([0x54, 0x56, 0x4c, 0x54, 0x04])
    private static let magicV5 = Data([0x54, 0x56, 0x4c, 0x54, 0x05])
    private static let magicV6 = Data([0x54, 0x56, 0x4c, 0x54, 0x06])
    private static let magicV7 = Data([0x5a, 0xd3, 0x7e, 0x91])
    private static let pbkdf2ID: UInt8 = 1
    private static let argon2idID: UInt8 = 2
    private static let iterations: UInt32 = 600_000
    private static let keyLength = 32
    private static let saltLength = 16
    private static let argonOps = Sodium().pwHash.OpsLimitInteractive
    private static let argonMemory = Sodium().pwHash.MemLimitInteractive
    private static let paddedBuckets = [32, 64, 128, 256, 384, 512, 640, 768]
    private static let maxPlaintextBytes = 2_048
    private static let innerMarker = Data("TC7\0".utf8)
    private static let maxQRPayloadBytes = 1_200
    private struct Slot { let type: UInt8; let metadata: Data; let wrappedKey: Data }
    private struct Parsed { let magic: Data; let aadHeader: Data; let payload: Data; let slots: [Slot] }

    enum UnlockMode: Equatable {
        case passphraseOnly
        case fidoOnly
        case passphraseAndFIDO
        case legacyEither
    }

    static func makePRFInput() throws -> Data { try randomData(count: 32) }

    static func estimatedNDEFLength(vault: PasswordVault, credentialIDs: [Data], mode: UnlockMode, padded: Bool = true, targetRecordLength: Int? = nil) throws -> Int {
        VaultNDEFTextCodec.binaryMessageLength(byteCount: try estimatedRecordLength(vault: vault, credentialIDs: credentialIDs, mode: mode, padded: padded, targetRecordLength: targetRecordLength, enforceQRLimit: false))
    }

    static func estimatedRecordByteLength(vault: PasswordVault, credentialIDs: [Data], mode: UnlockMode,
                                          padded: Bool = true, targetRecordLength: Int? = nil) throws -> Int {
        try estimatedRecordLength(vault: vault, credentialIDs: credentialIDs, mode: mode, padded: padded,
                                  targetRecordLength: targetRecordLength, enforceQRLimit: false)
    }

    static func estimatedBase64TextLength(vault: PasswordVault, credentialIDs: [Data], mode: UnlockMode) throws -> Int {
        let binaryLength = try estimatedRecordLength(vault: vault, credentialIDs: credentialIDs, mode: mode, padded: true, enforceQRLimit: true)
        return ((binaryLength + 2) / 3) * 4
    }

    private static func estimatedRecordLength(vault: PasswordVault, credentialIDs: [Data], mode: UnlockMode, padded: Bool, targetRecordLength: Int? = nil, enforceQRLimit: Bool) throws -> Int {
        let json = try encode(vault)
        let minimumPlaintextLength = innerMarker.count + 5 + json.count
        guard minimumPlaintextLength <= maxPlaintextBytes else { throw VaultError.recordTooLarge }
        let fixedLength = fixedRecordLength(credentialIDs: credentialIDs, mode: mode)
        let plaintextLength: Int
        if !padded {
            plaintextLength = minimumPlaintextLength
        } else if let targetRecordLength {
            plaintextLength = targetRecordLength - fixedLength - 12 - 16
        } else {
            guard let bucket = paddedBuckets.first(where: { $0 >= minimumPlaintextLength }) else { throw VaultError.recordTooLarge }
            plaintextLength = bucket
        }
        guard plaintextLength >= minimumPlaintextLength, plaintextLength <= maxPlaintextBytes else { throw VaultError.recordTooLarge }
        let payloadLength = 12 + plaintextLength + 16
        let binaryLength = fixedLength + payloadLength
        if enforceQRLimit && "TAGCRYPT1:".utf8.count + ((binaryLength + 2) / 3) * 4 > maxQRPayloadBytes {
            throw VaultError.recordTooLarge
        }
        return binaryLength
    }

    private static func fixedRecordLength(credentialIDs: [Data], mode: UnlockMode) -> Int {
        let passMetadataLength = 25
        let slotHeaderLength = 5 + 60
        let fidoMetadataLengths = credentialIDs.reduce(0) { $0 + 1 + $1.count + 32 + 16 }
        let includesPassphraseSlot = mode == .passphraseAndFIDO
        return magicV7.count + saltLength + 4 + 1
            + credentialIDs.count * slotHeaderLength + fidoMetadataLengths
            + (includesPassphraseSlot ? slotHeaderLength + passMetadataLength : 0)
    }

    static func seal(_ vault: PasswordVault, passphrase: String, credentials: [(credentialID: Data, prfOutput: Data)], prfInput: Data, mode: UnlockMode, padRecord: Bool = true, targetRecordLength: Int? = nil) throws -> Data {
        guard !vault.secret.isEmpty || !(vault.slots?.isEmpty ?? true) else { throw VaultError.emptySecret }
        let needsPassphrase = mode == .passphraseAndFIDO
        let normalized = passphrase.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
        if needsPassphrase {
            guard !normalized.isEmpty else { throw VaultError.emptyPassphrase }
            guard normalized.utf8.count >= 16,
                  TagcryptPassphraseAssessment.evaluate(normalized).meetsMinimum else {
                throw VaultError.passphraseTooShort
            }
        }
        guard (1...3).contains(credentials.count), prfInput.count == 32,
              credentials.allSatisfy({ !$0.credentialID.isEmpty && $0.credentialID.count <= 255 && $0.prfOutput.count == 32 }) else {
            throw FIDOKeyError.missingPRFOutput
        }
        guard mode == .fidoOnly || mode == .passphraseAndFIDO else { throw VaultError.unsupportedVersion }
        let magic = magicV7
        let salt = try randomData(count: saltLength)
        let aadHeader = magic + salt
        let json = try encode(vault)
        let minimumPlaintextLength = innerMarker.count + 5 + json.count
        let credentialIDs = credentials.map(\.credentialID)
        let plaintextLength: Int
        if !padRecord {
            plaintextLength = minimumPlaintextLength
        } else if let targetRecordLength {
            plaintextLength = targetRecordLength - fixedRecordLength(credentialIDs: credentialIDs, mode: mode) - 12 - 16
        } else {
            plaintextLength = paddedBuckets.first(where: { $0 >= minimumPlaintextLength }) ?? 0
        }
        guard plaintextLength >= minimumPlaintextLength, plaintextLength <= maxPlaintextBytes else { throw VaultError.recordTooLarge }
        let paddingCount = plaintextLength - minimumPlaintextLength
        let padding = paddingCount > 0 ? try randomData(count: paddingCount) : Data()
        var plaintext = innerMarker + Data([padRecord ? 1 : 0]) + uint32(UInt32(json.count)) + json + padding
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        var dek = try randomData(count: keyLength)
        defer { dek.resetBytes(in: 0..<dek.count) }
        let payload = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: dek), authenticating: aadHeader).combined
        var passKEK: SymmetricKey?
        var passMetadata: Data?
        if needsPassphrase {
            let passSalt = try randomData(count: saltLength)
            let metadata = Data([argon2idID]) + uint32(UInt32(argonOps)) + uint32(UInt32(argonMemory)) + passSalt
            passMetadata = metadata
            passKEK = try deriveArgon2idKey(normalized, salt: passSalt, opsLimit: argonOps, memLimit: argonMemory)
        }
        var slots = [Slot]()
        if let passMetadata, let passKEK {
            // Explicit emergency path: a passphrase can recover a joint-mode record alone.
            slots.append(try makeSlot(type: 1, metadata: passMetadata, wrappingKey: passKEK, payload: payload, dek: dek, aadHeader: aadHeader))
        }
        for credential in credentials {
            let wrapSalt = try randomData(count: 16)
            let metadata = Data([UInt8(credential.credentialID.count)]) + credential.credentialID + prfInput + wrapSalt
            let fidoKEK = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: credential.prfOutput), salt: wrapSalt,
                                                 info: Data("Tagcrypt v7 FIDO key-wrap".utf8), outputByteCount: keyLength)
            if mode == .fidoOnly {
                slots.append(try makeSlot(type: 2, metadata: metadata, wrappingKey: fidoKEK, payload: payload, dek: dek, aadHeader: aadHeader))
            } else if let passKEK {
                var combinedInput = Data(passKEK.withUnsafeBytes { Data($0) })
                combinedInput.append(contentsOf: fidoKEK.withUnsafeBytes { Data($0) })
                defer { combinedInput.resetBytes(in: 0..<combinedInput.count) }
                let combinedKEK = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: combinedInput), salt: wrapSalt,
                    info: Data("Tagcrypt v7 passphrase + FIDO key-wrap".utf8), outputByteCount: keyLength)
                slots.append(try makeSlot(type: 3, metadata: metadata, wrappingKey: combinedKEK, payload: payload, dek: dek, aadHeader: aadHeader))
            }
        }
        var output = aadHeader + uint32(UInt32(payload.count)) + payload + Data([UInt8(slots.count)])
        for slot in slots {
            output.append(slot.type); output.append(uint16(UInt16(slot.metadata.count))); output.append(slot.metadata)
            output.append(uint16(UInt16(slot.wrappedKey.count))); output.append(slot.wrappedKey)
        }
        return output
    }

    static func openWithPassphrase(_ input: Data, passphrase: String) throws -> PasswordVault {
        let parsed = try parse(input)
        guard let slot = parsed.slots.first(where: { $0.type == 1 }) else { throw VaultError.malformedRecord }
        let normalized = passphrase.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
        guard !normalized.isEmpty else { throw VaultError.emptyPassphrase }
        do {
            let key: SymmetricKey
            if parsed.magic == magicV7 {
                guard slot.metadata.count == 25, slot.metadata[0] == argon2idID else { throw VaultError.malformedRecord }
                let ops = Int(readUInt32(slot.metadata, at: 1))
                let memory = Int(readUInt32(slot.metadata, at: 5))
                guard validArgonParameters(ops, memory) else { throw VaultError.unsupportedVersion }
                key = try deriveArgon2idKey(normalized, salt: Data(slot.metadata[9..<25]), opsLimit: ops, memLimit: memory)
            } else {
                guard slot.metadata.count == 21, slot.metadata[0] == pbkdf2ID,
                      readUInt32(slot.metadata, at: 1) == iterations else { throw VaultError.unsupportedVersion }
                key = try derivePassphraseKey(normalized, salt: Data(slot.metadata[5..<21]))
            }
            let dek = try unwrap(slot, key: key, payload: parsed.payload, aadHeader: parsed.aadHeader)
            return try openPayload(parsed.payload, dek: dek, magic: parsed.magic, aadHeader: parsed.aadHeader)
        } catch { throw VaultError.decryptionFailed }
    }

    static func openWithFIDO(_ input: Data, credentialID: Data, prfOutput: Data) throws -> PasswordVault {
        let parsed = try parse(input)
        guard prfOutput.count == 32,
              let slot = parsed.slots.first(where: { $0.type == 2 && Self.credentialID(from: $0.metadata) == credentialID }),
              let wrapSalt = wrapSalt(from: slot.metadata) else { throw VaultError.decryptionFailed }
        let info: Data
        if parsed.magic == magicV4 { info = Data("Tagcrypt v4 FIDO key-wrap".utf8) }
        else if parsed.magic == magicV6 { info = Data("Tagcrypt v6 FIDO key-wrap".utf8) }
        else if parsed.magic == magicV7 { info = Data("Tagcrypt v7 FIDO key-wrap".utf8) }
        else { info = Data("Tagcrypt v5 FIDO key-wrap".utf8) }
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prfOutput), salt: wrapSalt, info: info, outputByteCount: keyLength)
        do {
            let dek = try unwrap(slot, key: key, payload: parsed.payload, aadHeader: parsed.aadHeader)
            return try openPayload(parsed.payload, dek: dek, magic: parsed.magic, aadHeader: parsed.aadHeader)
        } catch { throw VaultError.decryptionFailed }
    }

    static func openWithPassphraseAndFIDO(_ input: Data, passphrase: String, credentialID: Data, prfOutput: Data) throws -> PasswordVault {
        let parsed = try parse(input)
        guard (parsed.magic == magicV6 || parsed.magic == magicV7), prfOutput.count == 32,
              let passSlot = parsed.slots.first(where: { $0.type == 1 }),
              let fidoSlot = parsed.slots.first(where: { $0.type == 3 && Self.credentialID(from: $0.metadata) == credentialID }),
              let wrapSalt = wrapSalt(from: fidoSlot.metadata) else { throw VaultError.decryptionFailed }
        let normalized = passphrase.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
        guard normalized.utf8.count >= 16 else { throw VaultError.decryptionFailed }
        do {
            let passKey: SymmetricKey
            if parsed.magic == magicV7 {
                guard passSlot.metadata.count == 25, passSlot.metadata[0] == argon2idID else { throw VaultError.decryptionFailed }
                let ops = Int(readUInt32(passSlot.metadata, at: 1))
                let memory = Int(readUInt32(passSlot.metadata, at: 5))
                guard validArgonParameters(ops, memory) else { throw VaultError.decryptionFailed }
                passKey = try deriveArgon2idKey(normalized, salt: Data(passSlot.metadata[9..<25]), opsLimit: ops, memLimit: memory)
            } else {
                guard passSlot.metadata.count == 21, passSlot.metadata[0] == pbkdf2ID,
                      readUInt32(passSlot.metadata, at: 1) == iterations else { throw VaultError.decryptionFailed }
                passKey = try derivePassphraseKey(normalized, salt: Data(passSlot.metadata[5..<21]))
            }
            let fidoKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prfOutput), salt: wrapSalt,
                info: Data("Tagcrypt v\(parsed.magic == magicV7 ? "7" : "6") FIDO key-wrap".utf8), outputByteCount: keyLength)
            var combinedInput = Data(passKey.withUnsafeBytes { Data($0) })
            combinedInput.append(contentsOf: fidoKey.withUnsafeBytes { Data($0) })
            defer { combinedInput.resetBytes(in: 0..<combinedInput.count) }
            let combinedKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: combinedInput), salt: wrapSalt,
                info: Data("Tagcrypt v\(parsed.magic == magicV7 ? "7" : "6") passphrase + FIDO key-wrap".utf8), outputByteCount: keyLength)
            let dek = try unwrap(fidoSlot, key: combinedKey, payload: parsed.payload, aadHeader: parsed.aadHeader)
            return try openPayload(parsed.payload, dek: dek, magic: parsed.magic, aadHeader: parsed.aadHeader)
        } catch { throw VaultError.decryptionFailed }
    }

    static func unlockMode(in input: Data) throws -> UnlockMode {
        let parsed = try parse(input)
        guard parsed.magic == magicV6 || parsed.magic == magicV7 else { return parsed.slots.contains(where: { $0.type == 2 }) ? .legacyEither : .passphraseOnly }
        if parsed.slots.contains(where: { $0.type == 3 }) { return .passphraseAndFIDO }
        if parsed.slots.contains(where: { $0.type == 2 }) { return .fidoOnly }
        throw VaultError.malformedRecord
    }

    static func fidoParameters(in input: Data) throws -> [(credentialID: Data, prfInput: Data)] {
        let parsed = try parse(input)
        let parameters = parsed.slots.filter { $0.type == 2 || $0.type == 3 }.compactMap { slot -> (Data, Data)? in
            guard let credentialID = credentialID(from: slot.metadata), let prfInput = prfInput(from: slot.metadata) else { return nil }
            return (credentialID, prfInput)
        }
        guard !parameters.isEmpty else { throw VaultError.malformedRecord }
        return parameters
    }

    private static func parse(_ input: Data) throws -> Parsed {
        let data = Data(input)
        let magic: Data
        if data.starts(with: magicV4) { magic = magicV4 }
        else if data.starts(with: magicV5) { magic = magicV5 }
        else if data.starts(with: magicV6) { magic = magicV6 }
        else if data.starts(with: magicV7) { magic = magicV7 }
        else { throw VaultError.malformedRecord }
        let aadHeader: Data
        var cursor: Int
        if magic == magicV7 {
            guard data.count >= magic.count + saltLength + 5 else { throw VaultError.malformedRecord }
            cursor = magic.count + saltLength
            aadHeader = Data(data[..<cursor])
        } else {
            cursor = magic.count
            aadHeader = magic
        }
        guard data.count > cursor + 5 else { throw VaultError.malformedRecord }
        let payloadLength = Int(readUInt32(data, at: cursor)); cursor += 4
        guard payloadLength >= 28, payloadLength <= 1_000_000, cursor + payloadLength + 1 <= data.count else { throw VaultError.malformedRecord }
        let payload = Data(data[cursor..<(cursor + payloadLength)]); cursor += payloadLength
        let slotCount = Int(data[cursor]); cursor += 1
        guard (1...4).contains(slotCount) else { throw VaultError.malformedRecord }
        var slots = [Slot]()
        for _ in 0..<slotCount {
            guard cursor + 3 <= data.count else { throw VaultError.malformedRecord }
            let type = data[cursor]; cursor += 1
            let metadataLength = Int(readUInt16(data, at: cursor)); cursor += 2
            guard metadataLength <= 512, cursor + metadataLength + 2 <= data.count else { throw VaultError.malformedRecord }
            let metadata = Data(data[cursor..<(cursor + metadataLength)]); cursor += metadataLength
            let wrappedLength = Int(readUInt16(data, at: cursor)); cursor += 2
            guard wrappedLength == 60, cursor + wrappedLength <= data.count else { throw VaultError.malformedRecord }
            let wrappedKey = Data(data[cursor..<(cursor + wrappedLength)]); cursor += wrappedLength
            guard (1...3).contains(type) else { throw VaultError.unsupportedVersion }
            slots.append(Slot(type: type, metadata: metadata, wrappedKey: wrappedKey))
        }
        let validSlots: Bool
        if magic == magicV6 || magic == magicV7 {
            let type1 = slots.filter { $0.type == 1 }.count
            let type2 = slots.filter { $0.type == 2 }.count
            let type3 = slots.filter { $0.type == 3 }.count
            validSlots = (type1 == 0 && type2 > 0 && type2 <= 3 && type3 == 0)
                || (type1 == 1 && type2 == 0 && type3 > 0 && type3 <= 3)
        } else {
            validSlots = slots.contains(where: { $0.type == 1 }) && slots.contains(where: { $0.type == 2 })
                && (magic == magicV4 ? slots.filter({ $0.type == 2 }).count == 1 : slots.filter({ $0.type == 2 }).count <= 3)
        }
        guard cursor == data.count, validSlots else {
            throw VaultError.malformedRecord
        }
        return Parsed(magic: magic, aadHeader: aadHeader, payload: payload, slots: slots)
    }

    private static func makeSlot(type: UInt8, metadata: Data, wrappingKey: SymmetricKey, payload: Data, dek: Data, aadHeader: Data) throws -> Slot {
        let aad = aadHeader + payload + Data([type]) + metadata
        let wrapped = try ChaChaPoly.seal(dek, using: wrappingKey, authenticating: aad)
        return Slot(type: type, metadata: metadata, wrappedKey: wrapped.combined)
    }
    private static func unwrap(_ slot: Slot, key: SymmetricKey, payload: Data, aadHeader: Data) throws -> Data {
        let aad = aadHeader + payload + Data([slot.type]) + slot.metadata
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: slot.wrappedKey), using: key, authenticating: aad)
    }
    private static func openPayload(_ payload: Data, dek: Data, magic: Data, aadHeader: Data) throws -> PasswordVault {
        var clear = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: payload), using: SymmetricKey(data: dek), authenticating: aadHeader)
        defer { clear.resetBytes(in: 0..<clear.count) }
        if magic == magicV7 {
            guard clear.count >= 9, clear.starts(with: innerMarker), clear[4] <= 1 else { throw VaultError.malformedRecord }
            let padded = clear[4] == 1
            let jsonLength = Int(readUInt32(clear, at: 5))
            let jsonStart = 9
            guard jsonLength > 0, jsonStart + jsonLength <= clear.count,
                  padded ? clear.count <= maxPlaintextBytes : jsonStart + jsonLength == clear.count else {
                throw VaultError.malformedRecord
            }
            return try JSONDecoder().decode(PasswordVault.self, from: Data(clear[jsonStart..<(jsonStart + jsonLength)]))
        }
        return try JSONDecoder().decode(PasswordVault.self, from: clear)
    }
    private static func derivePassphraseKey(_ passphrase: String, salt: Data) throws -> SymmetricKey {
        var password = Data(passphrase.utf8); defer { password.resetBytes(in: 0..<password.count) }
        var derived = Data(count: keyLength)
        let status = password.withUnsafeBytes { passBytes in salt.withUnsafeBytes { saltBytes in derived.withUnsafeMutableBytes { outBytes in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passBytes.bindMemory(to: Int8.self).baseAddress, password.count,
                saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                outBytes.bindMemory(to: UInt8.self).baseAddress, keyLength)
        } } }
        guard status == kCCSuccess else { derived.resetBytes(in: 0..<derived.count); throw VaultError.derivationFailed(status) }
        defer { derived.resetBytes(in: 0..<derived.count) }
        return SymmetricKey(data: derived)
    }
    private static func deriveArgon2idKey(_ passphrase: String, salt: Data, opsLimit: Int, memLimit: Int) throws -> SymmetricKey {
        guard salt.count == Sodium().pwHash.SaltBytes, validArgonParameters(opsLimit, memLimit) else {
            throw VaultError.unsupportedVersion
        }
        var password = Array(passphrase.utf8)
        defer { password.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        guard let bytes = Sodium().pwHash.hash(outputLength: keyLength, passwd: password, salt: Array(salt),
                                               opsLimit: opsLimit, memLimit: memLimit, alg: .Argon2ID13) else {
            throw VaultError.derivationFailed(-1)
        }
        return SymmetricKey(data: Data(bytes))
    }
    private static func validArgonParameters(_ ops: Int, _ memory: Int) -> Bool {
        ops == argonOps && memory == argonMemory
    }
    private static func encode(_ vault: PasswordVault) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try encoder.encode(vault)
    }
    private static func credentialID(from metadata: Data) -> Data? {
        guard let length = metadata.first, length > 0, metadata.count == 1 + Int(length) + 32 + 16 else { return nil }
        return Data(metadata[1..<(1 + Int(length))])
    }
    private static func prfInput(from metadata: Data) -> Data? {
        guard let id = credentialID(from: metadata) else { return nil }
        return Data(metadata[(1 + id.count)..<(1 + id.count + 32)])
    }
    private static func wrapSalt(from metadata: Data) -> Data? {
        guard let id = credentialID(from: metadata) else { return nil }
        return Data(metadata[(1 + id.count + 32)..<(1 + id.count + 48)])
    }
    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw VaultError.randomGenerationFailed(status) }
        return data
    }
    private static func uint32(_ value: UInt32) -> Data { var value = value.bigEndian; return Data(bytes: &value, count: 4) }
    private static func uint16(_ value: UInt16) -> Data { var value = value.bigEndian; return Data(bytes: &value, count: 2) }
    private static func readUInt32(_ data: Data, at index: Int) -> UInt32 { data[index..<(index + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } }
    private static func readUInt16(_ data: Data, at index: Int) -> UInt16 { data[index..<(index + 2)].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) } }
}
