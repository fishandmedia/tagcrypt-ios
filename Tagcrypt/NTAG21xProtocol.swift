import Foundation
import Security

/// NTAG21x identification and command helpers. These helpers do not prove that a
/// tag is genuine NXP silicon; callers must keep writes explicit and fail closed
/// when the model/configuration is uncertain.
enum NTAG21xProtocol {
    enum Model: String {
        case ntag213 = "NTAG213"
        case ntag215 = "NTAG215"
        case ntag216 = "NTAG216"

        var userBytes: Int {
            switch self {
            case .ntag213: 144
            case .ntag215: 504
            case .ntag216: 888
            }
        }

        var userPageCount: Int { userBytes / 4 }
        var configurationPage: UInt8 {
            switch self {
            case .ntag213: 0x29
            case .ntag215: 0x83
            case .ntag216: 0xE3
            }
        }

        var config0Page: UInt8 { configurationPage }
        /// Dynamic lock bytes sit in the page just before CONFIG0 (0x28/0x82/0xE2).
        var dynamicLockPage: UInt8 { configurationPage &- 1 }
        /// Factory Capability Container: NDEF magic, v1.0, data size / 8, open access.
        var factoryCapabilityContainer: Data {
            switch self {
            case .ntag213: Data([0xE1, 0x10, 0x12, 0x00])
            case .ntag215: Data([0xE1, 0x10, 0x3E, 0x00])
            case .ntag216: Data([0xE1, 0x10, 0x6D, 0x00])
            }
        }
        /// Dynamic lock bits that cover every user page from 16 to the last
        /// (NTAG213/215/216 datasheet, dynamic lock bytes). NTAG213: one bit per
        /// 2 pages (pages 16-39 -> FF 0F). NTAG215/216: one bit per 16 pages
        /// (215 pages 16-129 -> byte 0 = FF; 216 pages 16-225 -> FF 3F).
        /// Byte 2 (block-lock bits) and RFUI bits stay 0.
        var dynamicSealBytes: Data {
            switch self {
            case .ntag213: Data([0xFF, 0x0F, 0x00])
            case .ntag215: Data([0xFF, 0x00, 0x00])
            case .ntag216: Data([0xFF, 0x3F, 0x00])
            }
        }
        var config1Page: UInt8 { configurationPage &+ 1 }
        var passwordPage: UInt8 { configurationPage &+ 2 }
        var packPage: UInt8 { configurationPage &+ 3 }
    }

    struct Configuration: Equatable {
        let config0: Data
        let config1: Data

        init?(config0: Data, config1: Data) {
            guard config0.count == 4, config1.count == 4 else { return nil }
            // Re-base slices (e.g. `read.dropFirst(4).prefix(4)`) to index 0;
            // `auth0`/`access` subscript from 0 and would trap on a slice.
            self.config0 = Data(config0)
            self.config1 = Data(config1)
        }

        var auth0: UInt8 { config0[3] }
        var access: UInt8 { config1[0] }
        var authLimit: UInt8 { access & 0x07 }
        var protectsReads: Bool { access & 0x80 != 0 }
    }

    struct PageWrite: Equatable {
        let page: UInt8
        let bytes: Data
    }

    struct UserMemorySealPlan: Equatable {
        let model: Model
        let writes: [PageWrite]
        let expectedCapabilityContainer: Data
        let expectedStaticLockBytes: Data
        let expectedDynamicLockBytes: Data
        let expectedConfig1: Data
    }

    struct Identification {
        let model: Model
        let versionBytes: Data
        let auth0: UInt8?
        let writeProtectedFromPage: Int?

        var protectionDescription: String {
            guard let auth0 else { return "Password-protection status unavailable" }
            return auth0 == 0xFF ? "No NTAG password write protection detected" :
                "Password write protection begins at page \(auth0)"
        }
    }

    struct Protection {
        let auth0: UInt8
        let protectsReads: Bool
    }

    /// GET_VERSION is a read-only command. The response's storage-size byte
    /// identifies NTAG213/215/216 as 0x0F/0x11/0x13 respectively.
    static func model(fromGetVersion response: Data) -> Model? {
        guard response.count == 8 else { return nil }
        return switch response[6] {
        case 0x0F: .ntag213
        case 0x11: .ntag215
        case 0x13: .ntag216
        default: nil
        }
    }

    /// Compatible-tag fallback: infer the model from the Capability Container
    /// (page 3) size byte when GET_VERSION does not identify the tag. Only used
    /// when the user has turned on "Compatible tags"; the CC is written by the
    /// tag maker and is not proof of the memory map.
    static func model(fromCapabilityContainer cc: Data) -> Model? {
        guard cc.count >= 4 else { return nil }
        let bytes = [UInt8](cc.prefix(4))
        guard bytes[0] == 0xE1 else { return nil }
        return switch bytes[2] {
        case 0x12: .ntag213
        case 0x3E: .ntag215
        case 0x6D: .ntag216
        default: nil
        }
    }

    /// CRC_A, returned in the byte order required by the NTAG21x native command
    /// interface (least-significant byte first).
    static func crcA(for bytes: Data) -> Data {
        var crc: UInt16 = 0x6363
        for byte in bytes {
            var value = UInt16(byte) ^ (crc & 0x00FF)
            value ^= value << 4
            crc = (crc >> 8) ^ (value << 8) ^ (value << 3) ^ (value >> 4)
        }
        return Data([UInt8(truncatingIfNeeded: crc), UInt8(truncatingIfNeeded: crc >> 8)])
    }

    /// P1-1: single switch for whether Tagcrypt appends CRC_A to native NTAG
    /// commands sent through `sendMiFareCommand`. Apple's reference says the
    /// caller must append it; field reports say Core NFC already does. Do not
    /// change this default until the read-only CRC diagnostic has been run on
    /// disposable tags; then update tests/tag_lock_protocol/main.swift to match.
    /// Decided 2026-10-11 from Can's physical CRC tests (NTAG215 clone, maker
    /// 0x04; NTAG216-compatible, maker 0x53): GET_VERSION without CRC returns
    /// 8 valid bytes, while the CRC-appended frame drops the connection and
    /// leaves the tag unresponsive for the session. Core NFC adds CRC_A itself.
    static let appendsCRC = false

    /// CRC mode for the current NFC session. NFCService's identification probe
    /// sets it per tag: it tries GET_VERSION with CRC_A first (the default above)
    /// and, if that fails, reconnects and retries without. All later native
    /// commands in that session use the mode that worked. Reset to the default
    /// at the start of every session. Only touched from the NFC session flow.
    nonisolated(unsafe) static var sessionAppendsCRC = appendsCRC

    static func command(_ bytes: [UInt8]) -> Data {
        command(bytes, appendingCRC: sessionAppendsCRC)
    }

    static func command(_ bytes: [UInt8], appendingCRC: Bool) -> Data {
        let body = Data(bytes)
        return appendingCRC ? body + crcA(for: body) : body
    }

    /// Read-only GET_VERSION frames for the CRC diagnostic.
    static let getVersionWithCRC = command([0x60], appendingCRC: true)
    static let getVersionWithoutCRC = command([0x60], appendingCRC: false)

    static func passwordAuthCommand(password: Data) -> Data? {
        guard password.count == 4 else { return nil }
        return command([0x1B] + Array(password))
    }

    static func passwordAuthMatches(_ response: Data, expectedPack: Data) -> Bool {
        guard expectedPack.count == 2 else { return false }
        // Core NFC versions may expose either the two response bytes or the raw
        // four-byte PACK+CRC_A frame. Accept the former, and verify CRC when
        // present; never treat malformed lengths as success.
        if response.count == 2 { return response == expectedPack }
        guard response.count == 4, response.prefix(2) == expectedPack else { return false }
        return response.suffix(2) == crcA(for: expectedPack)
    }

    static func writePageCommand(page: UInt8, data: Data) -> Data? {
        guard data.count == 4 else { return nil }
        return command([0xA2, page] + Array(data))
    }

    /// Pages used by the NTAG213 seal (NTAG213 datasheet, memory map).
    static let ntag213CapabilityContainerPage: UInt8 = 0x03
    static let ntag213StaticLockPage: UInt8 = 0x02
    static let ntag213DynamicLockPage: UInt8 = 0x28
    static let ntag213Config0Page: UInt8 = 0x29
    static let ntag213Config1Page: UInt8 = 0x2A
    /// A factory NTAG213 Capability Container: NDEF magic, version 1.0,
    /// 0x12 * 8 = 144 data bytes, read/write access.
    static let ntag213FactoryCapabilityContainer = Data([0xE1, 0x10, 0x12, 0x00])

    /// P1-2: permanent NTAG213 seal that freezes user memory, the Capability
    /// Container and the configuration pages. Order, each write read back by
    /// the caller afterwards:
    ///   1. CC page 3 -> E1 10 12 0F (OTP, OR-only: only the access byte
    ///      changes, to read-only, so phones stop offering writes);
    ///   2. dynamic lock bytes (page 0x28) -> FF 0F 00, locking pages 16-39;
    ///   3. static lock bytes (page 0x02) -> FE FF: L4-L15, block-locks
    ///      BL 9-4 / BL 15-10 and L_CC, so pages 3-15 are read-only;
    ///   4. CONFIG1 byte 0 |= CFGLCK (bit 6); AUTH0 stays 0xFF, so nobody can
    ///      later enable a password that would hide the sealed record.
    /// Fail-closed: refuses unless the CC is the factory value, every lock bit
    /// is zero, CFGLCK is clear, AUTH0 is 0xFF and read protection is off.
    /// NTAG215/216 are deliberately not guessed.
    static func ntag213WholeUserMemorySealPlan(capabilityContainer: Data,
                                               staticLockBytes: Data,
                                               dynamicLockBytes: Data,
                                               configuration: Configuration) -> UserMemorySealPlan? {
        wholeUserMemorySealPlan(model: .ntag213, capabilityContainer: capabilityContainer,
                                staticLockBytes: staticLockBytes, dynamicLockBytes: dynamicLockBytes,
                                configuration: configuration)
    }

    /// Same plan for any NTAG21x size; only the CC size byte, the dynamic lock
    /// page and its bit pattern, and the CONFIG pages differ.
    static func wholeUserMemorySealPlan(model: Model, capabilityContainer: Data,
                                        staticLockBytes: Data,
                                        dynamicLockBytes: Data,
                                        configuration: Configuration) -> UserMemorySealPlan? {
        guard capabilityContainer == model.factoryCapabilityContainer,
              staticLockBytes.count == 2, dynamicLockBytes.count == 3,
              staticLockBytes.allSatisfy({ $0 == 0 }),
              dynamicLockBytes.allSatisfy({ $0 == 0 }),
              configuration.auth0 == 0xFF, !configuration.protectsReads,
              configuration.access & 0x40 == 0 else { return nil }
        var cc = model.factoryCapabilityContainer
        cc[3] = 0x0F
        let dynamic = model.dynamicSealBytes
        let staticBytes = Data([0xFE, 0xFF])
        var config1 = configuration.config1
        config1[config1.startIndex] |= 0x40
        return UserMemorySealPlan(
            model: model,
            writes: [
                PageWrite(page: ntag213CapabilityContainerPage, bytes: cc),
                PageWrite(page: model.dynamicLockPage, bytes: dynamic + Data([0])),
                PageWrite(page: ntag213StaticLockPage, bytes: Data([0, 0]) + staticBytes),
                PageWrite(page: model.config1Page, bytes: Data(config1))
            ],
            expectedCapabilityContainer: cc,
            expectedStaticLockBytes: staticBytes,
            expectedDynamicLockBytes: dynamic,
            expectedConfig1: Data(config1)
        )
    }

    /// Create the password/configuration writes in the only safe order: PWD,
    /// PACK, CONFIG1, then CONFIG0/AUTH0 last. Existing AUTHLIM is checked before
    /// callers try any candidate password, so wrong-key scans cannot consume a
    /// limited-attempt counter.
    static func passwordProvisioningWrites(model: Model, credentials: TagLockCredentials,
                                           configuration: Configuration,
                                           authenticated: Bool = false) -> [PageWrite]? {
        guard credentials.password.count == 4, credentials.pack.count == 2,
              configuration.config0.count == 4, configuration.config1.count == 4,
              configuration.authLimit == 0, !configuration.protectsReads,
              configuration.auth0 == 0xFF || authenticated else { return nil }

        var config0 = configuration.config0
        var config1 = configuration.config1
        // Write protection only (PROT=0), no failed-attempt limit (AUTHLIM=0).
        // Retain all unrelated ACCESS/configuration bits and RFUI bytes.
        config1[0] &= ~UInt8(0x87)
        // Enable protection at the first user page only after all other config
        // and credentials are on the tag.
        config0[3] = 0x04

        return [
            PageWrite(page: model.passwordPage, bytes: credentials.password),
            PageWrite(page: model.packPage, bytes: credentials.pack + Data([0, 0])),
            PageWrite(page: model.config1Page, bytes: config1),
            PageWrite(page: model.config0Page, bytes: config0)
        ]
    }

    struct NDEFRecordBytes {
        let tnf: UInt8
        let type: Data
        let identifier: Data
        let payload: Data
    }

    /// NFC Forum NDEF message encoding (short records when the payload is under
    /// 256 bytes). Used only for the password-protected rewrite, where the
    /// record is written with native WRITE commands in the authenticated
    /// session instead of Core NFC's writeNDEF.
    static func ndefMessageBytes(_ records: [NDEFRecordBytes]) -> Data {
        var out = Data()
        for (index, record) in records.enumerated() {
            let short = record.payload.count < 256
            var header = record.tnf & 0x07
            if index == 0 { header |= 0x80 }                    // MB
            if index == records.count - 1 { header |= 0x40 }    // ME
            if short { header |= 0x10 }                          // SR
            if !record.identifier.isEmpty { header |= 0x08 }     // IL
            out.append(header)
            out.append(UInt8(record.type.count))
            if short {
                out.append(UInt8(record.payload.count))
            } else {
                let n = UInt32(record.payload.count)
                out.append(contentsOf: [UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
            }
            if !record.identifier.isEmpty { out.append(UInt8(record.identifier.count)) }
            out.append(record.type)
            out.append(record.identifier)
            out.append(record.payload)
        }
        return out
    }

    /// Type 2 NDEF TLV: 03, length (1 byte, or FF + 2 bytes from 255), message,
    /// FE terminator, zero-padded to whole 4-byte pages. Nil if it does not fit.
    static func ndefTLVPages(message: Data, model: Model) -> Data? {
        var tlv = Data([0x03])
        if message.count < 0xFF {
            tlv.append(UInt8(message.count))
        } else {
            tlv.append(contentsOf: [0xFF, UInt8(message.count >> 8), UInt8(message.count & 0xFF)])
        }
        tlv.append(message)
        tlv.append(0xFE)
        while tlv.count % 4 != 0 { tlv.append(0) }
        return tlv.count <= model.userBytes ? tlv : nil
    }

    /// A Type 2 READ command returns four consecutive 4-byte pages.
    static func readCommand(startingAt page: UInt8) -> Data {
        command([0x30, page])
    }

    /// Read-only config decoding. For NTAG21x, AUTH0 is byte 3 of CONFIG0;
    /// ACCESS.PROT is bit 7 of CONFIG1. PROT=0 is the requested write-only
    /// protection mode. This only reports settings; it never authenticates.
    static func protection(fromConfigRead response: Data, model: Model) -> Protection? {
        guard response.count == 16 else { return nil }
        _ = model
        let auth0 = response[3]
        let access = response[4]
        return Protection(auth0: auth0, protectsReads: access & 0x80 != 0)
    }

    static func userMemory(from tagRead: Data, model: Model) -> Data? {
        guard tagRead.count == model.userBytes else { return nil }
        return tagRead
    }

    /// Returns the NDEF TLV's terminator offset within user memory. It parses
    /// Type 2 TLV lengths rather than searching ciphertext for 0xFE.
    static func ndefTerminatorOffset(in memory: Data) -> Int? {
        var cursor = 0
        while cursor < memory.count {
            let type = memory[cursor]
            if type == 0x00 { cursor += 1; continue } // NULL TLV
            if type == 0xFE { return cursor }
            guard cursor + 1 < memory.count else { return nil }
            let shortLength = Int(memory[cursor + 1])
            var valueStart = cursor + 2
            let length: Int
            if shortLength == 0xFF {
                guard cursor + 3 < memory.count else { return nil }
                length = Int(memory[cursor + 2]) << 8 | Int(memory[cursor + 3])
                valueStart = cursor + 4
            } else {
                length = shortLength
            }
            guard length <= memory.count - valueStart else { return nil }
            let next = valueStart + length
            if type == 0x03 {
                return next < memory.count && memory[next] == 0xFE ? next : nil
            }
            cursor = next
        }
        return nil
    }

    static func randomize(after offset: Int, in memory: Data) throws -> Data {
        guard offset >= 0, offset < memory.count else { return memory }
        var output = memory
        let byteCount = memory.count - offset
        let status = output.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, raw.baseAddress!.advanced(by: offset))
        }
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        return output
    }
}
