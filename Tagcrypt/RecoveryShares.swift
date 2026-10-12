import Foundation
import Security

enum TagcryptRecoveryShares {
    static let binaryMediaType = "application/vnd.tagcrypt.share"

    enum ShareError: LocalizedError {
        case invalidShares
        case randomGenerationFailed(OSStatus)

        var errorDescription: String? {
            switch self {
            case .invalidShares: "Choose two different valid Tagcrypt recovery shares."
            case .randomGenerationFailed(let status): "Secure random generation failed (status \(status))."
            }
        }
    }

    private static let magic = Data("TCS1".utf8)

    /// Splits an already-encrypted record. Any two of the three returned shares
    /// reconstruct the original bytes; one share alone reveals no bytes.
    static func split(_ encryptedRecord: Data) throws -> [String] {
        guard !encryptedRecord.isEmpty, encryptedRecord.count <= 1_000_000 else {
            throw ShareError.invalidShares
        }
        var coefficients = Data(count: encryptedRecord.count)
        let coefficientCount = coefficients.count
        let status = coefficients.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, coefficientCount, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw ShareError.randomGenerationFailed(status) }
        defer { coefficients.resetBytes(in: 0..<coefficients.count) }

        let setIdentifier = try randomData(count: 16)
        let length = UInt32(encryptedRecord.count).bigEndian
        let lengthData = withUnsafeBytes(of: length) { Data($0) }
        return (1...3).map { x in
            var share = magic + Data([UInt8(x)]) + lengthData + setIdentifier
            for index in encryptedRecord.indices {
                share.append(encryptedRecord[index] ^ multiply(coefficients[index], UInt8(x)))
            }
            return "TAGCRYPT-SHARE1:" + share.base64EncodedString()
        }
    }

    static func binaryData(from encodedShare: String) throws -> Data {
        let parsed = try parse(encodedShare)
        return parsed.bytes
    }

    static func isBinaryShare(_ data: Data) -> Bool {
        data.count >= 25 && data.starts(with: magic)
    }

    static func encodedShare(fromBinaryData data: Data) throws -> String {
        _ = try parse(data)
        return "TAGCRYPT-SHARE1:" + data.base64EncodedString()
    }

    /// Raw NTAG21x mode fills the entire user area. The share length field
    /// identifies its meaningful prefix; random tail bytes are ignored on read.
    static func encodedShare(fromRawPageMemory memory: Data) throws -> String {
        guard memory.count >= 25, memory.starts(with: magic) else { throw ShareError.invalidShares }
        let length = memory[5..<9].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= 1_000_000 else { throw ShareError.invalidShares }
        let shareLength = 25 + Int(length)
        guard shareLength <= memory.count else { throw ShareError.invalidShares }
        return try encodedShare(fromBinaryData: Data(memory.prefix(shareLength)))
    }

    static func paddedRawPageMemory(_ share: Data, byteCount: Int) throws -> Data {
        _ = try parse(share)
        guard byteCount >= share.count else { throw ShareError.invalidShares }
        var output = Data(count: byteCount)
        let status = output.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, raw.baseAddress!)
        }
        guard status == errSecSuccess else { throw ShareError.randomGenerationFailed(status) }
        output.replaceSubrange(0..<share.count, with: share)
        return output
    }

    static func combine(_ encodedShares: [String]) throws -> Data {
        guard encodedShares.count == 2 else { throw ShareError.invalidShares }
        let parsed = try encodedShares.map(parse)
        guard parsed[0].x != parsed[1].x,
              parsed[0].length == parsed[1].length,
              parsed[0].setIdentifier == parsed[1].setIdentifier,
              parsed[0].values.count == parsed[1].values.count,
              parsed[0].values.count == parsed[0].length else { throw ShareError.invalidShares }
        let x1 = parsed[0].x
        let x2 = parsed[1].x
        let denominator = x1 ^ x2
        guard denominator != 0 else { throw ShareError.invalidShares }
        let factor1 = divide(x2, denominator)
        let factor2 = divide(x1, denominator)
        var output = Data(count: parsed[0].length)
        for index in output.indices {
            output[index] = multiply(parsed[0].values[index], factor1) ^ multiply(parsed[1].values[index], factor2)
        }
        return output
    }

    private struct ParsedShare {
        let x: UInt8
        let length: Int
        let setIdentifier: Data
        let values: Data
        let bytes: Data
    }

    private static func parse(_ text: String) throws -> ParsedShare {
        let prefix = "TAGCRYPT-SHARE1:"
        guard text.hasPrefix(prefix),
              let data = Data(base64Encoded: String(text.dropFirst(prefix.count))) else { throw ShareError.invalidShares }
        return try parse(data)
    }

    private static func parse(_ data: Data) throws -> ParsedShare {
        guard data.count >= 25, data.starts(with: magic),
              (1...3).contains(data[4]) else { throw ShareError.invalidShares }
        let length = data[5..<9].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= 1_000_000, data.count == 25 + Int(length) else {
            throw ShareError.invalidShares
        }
        return ParsedShare(x: data[4], length: Int(length), setIdentifier: Data(data[9..<25]),
                           values: Data(data[25...]), bytes: data)
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw ShareError.randomGenerationFailed(status) }
        return data
    }

    private static func multiply(_ lhs: UInt8, _ rhs: UInt8) -> UInt8 {
        var a = lhs
        var b = rhs
        var result: UInt8 = 0
        for _ in 0..<8 {
            if b & 1 == 1 { result ^= a }
            let highBit = a & 0x80
            a <<= 1
            if highBit != 0 { a ^= 0x1b }
            b >>= 1
        }
        return result
    }

    private static func divide(_ numerator: UInt8, _ denominator: UInt8) -> UInt8 {
        guard numerator != 0 else { return 0 }
        return multiply(numerator, power(denominator, 254))
    }

    private static func power(_ value: UInt8, _ exponent: Int) -> UInt8 {
        var result: UInt8 = 1
        var base = value
        var power = exponent
        while power > 0 {
            if power & 1 == 1 { result = multiply(result, base) }
            base = multiply(base, base)
            power >>= 1
        }
        return result
    }
}
