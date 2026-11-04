import Foundation

let record = Data((0..<80).map(UInt8.init))
let shares = try TagcryptRecoveryShares.split(record)
precondition(shares.count == 3)
let binary = try TagcryptRecoveryShares.binaryData(from: shares[0])
let binaryRoundTrip = try TagcryptRecoveryShares.encodedShare(fromBinaryData: binary)
precondition(binaryRoundTrip == shares[0])
for pair in [[0, 1], [0, 2], [1, 2]] {
    let restored = try TagcryptRecoveryShares.combine([shares[pair[0]], shares[pair[1]]])
    precondition(restored == record, "share pair \(pair) failed to reconstruct")
}
let otherSet = try TagcryptRecoveryShares.split(Data(repeating: 0x5a, count: record.count))
do {
    _ = try TagcryptRecoveryShares.combine([shares[0], otherSet[1]])
    fatalError("shares from different sets must be rejected")
} catch TagcryptRecoveryShares.ShareError.invalidShares { }
do {
    _ = try TagcryptRecoveryShares.combine([shares[0], shares[0]])
    fatalError("duplicate shares must be rejected")
} catch TagcryptRecoveryShares.ShareError.invalidShares { }
let padded = try TagcryptRecoveryShares.paddedRawPageMemory(binary, byteCount: binary.count + 32)
let rawRoundTrip = try TagcryptRecoveryShares.encodedShare(fromRawPageMemory: padded)
precondition(rawRoundTrip == shares[0])
print("Tagcrypt Shamir share format and all 2-of-3 pairs passed.")
