import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

let key = Data((0..<32).map(UInt8.init))
let uid = Data([0x04, 0x29, 0x04, 0xB1, 0x70, 0x00, 0x00])
let credentials = try TagLockCrypto.credentials(masterKey: key, uid: uid)
expect(credentials.password == Data([0xBE, 0xBD, 0xC4, 0x23]), "matches HMAC known-answer PWD")
expect(credentials.pack == Data([0x24, 0xFA]), "matches HMAC known-answer PACK")
let otherUIDCredentials = try TagLockCrypto.credentials(masterKey: key, uid: Data([1, 2, 3, 4, 5, 6, 8]))
expect(otherUIDCredentials != credentials, "UID binds derived credentials")
let keyBundle = TagLockKeyBundle(autoKey: key,
                                 organisationKeys: [TagLockOrganisationKey(label: "Operations", key: key)])
let roundTripBundle = try JSONDecoder().decode(TagLockKeyBundle.self, from: JSONEncoder().encode(keyBundle))
expect(roundTripBundle == keyBundle, "encrypted-backup key bundle model round-trips")
let organisationOnly = [TagLockOrganisationKey(label: "Team", key: Data(repeating: 7, count: 32))]
expect(TagLockCredentialResolver.candidates(mode: .off, autoKey: key, organisationKeys: organisationOnly).isEmpty,
       "Off mode produces no candidate passwords")
let candidates = TagLockCredentialResolver.candidates(mode: .organisation, autoKey: key, organisationKeys: organisationOnly)
expect(candidates.map(\.source) == [.auto, .organisation(label: "Team")], "Auto candidate is tried before Organisation keys")
expect(candidates.map(\.masterKey) == [key, organisationOnly[0].key], "resolver uses only configured master keys")
expect(TagLockCredentialResolver.provisioningCandidate(mode: .auto, candidates: candidates)?.source == .auto,
       "Auto mode provisions new tags with the device key")
expect(TagLockCredentialResolver.provisioningCandidate(mode: .organisation, candidates: candidates)?.source == .organisation(label: "Team"),
       "Organisation mode provisions new tags with a shared Organisation key")
expect(TagLockCredentialResolver.provisioningCandidate(mode: .off, candidates: candidates) == nil,
       "Off mode never selects a provisioning key")
do {
    _ = try TagLockCrypto.credentials(masterKey: Data(repeating: 0, count: 31), uid: uid)
    fatalError("short master key should fail")
} catch TagLockCryptoError.invalidMasterKeyLength {}
do {
    _ = try TagLockCrypto.credentials(masterKey: key, uid: Data(repeating: 0, count: 8))
    fatalError("long UID should fail")
} catch TagLockCryptoError.invalidUIDLength {}
print("Tag-lock credential tests passed")
