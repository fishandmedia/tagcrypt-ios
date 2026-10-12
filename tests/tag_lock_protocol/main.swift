import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
}

let pwd = Data([0xBE, 0xBD, 0xC4, 0x23])
let pack = Data([0x24, 0xFA])
let models: [(NTAG21xProtocol.Model, UInt8, UInt8, UInt8, UInt8)] = [
    (.ntag213, 0x29, 0x2A, 0x2B, 0x2C),
    (.ntag215, 0x83, 0x84, 0x85, 0x86),
    (.ntag216, 0xE3, 0xE4, 0xE5, 0xE6)
]

for (model, config0, config1, password, packPage) in models {
    expect(model.config0Page == config0, "\(model.rawValue) CONFIG0 page")
    expect(model.config1Page == config1, "\(model.rawValue) CONFIG1 page")
    expect(model.passwordPage == password, "\(model.rawValue) PWD page")
    expect(model.packPage == packPage, "\(model.rawValue) PACK page")
    let configuration = NTAG21xProtocol.Configuration(config0: Data([0x00, 0x00, 0x00, 0xFF]),
                                                     config1: Data([0x28, 0x12, 0x34, 0x56]))!
    guard let writes = NTAG21xProtocol.passwordProvisioningWrites(
        model: model, credentials: TagLockCredentials(password: pwd, pack: pack), configuration: configuration
    ) else { fatalError("expected safe password provisioning writes for \(model.rawValue)") }
    expect(writes.map(\.page) == [password, packPage, config1, config0], "\(model.rawValue) safe page write order")
    expect(writes[0].bytes == pwd, "\(model.rawValue) PWD byte order")
    expect(writes[1].bytes == pack + Data([0, 0]), "\(model.rawValue) PACK page order and RFUI zeroing")
    expect(writes[2].bytes == Data([0x28, 0x12, 0x34, 0x56]), "\(model.rawValue) clear PROT and AUTHLIM while preserving unrelated config bits")
    expect(writes[3].bytes[3] == 4, "\(model.rawValue) AUTH0 enabled last at first user page")
    expect(NTAG21xProtocol.writePageCommand(page: password, data: pwd) != nil, "four-byte page write command is constructible")
}

// Decided on hardware 2026-10-11: Core NFC adds CRC_A, so Tagcrypt sends bare frames.
expect(NTAG21xProtocol.appendsCRC == false, "default is the bare frame (Core NFC appends CRC_A)")
expect(NTAG21xProtocol.passwordAuthCommand(password: pwd) == Data([0x1B, 0xBE, 0xBD, 0xC4, 0x23]), "PWD_AUTH is sent without CRC_A by default")
expect(NTAG21xProtocol.command([0x1B] + Array(pwd), appendingCRC: true) == Data([0x1B, 0xBE, 0xBD, 0xC4, 0x23, 0xB0, 0xB0]), "CRC_A computation is still correct for the fallback")
expect(NTAG21xProtocol.passwordAuthMatches(Data([0x24, 0xFA]), expectedPack: pack), "matching PACK authenticates")
expect(NTAG21xProtocol.passwordAuthMatches(pack + NTAG21xProtocol.crcA(for: pack), expectedPack: pack), "matching PACK with valid CRC authenticates")
expect(!NTAG21xProtocol.passwordAuthMatches(Data([0x24, 0xFB]), expectedPack: pack), "wrong PACK fails authentication")
expect(!NTAG21xProtocol.passwordAuthMatches(pack + Data([0, 0]), expectedPack: pack), "PACK with invalid CRC fails authentication")
expect(!NTAG21xProtocol.passwordAuthMatches(Data([0x24]), expectedPack: pack), "malformed PACK response fails authentication")
expect(NTAG21xProtocol.passwordProvisioningWrites(
    model: .ntag213, credentials: TagLockCredentials(password: pwd, pack: pack),
    configuration: NTAG21xProtocol.Configuration(config0: Data([0, 0, 0, 0xFF]), config1: Data([0x28, 0, 0, 0]))!
) != nil, "zero-AUTHLIM unprotected tag can be configured")
expect(NTAG21xProtocol.passwordProvisioningWrites(
    model: .ntag213, credentials: TagLockCredentials(password: pwd, pack: pack),
    configuration: NTAG21xProtocol.Configuration(config0: Data([0, 0, 0, 0xFF]), config1: Data([0x2B, 0, 0, 0]))!
) == nil, "nonzero AUTHLIM refuses candidate password provisioning")
let factoryCC = Data([0xE1, 0x10, 0x12, 0x00])
let openConfig = NTAG21xProtocol.Configuration(config0: Data([0x04, 0x00, 0x00, 0xFF]),
                                               config1: Data([0x00, 0x05, 0x00, 0x00]))!
let seal = NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: factoryCC,
                                                           staticLockBytes: Data([0, 0]),
                                                           dynamicLockBytes: Data([0, 0, 0]),
                                                           configuration: openConfig)
expect(seal?.writes.map(\.page) == [0x03, 0x28, 0x02, 0x2A], "NTAG213 seal order: CC, dynamic lock, static lock, CONFIG1")
expect(seal?.writes[0].bytes == Data([0xE1, 0x10, 0x12, 0x0F]), "CC access byte becomes read-only, other CC bytes unchanged")
expect(seal?.writes[1].bytes == Data([0xFF, 0x0F, 0x00, 0x00]), "NTAG213 dynamic lock bytes cover pages 16-39, RFUI zero")
expect(seal?.writes[2].bytes == Data([0x00, 0x00, 0xFE, 0xFF]), "NTAG213 static locks cover pages 4-15 and L_CC")
expect(seal?.writes[3].bytes == Data([0x40, 0x05, 0x00, 0x00]), "CONFIG1 sets CFGLCK and keeps other bits")
expect(seal?.expectedConfig1 == Data([0x40, 0x05, 0x00, 0x00]), "CONFIG1 read-back expectation")
expect(NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: factoryCC,
                                                      staticLockBytes: Data([0, 1]),
                                                      dynamicLockBytes: Data([0, 0, 0]),
                                                      configuration: openConfig) == nil,
       "partially locked NTAG213 refuses a guessed seal")
expect(NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: factoryCC,
                                                      staticLockBytes: Data([0, 0]),
                                                      dynamicLockBytes: Data([0, 0, 1]),
                                                      configuration: openConfig) == nil,
       "pre-set dynamic lock bits refuse a guessed seal")
expect(NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: Data([0xE1, 0x10, 0x3E, 0x00]),
                                                      staticLockBytes: Data([0, 0]),
                                                      dynamicLockBytes: Data([0, 0, 0]),
                                                      configuration: openConfig) == nil,
       "non-factory CC (wrong size byte) refuses the seal")
expect(NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: factoryCC,
                                                      staticLockBytes: Data([0, 0]),
                                                      dynamicLockBytes: Data([0, 0, 0]),
                                                      configuration: NTAG21xProtocol.Configuration(config0: Data([0, 0, 0, 0x04]), config1: Data([0, 0, 0, 0]))!) == nil,
       "password-protected tag (AUTH0 != FF) refuses the seal")
expect(NTAG21xProtocol.ntag213WholeUserMemorySealPlan(capabilityContainer: factoryCC,
                                                      staticLockBytes: Data([0, 0]),
                                                      dynamicLockBytes: Data([0, 0, 0]),
                                                      configuration: NTAG21xProtocol.Configuration(config0: Data([0, 0, 0, 0xFF]), config1: Data([0x40, 0, 0, 0]))!) == nil,
       "already-frozen configuration (CFGLCK set) refuses the seal")
// Configuration built from a 16-byte READ slice must not trap (index re-basing).
let read16 = Data([0, 0, 0, 0xFF, 0x2B, 0, 0, 0] + Array(repeating: UInt8(0), count: 8))
let sliced = NTAG21xProtocol.Configuration(config0: read16.prefix(4), config1: read16.dropFirst(4).prefix(4))!
expect(sliced.access == 0x2B && sliced.authLimit == 3 && sliced.auth0 == 0xFF, "Configuration decodes READ slices")
// CRC switch: command() follows appendsCRC; diagnostic frames are fixed.
expect(NTAG21xProtocol.getVersionWithoutCRC == Data([0x60]), "diagnostic GET_VERSION without CRC is one byte")
expect(NTAG21xProtocol.getVersionWithCRC.count == 3, "diagnostic GET_VERSION with CRC is three bytes")
expect(NTAG21xProtocol.command([0x60]) == (NTAG21xProtocol.appendsCRC ? NTAG21xProtocol.getVersionWithCRC : NTAG21xProtocol.getVersionWithoutCRC),
       "command() follows the single appendsCRC switch")
// Compatible tags: model from the Capability Container size byte.
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0xE1, 0x10, 0x12, 0x00])) == .ntag213, "CC 0x12 -> NTAG213")
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0xE1, 0x10, 0x3E, 0x00])) == .ntag215, "CC 0x3E -> NTAG215")
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0xE1, 0x10, 0x6D, 0x00])) == .ntag216, "CC 0x6D -> NTAG216")
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0x00, 0x10, 0x12, 0x00])) == nil, "CC without NDEF magic is not recognised")
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0xE1, 0x10, 0x20, 0x00])) == nil, "unknown CC size is not recognised")
expect(NTAG21xProtocol.model(fromCapabilityContainer: Data([0xE1, 0x10, 0x12, 0x00] + Array(repeating: UInt8(0), count: 12))) == .ntag213, "CC parsed from a 16-byte READ")
// Session CRC mode drives command().
NTAG21xProtocol.sessionAppendsCRC = false
expect(NTAG21xProtocol.command([0x60]) == Data([0x60]), "session without CRC sends the bare frame")
NTAG21xProtocol.sessionAppendsCRC = true
expect(NTAG21xProtocol.command([0x60]).count == 3, "session with CRC appends two bytes")
// Seal plans for NTAG215/216 (datasheet dynamic lock maps).
for (model, cc, dynPage, dyn, cfg1Page) in [(NTAG21xProtocol.Model.ntag215, Data([0xE1, 0x10, 0x3E, 0x00]), UInt8(0x82), Data([0xFF, 0x00, 0x00]), UInt8(0x84)),
                                            (.ntag216, Data([0xE1, 0x10, 0x6D, 0x00]), UInt8(0xE2), Data([0xFF, 0x3F, 0x00]), UInt8(0xE4))] {
    let plan = NTAG21xProtocol.wholeUserMemorySealPlan(model: model, capabilityContainer: cc,
                                                       staticLockBytes: Data([0, 0]), dynamicLockBytes: Data([0, 0, 0]),
                                                       configuration: openConfig)
    expect(plan?.writes.map(\.page) == [0x03, dynPage, 0x02, cfg1Page], "\(model.rawValue) seal pages: CC, dynamic, static, CONFIG1")
    expect(plan?.writes[0].bytes == cc.prefix(3) + Data([0x0F]), "\(model.rawValue) CC becomes read-only")
    expect(plan?.writes[1].bytes == dyn + Data([0]), "\(model.rawValue) dynamic lock bits cover pages 16 to the last user page")
    expect(NTAG21xProtocol.wholeUserMemorySealPlan(model: model, capabilityContainer: factoryCC,
                                                   staticLockBytes: Data([0, 0]), dynamicLockBytes: Data([0, 0, 0]),
                                                   configuration: openConfig) == nil, "\(model.rawValue) refuses another model's CC")
}
// NDEF encoding for the protected native rewrite.
let shortMsg = NTAG21xProtocol.ndefMessageBytes([.init(tnf: 0x02, type: Data("a/b".utf8), identifier: Data(), payload: Data([1, 2, 3]))])
expect(shortMsg == Data([0xD2, 0x03, 0x03]) + Data("a/b".utf8) + Data([1, 2, 3]), "short media record header MB|ME|SR|TNF=2")
let longMsg = NTAG21xProtocol.ndefMessageBytes([.init(tnf: 0x02, type: Data("t".utf8), identifier: Data(), payload: Data(count: 300))])
expect(longMsg.prefix(6) == Data([0xC2, 0x01, 0x00, 0x00, 0x01, 0x2C]), "long record uses a 4-byte payload length")
let tlv = NTAG21xProtocol.ndefTLVPages(message: shortMsg, model: .ntag213)!
expect(tlv.prefix(2) == Data([0x03, UInt8(shortMsg.count)]) && tlv[2 + shortMsg.count] == 0xFE && tlv.count % 4 == 0, "TLV wraps the message with FE and page padding")
let bigTLV = NTAG21xProtocol.ndefTLVPages(message: Data(count: 300), model: .ntag215)!
expect(bigTLV.prefix(4) == Data([0x03, 0xFF, 0x01, 0x2C]), "TLV uses the 3-byte length from 255 bytes")
expect(NTAG21xProtocol.ndefTLVPages(message: Data(count: 200), model: .ntag213) == nil, "TLV refuses a message larger than the tag")
print("Tag-lock protocol tests passed")
