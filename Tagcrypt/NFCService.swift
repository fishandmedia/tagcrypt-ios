@preconcurrency import CoreNFC
import Combine
import Foundation

enum NFCOverwritePolicy: String, CaseIterable, Identifiable {
    case warn
    case never
    case skip
    case always

    var id: String { rawValue }
    var title: String {
        switch self {
        case .warn: "Warn before replacing"
        case .never: "Never overwrite"
        case .skip: "Skip tags with data"
        case .always: "Always overwrite"
        }
    }
}

/// Core NFC truncates long sheet messages. Keep sheet text short; the full
/// explanation stays in the in-app status line and Settings.
enum NFCSheetText {
    static let tagKept = "Tag not changed. Existing data was kept."
    static let tagNotChanged = "Tag not changed."

    /// iOS cuts sheet text at about two lines. Keep short messages, else use
    /// the first sentence if it fits, else a pointer to the in-app status.
    static func short(_ message: String) -> String {
        let limit = 64
        if message.count <= limit { return message }
        if let end = message.firstIndex(of: "."), message.distance(from: message.startIndex, to: end) < limit {
            return String(message[...end])
        }
        return "Stopped. Details are in Tagcrypt."
    }
}

/// Tagcrypt's own outcome for the last NFC session. Core NFC offers only a
/// success tick (`invalidate()`) or an error X (`invalidate(errorMessage:)`);
/// a neutral "skipped" state can only be shown in the app after dismissal.
enum NFCSessionOutcome: Equatable {
    case written
    case read
    case skipped
    case failed
    case cancelled
}

enum VaultNDEFTextCodec {
    static let binaryMediaType = "application/vnd.tagcrypt.record"

    static func message(for text: String) -> NFCNDEFMessage {
        NFCNDEFMessage(records: [record(for: text)])
    }

    static func binaryMessage(for data: Data) -> NFCNDEFMessage {
        NFCNDEFMessage(records: [NFCNDEFPayload(format: .media, type: Data(binaryMediaType.utf8), identifier: Data(), payload: data)])
    }

    static func binaryShareMessage(for data: Data) -> NFCNDEFMessage {
        NFCNDEFMessage(records: [NFCNDEFPayload(format: .media, type: Data(TagcryptRecoveryShares.binaryMediaType.utf8), identifier: Data(), payload: data)])
    }

    static func binaryMessageLength(byteCount: Int) -> Int {
        binaryMessage(for: Data(count: max(0, byteCount))).length
    }

    static func binaryShareMessageLength(byteCount: Int) -> Int {
        binaryShareMessage(for: Data(count: max(0, byteCount))).length
    }

    static func maximumBinaryPayloadByteCount(fitting capacity: Int) -> Int {
        guard capacity > 0 else { return 0 }
        var low = 0
        var high = capacity
        while low < high {
            let middle = (low + high + 1) / 2
            if binaryMessageLength(byteCount: middle) <= capacity { low = middle }
            else { high = middle - 1 }
        }
        return low
    }

    /// Ask Core NFC for the real NDEF byte count, including the long-record
    /// payload-length field used once a Base64 Text record exceeds 255 bytes.
    static func messageLength(textLength: Int) -> Int {
        let placeholder = String(repeating: "A", count: max(0, textLength))
        return message(for: placeholder).length
    }

    private static func record(for text: String) -> NFCNDEFPayload {
        let language = Data("en".utf8)
        let textPayload = Data([UInt8(language.count)]) + language + Data(text.utf8)
        return NFCNDEFPayload(
            format: .nfcWellKnown,
            type: Data("T".utf8),
            identifier: Data(),
            payload: textPayload
        )
    }
}

/// Core NFC reader objects are callback-driven and remain confined to one reader session.
private final class NFCUncheckedBox<Value>: @unchecked Sendable {
    let value: Value
    init(_ value: Value) { self.value = value }
}

@MainActor
final class NFCService: NSObject, ObservableObject {
    private struct TagLockPlan {
        let writes: [NTAG21xProtocol.PageWrite]?
        let credentials: TagLockCredentials
        let alreadyProtected: Bool
    }
    @Published private(set) var status = "Ready to use an NFC tag."
    @Published private(set) var isScanning = false
    @Published private(set) var readerPresentationActive = false
    @Published private(set) var overwriteConfirmationNeeded = false
    @Published private(set) var sealConfirmationNeeded = false
    @Published private(set) var capacityAdaptationNeeded = false
    @Published private(set) var reportedNDEFCapacity: Int?
    @Published private(set) var requiredNDEFMessageBytes: Int?
    @Published private(set) var tagProtectionFallbackNeeded = false
    @Published private(set) var tagProtectionFallbackReason = ""
    @Published private(set) var lastOutcome: NFCSessionOutcome?
    /// Persistent warning after a verified NDEF write whose NTAG password
    /// setup stopped partway. Cleared only by the user or a later successful
    /// provisioning, so it survives the transient status line.
    @Published private(set) var tagPasswordSetupWarning: String?
    @Published private(set) var scannedTagSummary = "Scan a tag to identify its type, capacity, and available protection status."
    /// Advanced "Compatible tags" setting: identify tags whose GET_VERSION does
    /// not match NTAG213/215/216 from their Capability Container instead.
    var allowCompatibleTags = false
    var onRead: ((Data) -> Void)?
    var onRecoveryShare: ((String) -> Void)?
    var onWriteVerified: (() -> Void)?

    private var session: NFCTagReaderSession?
    private var writePayload: Data?
    private var pendingOverwriteTagIdentifier: Data?
    private var confirmedOverwriteTagIdentifier: Data?
    private var showOverwritePromptAfterInvalidation = false
    private var overwritePolicy: NFCOverwritePolicy = .warn
    private var wipeOldTagData = true
    private var rawPageMode = false
    private var tagLockMode: TagLockMode = .off
    private var tagLockCandidates: [TagLockCredentialCandidate] = []
    private var pendingFallbackTagIdentifier: Data?
    private var approvedNDEFOnlyTagIdentifier: Data?
    private var sealExpectedRecord: Data?
    private var sealApprovedTagIdentifier: Data?
    private var sealApprovedModel: NTAG21xProtocol.Model?
    private var crcDiagnosticActive = false
    private var removePasswordActive = false
    private var identifyOnlyActive = false
    /// Set by authenticateTag when it gives up because the reconnect failed (Review P2-7).
    private var lastAuthLostConnection = false
    /// Plain-language result of the last "Identify my tag" scan.
    @Published private(set) var identifyResult: String?
    /// NTAG size name ("NTAG213"/"NTAG215"/"NTAG216") matched by the last Identify scan, for auto-selecting the size picker.
    @Published private(set) var identifiedSizeName: String?
    /// Review P3-11: the last CRC diagnostic, kept (with its date) until the next diagnostic.
    @Published private(set) var lastCRCDiagnostic: String? = UserDefaults.standard.string(forKey: "tagcrypt.ntag.lastCRCDiagnostic")

    func read(rawPageMode: Bool = false) {
        guard NFCReaderSession.readingAvailable else {
            status = "NFC reading is not available on this device."
            return
        }
        writePayload = nil
        self.rawPageMode = rawPageMode
        beginSession(message: "Hold the top of your iPhone near the NFC tag to read it.")
    }

    func write(_ payload: Data, overwritePolicy: NFCOverwritePolicy = .warn, wipeOldTagData: Bool = true,
               rawPageMode: Bool = false, tagLockMode: TagLockMode = .off,
               tagLockCandidates: [TagLockCredentialCandidate] = []) {
        guard NFCReaderSession.readingAvailable else {
            status = "NFC writing is not available on this device."
            return
        }
        writePayload = payload
        pendingOverwriteTagIdentifier = nil
        confirmedOverwriteTagIdentifier = nil
        showOverwritePromptAfterInvalidation = false
        self.overwritePolicy = overwritePolicy
        self.wipeOldTagData = wipeOldTagData
        self.rawPageMode = rawPageMode
        self.tagLockMode = tagLockMode
        self.tagLockCandidates = tagLockCandidates
        capacityAdaptationNeeded = false
        reportedNDEFCapacity = nil
        requiredNDEFMessageBytes = nil
        tagProtectionFallbackNeeded = false
        tagProtectionFallbackReason = ""
        pendingFallbackTagIdentifier = nil
        approvedNDEFOnlyTagIdentifier = nil
        guard tagLockMode == .off || (!rawPageMode && !tagLockCandidates.isEmpty) else {
            status = rawPageMode
                ? "Tag password protection is not available in raw-page mode. No tag was changed."
                : "No usable tag-password key is available. Add or back up a key, or turn password mode Off. No tag was changed."
            return
        }
        beginSession(message: "Hold the top of your iPhone near a writable NFC tag.")
    }

    func setStatus(_ value: String) { status = value }

    /// Removes a TagCrypt tag password: PWD_AUTH with a known key, then AUTH0 =
    /// 0xFF (writable by any app), then PWD/PACK back to factory values, then
    /// read-back. Refused when the configuration is frozen (CFGLCK).
    func removeTagPassword(candidates: [TagLockCredentialCandidate]) {
        guard NFCReaderSession.readingAvailable else { status = "NFC reading is not available on this device."; return }
        guard !candidates.isEmpty else { status = "No tag-password key is stored on this iPhone, so no password can be removed."; return }
        writePayload = nil
        rawPageMode = false
        sealExpectedRecord = nil
        identifyOnlyActive = false
        tagLockCandidates = candidates
        removePasswordActive = true
        beginSession(message: "Hold the password-protected tag near the top of your iPhone.")
    }

    private func finishRemovePassword(mifareTag: NFCUncheckedBox<NFCMiFareTag>?, uid: Data,
                                      session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        func fail(_ message: String) {
            status = message
            lastOutcome = .failed
            isScanning = false
            session = nil
            sessionBox.value.invalidate(errorMessage: NFCSheetText.short(message))
        }
        guard let tag = mifareTag, uid.count == 7, let model = NFCService.sessionModel else {
            fail("This tag was not identified as an NTAG213/215/216. Nothing was changed."); return
        }
        tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { read, readError in
            Task { @MainActor in
                guard readError == nil, read.count >= 8,
                      let config = NTAG21xProtocol.Configuration(config0: read.prefix(4), config1: read.dropFirst(4).prefix(4)) else {
                    fail("The tag's configuration could not be read. Nothing was changed."); return
                }
                guard config.auth0 != 0xFF else { fail("This tag has no tag password. Nothing was changed."); return }
                guard config.access & 0x40 == 0 else { fail("This tag's configuration is permanently frozen, so its password cannot be removed."); return }
                guard config.authLimit == 0 else { fail("This tag limits password attempts (AUTHLIM). TagCrypt will not try keys on it."); return }
                let credentials = self.tagLockCandidates.compactMap { try? TagLockCrypto.credentials(masterKey: $0.masterKey, uid: uid) }
                self.authenticateTag(tag: tag, credentials: credentials, index: 0, session: sessionBox) { matched in
                    guard matched != nil else {
                        fail(self.lastAuthLostConnection
                             ? "The tag moved away while checking its password. Hold it still and scan again. Nothing was changed."
                             : "None of your keys matches this tag's password. Nothing was changed.")
                        return
                    }
                    var config0 = config.config0
                    config0[3] = 0xFF
                    let writes = [
                        NTAG21xProtocol.PageWrite(page: model.config0Page, bytes: config0),
                        NTAG21xProtocol.PageWrite(page: model.passwordPage, bytes: Data([0xFF, 0xFF, 0xFF, 0xFF])),
                        NTAG21xProtocol.PageWrite(page: model.packPage, bytes: Data([0, 0, 0, 0]))
                    ]
                    func writeNext(_ index: Int) {
                        guard index < writes.count else {
                            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { check, checkError in
                                Task { @MainActor in
                                    guard checkError == nil, check.count >= 4, check[3] == 0xFF else {
                                        fail("Password removal could not be verified. Scan the tag with Identify to check it."); return
                                    }
                                    self.status = "Tag password removed. Any app can write this tag again."
                                    self.lastOutcome = .written
                                    self.isScanning = false
                                    self.session = nil
                                    sessionBox.value.alertMessage = "Tag password removed."
                                    sessionBox.value.invalidate()
                                }
                            }
                            return
                        }
                        guard let command = NTAG21xProtocol.writePageCommand(page: writes[index].page, data: writes[index].bytes) else { return }
                        tag.value.sendMiFareCommand(commandPacket: command) { _, error in
                            Task { @MainActor in
                                if let error {
                                    fail(index == 0
                                        ? "Removing the password failed: \(error.localizedDescription). Nothing was changed."
                                        : "The password is off (AUTH0 cleared) but resetting the stored password failed. The tag is writable again.")
                                    return
                                }
                                writeNext(index + 1)
                            }
                        }
                    }
                    writeNext(0)
                }
            }
        }
    }

    /// "Identify my tag": a read-only scan that reports the chip, capacity,
    /// write/lock/password state and what is already stored. Never writes.
    func identifyTag() {
        guard NFCReaderSession.readingAvailable else { status = "NFC reading is not available on this device."; return }
        writePayload = nil
        rawPageMode = false
        sealExpectedRecord = nil
        crcDiagnosticActive = false
        identifyOnlyActive = true
        identifyResult = nil
        identifiedSizeName = nil
        beginSession(message: "Hold your tag near the top of your iPhone. This only reads it.")
    }

    /// Advanced, read-only (P1-1): sends GET_VERSION once with CRC_A and once
    /// without, reconnecting in between, and records both replies or error
    /// codes in `scannedTagSummary`. Never writes and never authenticates.
    func runCRCDiagnostic() {
        guard NFCReaderSession.readingAvailable else { status = "NFC reading is not available on this device."; return }
        writePayload = nil
        rawPageMode = false
        sealExpectedRecord = nil
        crcDiagnosticActive = true
        beginSession(message: "Hold a disposable NTAG tag near the top of your iPhone. This test only reads.")
    }

    func dismissTagPasswordSetupWarning() { tagPasswordSetupWarning = nil }

    func prepareWholeMemorySeal(for record: Data, tagLockMode: TagLockMode, rawPageMode: Bool) {
        guard NFCReaderSession.readingAvailable else { status = "NFC reading is not available on this device."; return }
        guard !rawPageMode, tagLockMode == .off else {
            status = "Turn off raw-page mode and NTAG password protection before sealing. No tag was changed."
            return
        }
        self.tagLockMode = .off
        self.tagLockCandidates = []
        sealExpectedRecord = record
        sealApprovedTagIdentifier = nil
        sealApprovedModel = nil
        beginSession(message: "Scan the tag holding this exact encrypted record to inspect it before sealing.")
    }

    func confirmWholeMemorySeal() {
        guard sealConfirmationNeeded, sealApprovedTagIdentifier != nil else { return }
        sealConfirmationNeeded = false
        beginSession(message: "Rescan the same tag to seal it permanently.")
    }

    func cancelWholeMemorySeal() {
        guard sealConfirmationNeeded else { return }
        sealConfirmationNeeded = false
        sealExpectedRecord = nil
        sealApprovedTagIdentifier = nil
        sealApprovedModel = nil
        status = "Seal cancelled. No lock bits were written."
    }

    func continueWithoutTagProtection() {
        guard tagProtectionFallbackNeeded, let identifier = pendingFallbackTagIdentifier else { return }
        tagProtectionFallbackNeeded = false
        pendingFallbackTagIdentifier = nil
        approvedNDEFOnlyTagIdentifier = identifier
        beginSession(message: "Hold the same tag near the top of your iPhone to write the encrypted NDEF record without tag password protection.")
    }

    func cancelTagProtectionFallback() {
        guard tagProtectionFallbackNeeded else { return }
        tagProtectionFallbackNeeded = false
        pendingFallbackTagIdentifier = nil
        approvedNDEFOnlyTagIdentifier = nil
        status = "Write cancelled. No NDEF record or tag-password settings were changed."
    }

    func dismissCapacityAdaptation() {
        capacityAdaptationNeeded = false
    }

    func readerPresentationDidDismiss() {
        readerPresentationActive = false
    }

    func confirmOverwrite() {
        guard overwriteConfirmationNeeded else { return }
        overwriteConfirmationNeeded = false
        guard let tagIdentifier = pendingOverwriteTagIdentifier else {
            status = "The overwrite confirmation expired. Tap Write prepared record to scan again."
            return
        }
        pendingOverwriteTagIdentifier = nil
        confirmedOverwriteTagIdentifier = tagIdentifier
        beginSession(message: "Hold the same NFC tag near the top of your iPhone to replace its data.")
    }

    func cancelOverwrite() {
        guard overwriteConfirmationNeeded else { return }
        overwriteConfirmationNeeded = false
        pendingOverwriteTagIdentifier = nil
        confirmedOverwriteTagIdentifier = nil
        showOverwritePromptAfterInvalidation = false
        status = "Write cancelled. Existing tag data was left unchanged. The prepared record is still available."
    }

    /// Read-only identification probe (P1-5). It runs to completion before any
    /// NDEF, raw-page or seal command is sent; a NAK or timeout here never
    /// aborts the main flow. It decides two things for the rest of the session:
    ///  - the CRC mode (P1-1): GET_VERSION with CRC_A first, then, after a
    ///    reconnect, without it; later commands use whichever worked;
    ///  - the tag model: from GET_VERSION, or, only when the user turned on
    ///    Compatible tags, from the Capability Container size byte.
    /// The summary never contains record contents or the full UID.
    private func inspectTag(_ tag: NFCUncheckedBox<NFCMiFareTag>, uidLength: Int,
                            session sessionBox: NFCUncheckedBox<NFCTagReaderSession>,
                            completion: @escaping @MainActor () -> Void) {
        NTAG21xProtocol.sessionAppendsCRC = NTAG21xProtocol.appendsCRC
        NFCService.sessionModel = nil
        NFCService.sessionModelFromCC = false
        NFCService.sessionAllowsCompatibleTags = allowCompatibleTags
        let family = NFCService.familyName(tag.value.mifareFamily)
        let base = "Core NFC family: MIFARE \(family) · UID \(uidLength) bytes"
        // The probe is read-only, so it also runs on tags Core NFC reports as
        // family "unknown" (common for clone stickers). Writes stay gated by
        // familyAllowed(), which needs Compatible tags for that family.
        guard tag.value.mifareFamily == .ultralight || tag.value.mifareFamily == .unknown else {
            scannedTagSummary = "\(base) · not probed (MIFARE \(family) is not a Type 2 tag). Advanced NTAG features are unavailable on this tag."
            completion()
            return
        }
        func finish(_ versionText: String, _ model: NTAG21xProtocol.Model?, fromCC: Bool) {
            guard let model else {
                // A failed native frame can leave the tag halted; reconnect
                // before the NDEF transaction (Review P1-8b).
                sessionBox.value.connect(to: .miFare(tag.value)) { _ in
                    Task { @MainActor in
                        self.scannedTagSummary = "\(base) · \(versionText) · model not identified\(self.allowCompatibleTags ? "" : " (turn on Compatible tags to identify it from its Capability Container)"). Use the reported NDEF capacity; password and lock status are unknown."
                        completion()
                    }
                }
                return
            }
            NFCService.sessionModel = model
            NFCService.sessionModelFromCC = fromCC
            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { config, configError in
                let protection = configError == nil ? NTAG21xProtocol.protection(fromConfigRead: config, model: model) : nil
                let configLocked = configError == nil && config.count >= 5 && config[4] & 0x40 != 0
                // Static lock bytes and CC (READ page 2 -> pages 2..5), read-only.
                tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: 0x02)) { lockRead, lockError in
                if lockError == nil, lockRead.count >= 8 {
                    let staticLocks = Data([lockRead[2], lockRead[3]])
                    let ccReadOnly = lockRead[7] == 0x0F
                    NFCService.sessionLockState = (ccReadOnly && staticLocks == Data([0xFE, 0xFF]) && configLocked) ? .sealed
                        : (ccReadOnly || staticLocks.contains { $0 != 0 } || configLocked) ? .partlyLocked : .open
                } else {
                    NFCService.sessionLockState = .unknown
                }
                Task { @MainActor in
                    let protectionText: String
                    if let protection {
                        let access = protection.protectsReads ? "read and write protection configured" : "write-only protection configured"
                        protectionText = protection.auth0 == 0xFF ? "no password protection detected" : "AUTH0 page \(protection.auth0), \(access)"
                    } else {
                        protectionText = "configuration unreadable, protection status unknown"
                    }
                    let crcText = NTAG21xProtocol.sessionAppendsCRC ? "CRC appended" : "no CRC"
                    let source = fromCC ? "model from Capability Container (compatible tag)" : "model from GET_VERSION"
                    self.scannedTagSummary = "\(base) · \(versionText) · \(crcText) · \(model.rawValue), \(model.userBytes) user bytes, \(source) · \(protectionText) · locks: \(NFCService.sessionLockState.rawValue). Not proof of genuine NXP silicon or secrecy."
                    completion()
                }
                }
            }
        }
        // GET_VERSION is optional on clones and a NAK drops the tag, so
        // reconnect before every fallback READ. READ is supported by every
        // Type 2 tag, which makes it the reliable way to learn the CRC mode.
        func inferFromCC(_ versionText: String) {
            func readCC(appendingCRC: Bool, _ done: @escaping (Data?) -> Void) {
                sessionBox.value.connect(to: .miFare(tag.value)) { reconnectError in
                    guard reconnectError == nil else { done(nil); return }
                    tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.command([0x30, 0x03], appendingCRC: appendingCRC)) { ccRead, ccError in
                        done(ccError == nil && ccRead.count >= 4 ? Data(ccRead.prefix(4)) : nil)
                    }
                }
            }
            func handle(_ cc: Data?, crc: Bool, _ tried: String) {
                guard let cc else { finish(versionText + " · READ failed \(tried)", nil, fromCC: false); return }
                NTAG21xProtocol.sessionAppendsCRC = crc
                let ccModel = NTAG21xProtocol.model(fromCapabilityContainer: cc)
                NFCService.sessionCCModel = ccModel
                let text = versionText + " · READ ok \(crc ? "with" : "without") CRC · CC \(NFCService.hex(cc))"
                guard let ccModel else { finish(text + " (not an NTAG21x size)", nil, fromCC: false); return }
                guard NFCService.sessionAllowsCompatibleTags else {
                    finish(text + " (sized like \(ccModel.rawValue); Compatible tags is off)", nil, fromCC: false)
                    return
                }
                finish(text, ccModel, fromCC: true)
            }
            readCC(appendingCRC: false) { cc in
                if cc != nil { handle(cc, crc: false, ""); return }
                readCC(appendingCRC: true) { ccWithCRC in
                    handle(ccWithCRC, crc: true, "with and without CRC")
                }
            }
        }
        // Bare frame first: field evidence (and NFC Tools identifying Can's
        // clone NTAG215 on iOS) says Core NFC adds CRC_A itself, and a malformed
        // first frame halts the tag for the rest of the session even after a
        // reconnect. The CRC-appended frame is only the fallback.
        tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.command([0x60], appendingCRC: false)) { version, error in
            if error == nil, let model = NTAG21xProtocol.model(fromGetVersion: version) {
                NTAG21xProtocol.sessionAppendsCRC = false
                finish("GET_VERSION \(NFCService.hex(version)) (no CRC)", model, fromCC: false)
                return
            }
            let firstText = error.map { "GET_VERSION error \(NFCService.errorCode($0))" } ?? "GET_VERSION \(NFCService.hex(version))"
            sessionBox.value.connect(to: .miFare(tag.value)) { reconnectError in
                if reconnectError != nil { finish(firstText + " · reconnect failed", nil, fromCC: false); return }
                tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.command([0x60], appendingCRC: true)) { crcVersion, crcError in
                    let crcText = crcError.map { "+CRC error \(NFCService.errorCode($0))" } ?? "+CRC \(NFCService.hex(crcVersion))"
                    if crcError == nil, let model = NTAG21xProtocol.model(fromGetVersion: crcVersion) {
                        NTAG21xProtocol.sessionAppendsCRC = true
                        finish("\(firstText) · \(crcText)", model, fromCC: false)
                        return
                    }
                    inferFromCC("\(firstText) · \(crcText)")
                }
            }
        }
    }

    /// Model identified by this session's probe (GET_VERSION, or the CC when
    /// Compatible tags is on). Every later NTAG flow in the session uses it
    /// instead of re-sending GET_VERSION.
    nonisolated(unsafe) static var sessionModel: NTAG21xProtocol.Model?
    nonisolated(unsafe) static var sessionModelFromCC = false
    /// Model implied by the CC size byte, recorded even when Compatible tags is
    /// off (informational only, for Identify my tag).
    nonisolated(unsafe) static var sessionCCModel: NTAG21xProtocol.Model?
    enum LockState: String { case unknown, open, partlyLocked = "partly locked", sealed }
    nonisolated(unsafe) static var sessionLockState: LockState = .unknown
    nonisolated(unsafe) static var sessionAllowsCompatibleTags = false

    nonisolated static func familyAllowed(_ tag: NFCMiFareTag) -> Bool {
        tag.mifareFamily == .ultralight || (sessionAllowsCompatibleTags && tag.mifareFamily == .unknown)
    }

    private func performCRCDiagnostic(tag tagBox: NFCUncheckedBox<NFCTag>,
                                      mifareTag: NFCUncheckedBox<NFCMiFareTag>?, uidLength: Int,
                                      session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        guard let mifareTag else {
            scannedTagSummary = "CRC diagnostic · not a MIFARE/Type 2 tag (ISO 7816, ISO 15693 or FeliCa) · UID \(uidLength) bytes · not run."
            status = scannedTagSummary
            lastOutcome = .failed
            isScanning = false
            session = nil
            sessionBox.value.invalidate(errorMessage: NFCSheetText.short("Not a Type 2 tag. Nothing was sent."))
            return
        }
        // Bare frames first: a CRC-appended frame halts these tags for the rest
        // of the session, so it is sent last.
        func readP3(_ crc: Bool, _ done: @escaping (String) -> Void) {
            mifareTag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.command([0x30, 0x03], appendingCRC: crc)) { reply, error in
                if let error { done("error \(NFCService.errorCode(error))"); return }
                done("\(NFCService.hex(Data(reply.prefix(4)))) (\(reply.count) bytes)")
            }
        }
        func reconnectThen(_ next: @escaping () -> Void, failed: @escaping (String) -> Void) {
            sessionBox.value.connect(to: tagBox.value) { err in
                if let err { failed("reconnect failed \(NFCService.errorCode(err))") } else { next() }
            }
        }
        let family = NFCService.familyName(mifareTag.value.mifareFamily)
        mifareTag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.getVersionWithoutCRC) { bareReply, bareError in
            let bareVersion = NFCService.describeDiagnosticReply(bareReply, bareError)
            reconnectThen({
                readP3(false) { bareRead in
                    reconnectThen({
                        mifareTag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.getVersionWithCRC) { crcReply, crcError in
                            let crcVersion = NFCService.describeDiagnosticReply(crcReply, crcError)
                            Task { @MainActor in
                                self.finishCRCDiagnostic("without CRC: \(bareVersion) · READ p3 without CRC: \(bareRead) · GET_VERSION with CRC: \(crcVersion)",
                                                         uidLength: uidLength, family: family, session: sessionBox)
                            }
                        }
                    }, failed: { text in
                        Task { @MainActor in
                            self.finishCRCDiagnostic("without CRC: \(bareVersion) · READ p3 without CRC: \(bareRead) · with CRC: \(text)",
                                                     uidLength: uidLength, family: family, session: sessionBox)
                        }
                    })
                }
            }, failed: { text in
                Task { @MainActor in
                    self.finishCRCDiagnostic("without CRC: \(bareVersion) · \(text)",
                                             uidLength: uidLength, family: family, session: sessionBox)
                }
            })
        }
    }

    nonisolated static func describeDiagnosticReply(_ reply: Data, _ error: Error?) -> String {
        if let error { return "error \(errorCode(error))" }
        let model = NTAG21xProtocol.model(fromGetVersion: reply)?.rawValue ?? "no model match"
        return "\(hex(reply)) (\(reply.count) bytes, \(model))"
    }

    private func finishCRCDiagnostic(_ result: String, uidLength: Int, family: String,
                                     session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        scannedTagSummary = "CRC diagnostic (read-only) · Core NFC family: \(family) · UID \(uidLength) bytes · GET_VERSION \(result) · app default: \(NTAG21xProtocol.appendsCRC ? "appends CRC" : "no CRC")"
        status = "CRC diagnostic finished. Record the result shown under Tag details; nothing was written."
        let stamp = Date().formatted(date: .abbreviated, time: .shortened)
        lastCRCDiagnostic = "\(stamp) · \(scannedTagSummary)"
        UserDefaults.standard.set(lastCRCDiagnostic, forKey: "tagcrypt.ntag.lastCRCDiagnostic")
        lastOutcome = .read
        isScanning = false
        session = nil
        sessionBox.value.alertMessage = "Diagnostic finished. Nothing was written."
        sessionBox.value.invalidate()
    }

    private func finishIdentify(ndefTag: NFCUncheckedBox<NFCNDEFTag>, mifareTag: NFCUncheckedBox<NFCMiFareTag>?,
                                uid: Data, session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        let isoDep = mifareTag?.value.historicalBytes != nil
        let chip: String
        if let model = NFCService.sessionModel {
            chip = NFCService.sessionModelFromCC
                ? "Behaves like an \(model.rawValue) (identified from its header; probably not genuine NXP)"
                : "\(model.rawValue) (\(model.userBytes) bytes of user memory)"
        } else if let ccModel = NFCService.sessionCCModel {
            chip = "Sized like an \(ccModel.rawValue), chip not confirmed (no GET_VERSION; typical of clones). Turn on Compatible tags to use advanced features."
        } else if isoDep {
            chip = "ISO 14443-4 chip, not an NTAG. Ordinary encrypted records work; tag password, raw pages and the seal do not."
        } else if let mifareTag {
            chip = mifareTag.value.mifareFamily == .unknown || mifareTag.value.mifareFamily == .ultralight
                ? "Type 2 tag, exact chip unknown (common for clone stickers)"
                : "MIFARE \(NFCService.familyName(mifareTag.value.mifareFamily)), not an NTAG21x"
        } else {
            chip = "Not a Type 2 tag (ISO 7816, ISO 15693 or FeliCa)"
        }
        NFCService.queryNDEFStatusRetrying(ndefTag, session: sessionBox) { ndefStatus, capacity, statusError in
            let statusText: String
            switch ndefStatus {
            case .readWrite: statusText = "Writable"
            case .readOnly: statusText = "Read-only (locked)"
            case .notSupported: statusText = "Not NDEF-formatted; iPhone cannot use it"
            @unknown default: statusText = "Unknown"
            }
            let finish: (String) -> Void = { contents in
                Task { @MainActor in
                    var lines = ["Chip: \(chip)", "Maker: \(NFCService.makerName(uid.first))"]
                    if statusError == nil {
                        lines.append("NDEF: \(statusText), \(capacity) bytes usable")
                        if ndefStatus != .notSupported {
                            lines.append("Fits: \(capacity >= 400 ? "long records" : capacity >= 130 ? "short records and shares" : "very short records only")")
                        }
                    } else {
                        lines.append("NDEF: could not read status")
                    }
                    let summary = self.scannedTagSummary
                    if summary.contains("no password protection detected") { lines.append("Password: none") }
                    else if summary.contains("AUTH0 page") { lines.append("Password: set (write-protected; only the matching key can rewrite it)") }
                    else { lines.append("Password: unknown on this chip") }
                    switch NFCService.sessionLockState {
                    case .sealed: lines.append("Sealed: yes, permanently read-only")
                    case .partlyLocked: lines.append("Sealed: partly (some lock bits set)")
                    case .open: lines.append("Sealed: no")
                    case .unknown: break
                    }
                    lines.append("Contents: \(contents)")
                    self.identifyResult = lines.joined(separator: "\n")
                    if let model = NFCService.sessionModel ?? NFCService.sessionCCModel {
                        self.identifiedSizeName = model.rawValue
                    } else if statusError == nil, ndefStatus != .notSupported {
                        self.identifiedSizeName = capacity >= 800 ? "NTAG216" : capacity >= 450 ? "NTAG215" : capacity >= 120 ? "NTAG213" : nil
                    }
                    self.status = "Tag identified. Nothing was written."
                    self.lastOutcome = .read
                    self.isScanning = false
                    self.session = nil
                    sessionBox.value.alertMessage = "Tag identified. Nothing was written."
                    sessionBox.value.invalidate()
                }
            }
            guard statusError == nil, ndefStatus != .notSupported else { finish("unknown"); return }
            ndefTag.value.readNDEF { message, readError in
                if (readError as? NFCReaderError)?.code == .ndefReaderSessionErrorZeroLengthMessage || message?.records.isEmpty == true {
                    finish("empty"); return
                }
                guard readError == nil, let message else { finish("could not be read"); return }
                let isTagcrypt = message.records.contains { record in
                    if record.typeNameFormat == .media,
                       let type = String(data: record.type, encoding: .utf8),
                       type == VaultNDEFTextCodec.binaryMediaType || type == TagcryptRecoveryShares.binaryMediaType { return true }
                    if let text = record.wellKnownTypeTextPayload().0, let data = Data(base64Encoded: text) {
                        return VaultCrypto.isTagcryptRecord(data)
                    }
                    return false
                }
                finish(isTagcrypt ? "a Tagcrypt encrypted record (\(message.length) bytes)"
                                  : "\(message.records.count) other NDEF record\(message.records.count == 1 ? "" : "s") (\(message.length) bytes)")
            }
        }
    }

    private func appendCapacityToSummary(_ capacity: Int) {
        guard !scannedTagSummary.contains("reported NDEF capacity") else { return }
        scannedTagSummary += " · reported NDEF capacity \(capacity) bytes"
    }

    private func beginSession(message: String) {
        guard let newSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil) else {
            status = "Could not start an NFC reader session."
            return
        }
        newSession.alertMessage = message
        session = newSession
        lastOutcome = nil
        NFCService.sessionModel = nil
        NFCService.sessionModelFromCC = false
        NFCService.sessionCCModel = nil
        NFCService.sessionLockState = .unknown
        NTAG21xProtocol.sessionAppendsCRC = NTAG21xProtocol.appendsCRC
        isScanning = true
        readerPresentationActive = true
        status = message
        newSession.begin()
    }

}

extension NFCService: NFCTagReaderSessionDelegate {
    nonisolated func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Task { @MainActor in
            // Keep a terminal read/write result instead of replacing it with Core NFC's
            // expected invalidation callback after invalidate() is called on success.
            guard self.isScanning else {
                self.session = nil
                if self.showOverwritePromptAfterInvalidation {
                    self.showOverwritePromptAfterInvalidation = false
                    self.overwriteConfirmationNeeded = true
                }
                return
            }
            self.isScanning = false
            self.session = nil
            if let nfcError = error as? NFCReaderError, nfcError.code == .readerSessionInvalidationErrorUserCanceled {
                self.confirmedOverwriteTagIdentifier = nil
                self.writePayload = nil
                if self.sealExpectedRecord != nil {
                    self.sealExpectedRecord = nil
                    self.sealApprovedTagIdentifier = nil
                    self.sealApprovedModel = nil
                    self.sealConfirmationNeeded = false
                }
                self.lastOutcome = .cancelled
                self.crcDiagnosticActive = false
                self.identifyOnlyActive = false
                self.removePasswordActive = false
                self.status = "NFC session cancelled."
            } else {
                self.confirmedOverwriteTagIdentifier = nil
                self.pendingOverwriteTagIdentifier = nil
                self.showOverwritePromptAfterInvalidation = false
                self.writePayload = nil
                self.lastOutcome = .failed
                self.status = "NFC session ended: \(error.localizedDescription)"
            }
        }
    }

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else { return }
        let sessionBox = NFCUncheckedBox(session)
        let tagBox = NFCUncheckedBox(tag)
        Task { @MainActor in self.status = "NFC tag detected. Connecting…" }
        sessionBox.value.connect(to: tagBox.value) { error in
            if let error {
                sessionBox.value.invalidate(errorMessage: NFCSheetText.short("Could not connect to tag: \(error.localizedDescription)"))
                return
            }
            let ndefTag: NFCNDEFTag
            let mifareTag: NFCMiFareTag?
            let tagIdentifier: Data
            switch tagBox.value {
            case let .miFare(tag):
                ndefTag = tag
                mifareTag = tag
                tagIdentifier = tag.identifier
            case let .iso7816(tag):
                ndefTag = tag
                mifareTag = nil
                tagIdentifier = tag.identifier
            case let .iso15693(tag):
                ndefTag = tag
                mifareTag = nil
                tagIdentifier = tag.identifier
            case let .feliCa(tag):
                ndefTag = tag
                mifareTag = nil
                tagIdentifier = tag.currentIDm
            @unknown default:
                sessionBox.value.invalidate(errorMessage: NFCSheetText.short("This NFC tag type is not supported."))
                return
            }
            let ndefTagBox = NFCUncheckedBox(ndefTag)
            let mifareTagBox = mifareTag.map(NFCUncheckedBox.init)
            Task { @MainActor in
                if self.crcDiagnosticActive {
                    self.crcDiagnosticActive = false
                    self.performCRCDiagnostic(tag: tagBox, mifareTag: mifareTagBox,
                                              uidLength: tagIdentifier.count, session: sessionBox)
                    return
                }
                self.scannedTagSummary = "Identifying NFC tag…"
                guard let mifareTagBox else {
                    self.scannedTagSummary = "Not a MIFARE tag · UID \(tagIdentifier.count) bytes · NDEF only."
                    self.continueAfterProbe(ndefTag: ndefTagBox, mifareTag: nil,
                                            tagIdentifier: tagIdentifier, session: sessionBox)
                    return
                }
                // P1-8: ordinary NDEF reads and writes send no native command.
                // The probe runs only for flows that need the chip model.
                guard self.needsNativeProbe else {
                    NFCService.resetSessionProbeState()
                    self.scannedTagSummary = "Core NFC family: MIFARE \(NFCService.familyName(mifareTagBox.value.mifareFamily)) · UID \(tagIdentifier.count) bytes · not probed (no advanced tag feature in use). NDEF only."
                    self.continueAfterProbe(ndefTag: ndefTagBox, mifareTag: mifareTagBox,
                                            tagIdentifier: tagIdentifier, session: sessionBox)
                    return
                }
                self.inspectTag(mifareTagBox, uidLength: tagIdentifier.count, session: sessionBox) {
                    self.continueAfterProbe(ndefTag: ndefTagBox, mifareTag: mifareTagBox,
                                            tagIdentifier: tagIdentifier, session: sessionBox)
                }
            }
        }
    }

    /// True when this session needs the chip model (native NTAG commands).
    /// Plain NDEF read/write with every advanced feature Off sends no native
    /// frame at all (Review P1-8). Tag-lock candidates count because a tag that
    /// already has a password must be unlocked before any write.
    private var needsNativeProbe: Bool {
        if removePasswordActive || identifyOnlyActive || sealExpectedRecord != nil || rawPageMode { return true }
        guard writePayload != nil else { return false }
        return wipeOldTagData || tagLockMode != .off || !tagLockCandidates.isEmpty
    }

    static func resetSessionProbeState() {
        NTAG21xProtocol.sessionAppendsCRC = NTAG21xProtocol.appendsCRC
        sessionModel = nil
        sessionModelFromCC = false
        sessionCCModel = nil
        sessionLockState = .unknown
    }

    /// Main flow, chained from the identification probe's completion so the two
    /// command chains never interleave on one tag (P1-5).
    private func continueAfterProbe(ndefTag ndefTagBox: NFCUncheckedBox<NFCNDEFTag>,
                                    mifareTag mifareTagBox: NFCUncheckedBox<NFCMiFareTag>?,
                                    tagIdentifier: Data,
                                    session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
                if self.removePasswordActive {
                    self.removePasswordActive = false
                    self.finishRemovePassword(mifareTag: mifareTagBox, uid: tagIdentifier, session: sessionBox)
                    return
                }
                if self.identifyOnlyActive {
                    self.identifyOnlyActive = false
                    self.finishIdentify(ndefTag: ndefTagBox, mifareTag: mifareTagBox,
                                        uid: tagIdentifier, session: sessionBox)
                    return
                }
                if self.sealExpectedRecord != nil {
                    guard let mifareTagBox else {
                        self.finishSealFailure("This is not a supported NTAG21x tag. No lock bits were written.", session: sessionBox)
                        return
                    }
                    self.inspectOrSealTag(tag: mifareTagBox, ndefTag: ndefTagBox,
                                          identifier: tagIdentifier, session: sessionBox)
                    return
                }
                if self.rawPageMode {
                    guard let mifareTagBox else {
                        self.finishRawFailure("Raw-page mode requires a MIFARE Ultralight-compatible NTAG21x tag. No data was changed.", session: sessionBox)
                        return
                    }
                    self.status = "Checking supported NTAG21x raw-page storage…"
                    self.handleRawPageMode(tag: mifareTagBox, tagIdentifier: tagIdentifier, session: sessionBox)
                    return
                }
                self.status = "Tag connected. Checking NDEF write support and capacity…"
                NFCService.queryNDEFStatusRetrying(ndefTagBox, session: sessionBox) { status, capacity, error in
                if let error {
                    sessionBox.value.invalidate(errorMessage: NFCSheetText.short("Could not read tag status: \(error.localizedDescription)"))
                    return
                }
                Task { @MainActor in
                    let pendingWrite = self.writePayload
                    self.status = "NDEF status: \(self.statusDescription(status)); capacity: \(capacity) bytes."
                    self.appendCapacityToSummary(capacity)
                    guard pendingWrite == nil || status == .readWrite else {
                        self.status = "Tag reports NDEF \(self.statusDescription(status)); it is not writable through NDEF."
                        self.isScanning = false
                        self.session = nil
                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                        return
                    }
                    guard let payload = pendingWrite else {
                        ndefTagBox.value.readNDEF { message, error in
                            if let error {
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.short("Could not read tag: \(error.localizedDescription)"))
                                return
                            }
                            if let share = message?.records.lazy.compactMap({ record -> String? in
                                guard record.typeNameFormat == .media,
                                      String(data: record.type, encoding: .utf8) == TagcryptRecoveryShares.binaryMediaType else { return nil }
                                return try? TagcryptRecoveryShares.encodedShare(fromBinaryData: record.payload)
                            }).first {
                                Task { @MainActor in
                                    self.onRecoveryShare?(share)
                                    self.lastOutcome = .read
                                    self.status = "NDEF recovery share read. Scan a second share or reconstruct the encrypted record."
                                    self.isScanning = false
                                    self.session = nil
                                    sessionBox.value.alertMessage = "Recovery share read."
                                    sessionBox.value.invalidate()
                                }
                                return
                            }
                            let portableRecord = message?.records.lazy.compactMap { ndefRecord -> Data? in
                                if ndefRecord.typeNameFormat == .media,
                                   String(data: ndefRecord.type, encoding: .utf8) == VaultNDEFTextCodec.binaryMediaType,
                                   VaultCrypto.isTagcryptRecord(ndefRecord.payload) {
                                    return ndefRecord.payload
                                }
                                guard let text = ndefRecord.wellKnownTypeTextPayload().0,
                                      let decoded = Data(base64Encoded: text),
                                      VaultCrypto.isTagcryptRecord(decoded) else { return nil }
                                return decoded
                            }.first
                            guard let record = portableRecord else {
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.short("No Tagcrypt encrypted record was found on this tag."))
                                return
                            }
                            Task { @MainActor in
                                self.onRead?(record)
                                self.lastOutcome = .read
                                self.status = "NDEF record read. Enter the matching vault passphrase to decrypt it."
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.alertMessage = "Encrypted Tagcrypt record read."
                                sessionBox.value.invalidate()
                            }
                        }
                        return
                    }
                    let ndefMessage: NFCNDEFMessage
                    if TagcryptRecoveryShares.isBinaryShare(payload) {
                        ndefMessage = VaultNDEFTextCodec.binaryShareMessage(for: payload)
                    } else {
                        ndefMessage = VaultCrypto.isV7Record(payload)
                            ? VaultNDEFTextCodec.binaryMessage(for: payload)
                            : VaultNDEFTextCodec.message(for: payload.base64EncodedString())
                    }
                    let ndefMessageBox = NFCUncheckedBox(ndefMessage)
                    let ndefMessageLength = ndefMessageBox.value.length
                    guard ndefMessageLength <= capacity else {
                        self.reportedNDEFCapacity = capacity
                        self.requiredNDEFMessageBytes = ndefMessageLength
                        self.capacityAdaptationNeeded = !self.rawPageMode
                        self.status = "NDEF record needs \(ndefMessageLength) bytes; this tag reports \(capacity). No data was written."
                        self.isScanning = false
                        self.session = nil
                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                        return
                    }
                    self.status = "Checking existing tag data before writing…"
                    ndefTagBox.value.readNDEF { existingMessage, readError in
                        let isFormattedEmptyTag = (readError as? NFCReaderError)?.code == .ndefReaderSessionErrorZeroLengthMessage
                        guard readError == nil || isFormattedEmptyTag else {
                            Task { @MainActor in
                                let detail = readError?.localizedDescription ?? "Unknown tag read error."
                                self.status = "Could not check existing tag data. Nothing was written: \(detail)"
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                            }
                            return
                        }
                        Task { @MainActor in
                            let writeAction = {
                                if let approvedIdentifier = self.approvedNDEFOnlyTagIdentifier {
                                    guard approvedIdentifier == tagIdentifier else {
                                        self.approvedNDEFOnlyTagIdentifier = nil
                                        self.status = "This is not the tag approved for an unprotected NDEF write. Nothing was written."
                                        self.isScanning = false
                                        self.session = nil
                                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                                        return
                                    }
                                    self.approvedNDEFOnlyTagIdentifier = nil
                                    self.writeAndVerify(ndefMessageBox.value, byteCount: ndefMessageLength,
                                                        tag: ndefTagBox, mifareTag: mifareTagBox,
                                                        session: sessionBox, wipeOldTagData: false,
                                                        tagLockPlan: nil)
                                    return
                                }
                                self.prepareTagLock(tag: mifareTagBox, uid: tagIdentifier, session: sessionBox) { plan, error in
                                    if error == NFCService.authConnectionLost {
                                        self.status = "The tag moved away while checking its password. Hold it still and scan again. Nothing was written."
                                        self.lastOutcome = .failed
                                        self.isScanning = false
                                        self.session = nil
                                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                                        return
                                    }
                                    if error == NFCService.lockedByAnotherKey {
                                        // P2-3: the tag is write-protected by a key this device does not
                                        // hold, so an NDEF-only write would fail. Offer no fallback.
                                        self.status = "This tag is locked by another key. Nothing was written."
                                        self.lastOutcome = .failed
                                        self.isScanning = false
                                        self.session = nil
                                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                                        return
                                    }
                                    guard error == nil else {
                                        self.tagProtectionFallbackReason = error!
                                        self.pendingFallbackTagIdentifier = tagIdentifier
                                        self.tagProtectionFallbackNeeded = true
                                        self.status = "Tag protection is unavailable on this tag. Choose encrypted NDEF only or cancel; no write has happened yet."
                                        self.isScanning = false
                                        self.session = nil
                                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                                        return
                                    }
                                    self.writeAndVerify(ndefMessageBox.value, byteCount: ndefMessageLength,
                                                        tag: ndefTagBox, mifareTag: mifareTagBox,
                                                        session: sessionBox, wipeOldTagData: self.wipeOldTagData,
                                                        tagLockPlan: plan)
                                }
                            }
                            let hasExistingContent = existingMessage?.records.contains {
                                $0.typeNameFormat != .empty
                            } ?? false
                            if let confirmedIdentifier = self.confirmedOverwriteTagIdentifier,
                               confirmedIdentifier != tagIdentifier {
                                self.confirmedOverwriteTagIdentifier = nil
                                self.status = "The scanned tag is different from the tag you approved. Nothing was written. Tap Write prepared record to start again."
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                            } else if hasExistingContent && !isFormattedEmptyTag && self.overwritePolicy == .never {
                                self.confirmedOverwriteTagIdentifier = nil
                                self.status = "This tag already contains data. Your Never overwrite setting left it unchanged and stopped the write."
                                self.writePayload = nil
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.tagKept)
                            } else if hasExistingContent && !isFormattedEmptyTag && self.overwritePolicy == .skip {
                                self.confirmedOverwriteTagIdentifier = nil
                                self.status = "Tag skipped: it already contains data, so it was left unchanged. No data was written."
                                self.writePayload = nil
                                self.lastOutcome = .skipped
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.alertMessage = NFCSheetText.tagNotChanged
                                sessionBox.value.invalidate()
                            } else if hasExistingContent && !isFormattedEmptyTag && self.overwritePolicy == .warn &&
                                        self.confirmedOverwriteTagIdentifier == nil {
                                self.pendingOverwriteTagIdentifier = tagIdentifier
                                self.showOverwritePromptAfterInvalidation = true
                                self.status = "Existing NDEF data found. Confirm replacement in Tagcrypt, then scan the same tag again."
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.alertMessage = "Existing data found. Confirm replacement in Tagcrypt, then scan the same tag again."
                                sessionBox.value.invalidate()
                            } else {
                                self.confirmedOverwriteTagIdentifier = nil
                                writeAction()
                            }
                        }
                    }
                }
                }
    }

    private func handleRawPageMode(tag: NFCUncheckedBox<NFCMiFareTag>, tagIdentifier: Data,
                                   session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        guard NFCService.familyAllowed(tag.value) else {
            finishRawFailure("Raw-page mode currently supports only identified NTAG213/215/216 tags.", session: sessionBox)
            return
        }
        do {
            guard let model = NFCService.sessionModel else {
                finishRawFailure("This tag was not identified as NTAG213/215/216\(allowCompatibleTags ? "" : " (Compatible tags is off)"). No raw pages were read or written.", session: sessionBox)
                return
            }
            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { config, configError in
                guard configError == nil,
                      let protection = NTAG21xProtocol.protection(fromConfigRead: config, model: model),
                      protection.auth0 == 0xFF, !protection.protectsReads else {
                    Task { @MainActor in self.finishRawFailure("Tag configuration is protected or unreadable. Raw-page mode will not authenticate or modify it.", session: sessionBox) }
                    return
                }
                self.readUserMemory(tag, model: model) { memory, readError in
                    guard let memory, readError == nil else {
                        Task { @MainActor in self.finishRawFailure("Could not read the complete user memory: \(readError ?? "unknown read error").", session: sessionBox) }
                        return
                    }
                    Task { @MainActor in
                        self.scannedTagSummary = "\(model.rawValue) · \(model.userBytes) raw user bytes · no password write protection detected"
                        if let payload = self.writePayload {
                            let rawPayload: Data
                            if TagcryptRecoveryShares.isBinaryShare(payload), payload.count != model.userBytes {
                                do { rawPayload = try TagcryptRecoveryShares.paddedRawPageMemory(payload, byteCount: model.userBytes) }
                                catch {
                                    self.finishRawFailure("This recovery share does not fit the selected \(model.rawValue) raw memory.", session: sessionBox)
                                    return
                                }
                            } else {
                                rawPayload = payload
                            }
                            guard rawPayload.count == model.userBytes else {
                                self.finishRawFailure("Prepared data is \(rawPayload.count) bytes, but this \(model.rawValue) has \(model.userBytes) raw user bytes. Select the matching tag size and prepare again.", session: sessionBox)
                                return
                            }
                            self.applyRawOverwritePolicy(payload: rawPayload, existingMemory: memory, model: model,
                                                         tag: tag, tagIdentifier: tagIdentifier, session: sessionBox)
                        } else {
                            if let share = try? TagcryptRecoveryShares.encodedShare(fromRawPageMemory: memory) {
                                self.onRecoveryShare?(share)
                                self.lastOutcome = .read
                                self.status = "Recovery share read from all \(model.userBytes) raw user bytes. Scan another share or reconstruct the encrypted record."
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.alertMessage = "Recovery share read."
                                sessionBox.value.invalidate()
                                return
                            }
                            guard VaultCrypto.isTagcryptRecord(memory) else {
                                self.finishRawFailure("No binary Tagcrypt record was found in raw user memory. Check the selected tag mode.", session: sessionBox)
                                return
                            }
                            self.onRead?(memory)
                            self.lastOutcome = .read
                            self.status = "Raw binary record read from all \(model.userBytes) user bytes. Enter its passphrase to decrypt; this tag has no NDEF background read."
                            self.isScanning = false
                            self.session = nil
                            sessionBox.value.alertMessage = "Raw encrypted record read."
                            sessionBox.value.invalidate()
                        }
                    }
                }
            }
        }
    }

    private func applyRawOverwritePolicy(payload: Data, existingMemory: Data, model: NTAG21xProtocol.Model,
                                         tag: NFCUncheckedBox<NFCMiFareTag>, tagIdentifier: Data,
                                         session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        let hasExistingContent = existingMemory.contains(where: { $0 != 0 })
        if let confirmedIdentifier = confirmedOverwriteTagIdentifier, confirmedIdentifier != tagIdentifier {
            confirmedOverwriteTagIdentifier = nil
            finishRawFailure("The scanned tag is different from the one approved. Nothing was written; scan the approved tag again.", session: sessionBox)
        } else if hasExistingContent && overwritePolicy == .never {
            confirmedOverwriteTagIdentifier = nil
            writePayload = nil
            finishRawFailure("Raw user memory already contains data. Never overwrite left it unchanged.", session: sessionBox,
                             sheetText: NFCSheetText.tagKept)
        } else if hasExistingContent && overwritePolicy == .skip {
            confirmedOverwriteTagIdentifier = nil
            writePayload = nil
            status = "Raw tag skipped: it already contains data, so it was left unchanged. No data was written."
            lastOutcome = .skipped
            isScanning = false
            session = nil
            sessionBox.value.alertMessage = NFCSheetText.tagNotChanged
            sessionBox.value.invalidate()
        } else if hasExistingContent && overwritePolicy == .warn && confirmedOverwriteTagIdentifier == nil {
            pendingOverwriteTagIdentifier = tagIdentifier
            showOverwritePromptAfterInvalidation = true
            status = "Raw user memory contains data. Confirm replacement in Tagcrypt, then scan the same tag again."
            isScanning = false
            session = nil
            sessionBox.value.alertMessage = "Existing raw data found. Confirm replacement, then scan the same tag again."
            sessionBox.value.invalidate()
        } else {
            confirmedOverwriteTagIdentifier = nil
            writeRawRecord(payload, model: model, tag: tag, session: sessionBox)
        }
    }

    private func writeRawRecord(_ payload: Data, model: NTAG21xProtocol.Model, tag: NFCUncheckedBox<NFCMiFareTag>,
                                session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        status = "Writing a padded binary record across all \(model.userBytes) raw user bytes…"
        writeUserMemoryTail(tag, model: model, memory: payload, startingAt: 0) { writeError in
            guard writeError == nil else {
                Task { @MainActor in self.finishRawFailure("Raw page write stopped: \(writeError ?? "unknown write error").", session: sessionBox) }
                return
            }
            self.readUserMemory(tag, model: model) { readBack, readError in
                guard readError == nil, readBack == payload else {
                    Task { @MainActor in self.finishRawFailure("Full raw-memory read-back did not match the encrypted record.", session: sessionBox) }
                    return
                }
                Task { @MainActor in
                    let wasRecoveryShare = self.writePayload.map(TagcryptRecoveryShares.isBinaryShare) ?? false
                    self.writePayload = nil
                    self.onWriteVerified?()
                    self.lastOutcome = .written
                    self.status = wasRecoveryShare
                        ? "Recovery share written and all \(model.userBytes) raw user bytes verified. Store the other shares separately."
                        : "Raw binary record written and all \(model.userBytes) user bytes verified. No NDEF/background read is available in raw mode."
                    self.isScanning = false
                    self.session = nil
                    sessionBox.value.alertMessage = "Raw binary record written and verified."
                    sessionBox.value.invalidate()
                }
            }
        }
    }

    private func finishRawFailure(_ message: String, session sessionBox: NFCUncheckedBox<NFCTagReaderSession>,
                                  sheetText: String? = nil) {
        status = message
        lastOutcome = .failed
        isScanning = false
        session = nil
        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(sheetText ?? message))
    }

    private func writeAndVerify(_ message: NFCNDEFMessage, byteCount: Int,
                                tag: NFCUncheckedBox<NFCNDEFTag>, mifareTag: NFCUncheckedBox<NFCMiFareTag>?,
                                session sessionBox: NFCUncheckedBox<NFCTagReaderSession>, wipeOldTagData: Bool,
                                tagLockPlan: TagLockPlan?) {
        let expectedMessage = NFCUncheckedBox(message)
        status = "Tag is writable. Writing \(byteCount) bytes, then verifying the record…"
        // Password-protected rewrite: Core NFC's writeNDEF does not keep the
        // PWD_AUTH session (Can's 215/216 clones: second write failed with
        // "Stack Error"), so write the NDEF TLV with native WRITE commands
        // straight after authentication, then verify with readNDEF as usual.
        if tagLockPlan?.alreadyProtected == true, let mifareTag, let model = NFCService.sessionModel {
            let records = message.records.map {
                NTAG21xProtocol.NDEFRecordBytes(tnf: UInt8($0.typeNameFormat.rawValue), type: $0.type,
                                                identifier: $0.identifier, payload: $0.payload)
            }
            guard let pages = NTAG21xProtocol.ndefTLVPages(message: NTAG21xProtocol.ndefMessageBytes(records), model: model) else {
                status = "The record does not fit this \(model.rawValue). Nothing was written."
                lastOutcome = .failed
                isScanning = false
                session = nil
                sessionBox.value.invalidate(errorMessage: NFCSheetText.short(status))
                return
            }
            var padded = pages
            padded.append(Data(count: model.userBytes - pages.count))
            let lastPage = 4 + pages.count / 4 - 1
            func writePage(_ page: Int) {
                guard page <= lastPage else {
                    tag.value.readNDEF { readBack, readError in
                        Task { @MainActor in
                            guard readError == nil, let readBack, self.matches(readBack, expectedMessage.value) else {
                                self.status = "Write verification failed after the protected write. Keep the original secret and retry."
                                self.lastOutcome = .failed
                                self.isScanning = false
                                self.session = nil
                                sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                                return
                            }
                            self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: false,
                                                     detail: "existing NTAG password was verified and the record was written in the authenticated session")
                        }
                    }
                    return
                }
                let offset = (page - 4) * 4
                guard let command = NTAG21xProtocol.writePageCommand(page: UInt8(page), data: Data(padded[offset..<(offset + 4)])) else { return }
                mifareTag.value.sendMiFareCommand(commandPacket: command) { _, error in
                    if let error {
                        Task { @MainActor in
                            self.status = "Protected write stopped at page \(page): \(error.localizedDescription). The tag may hold a partial record; the prepared record is still available."
                            self.lastOutcome = .failed
                            self.isScanning = false
                            self.session = nil
                            sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                        }
                        return
                    }
                    writePage(page + 1)
                }
            }
            writePage(4)
            return
        }
        tag.value.writeNDEF(expectedMessage.value) { error in
            if let error {
                Task { @MainActor in
                    self.status = "Write failed: \(error.localizedDescription). The prepared record remains available for retry."
                    self.isScanning = false
                    self.session = nil
                    sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                }
                return
            }
            tag.value.readNDEF { readBack, readError in
                guard readError == nil, let readBack, self.matches(readBack, expectedMessage.value) else {
                    let detail = readError?.localizedDescription ?? "The tag's read-back bytes do not match the prepared record."
                    Task { @MainActor in
                        self.status = "Write verification failed: \(detail) Keep the original secret and retry on a tag you can verify."
                        self.isScanning = false
                        self.session = nil
                        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(self.status))
                    }
                    return
                }
                if let tagLockPlan, !tagLockPlan.alreadyProtected, let writes = tagLockPlan.writes,
                   let mifareTag {
                    Task { @MainActor in
                        self.provisionTag(tag: mifareTag, writes: writes, credentials: tagLockPlan.credentials) { result in
                            Task { @MainActor in
                                switch result {
                                case .success:
                                    self.tagPasswordSetupWarning = nil
                                    self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: false,
                                                             detail: "NTAG password protection was enabled and verified. Unused-page randomization was skipped because it must be validated after authentication.")
                                case .failure(let error):
                                    self.finishPartialProvisioning(byteCount: byteCount, error: error, session: sessionBox)
                                }
                            }
                        }
                    }
                    return
                }
                guard !wipeOldTagData || tagLockPlan?.alreadyProtected == true else {
                    Task { @MainActor in self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: false, detail: nil) }
                    return
                }
                if tagLockPlan?.alreadyProtected == true {
                    Task { @MainActor in
                        self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: false,
                                                 detail: "existing NTAG password was verified; unused-page randomization was skipped after authentication")
                    }
                    return
                }
                guard let mifareTag else {
                    Task { @MainActor in
                        self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: false,
                                                 detail: "unused-page randomization is only available for identified NTAG21x tags")
                    }
                    return
                }
                self.wipeUnusedTagMemory(mifareTag, ndefTag: tag, expectedMessage: expectedMessage) { detail in
                    Task { @MainActor in self.finishVerifiedWrite(byteCount: byteCount, session: sessionBox, tailCleared: detail == nil, detail: detail) }
                }
            }
        }
    }

    private func prepareTagLock(tag: NFCUncheckedBox<NFCMiFareTag>?, uid: Data,
                                session sessionBox: NFCUncheckedBox<NFCTagReaderSession>,
                                completion: @escaping (TagLockPlan?, String?) -> Void) {
        if tagLockMode == .off {
            // Mode Off never provisions, but a tag that already has a password
            // must still be unlocked with a known key or the write is rejected
            // ("Stack Error"). Auth only; AUTHLIM must be 0 so a wrong key
            // cannot count down a lockout.
            guard !tagLockCandidates.isEmpty, let tag, uid.count == 7,
                  tag.value.mifareFamily == .ultralight || tag.value.mifareFamily == .unknown,
                  let model = NFCService.sessionModel else { completion(nil, nil); return }
            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { read, readError in
                Task { @MainActor in
                    guard readError == nil, read.count >= 8,
                          let config = NTAG21xProtocol.Configuration(config0: read.prefix(4), config1: read.dropFirst(4).prefix(4)),
                          config.auth0 != 0xFF, config.authLimit == 0, !config.protectsReads else {
                        completion(nil, nil); return
                    }
                    let credentials = self.tagLockCandidates.compactMap { try? TagLockCrypto.credentials(masterKey: $0.masterKey, uid: uid) }
                    self.authenticateTag(tag: tag, credentials: credentials, index: 0, session: sessionBox) { matched in
                        guard let matched else { completion(nil, self.lastAuthLostConnection ? NFCService.authConnectionLost : NFCService.lockedByAnotherKey); return }
                        completion(TagLockPlan(writes: nil, credentials: matched, alreadyProtected: true), nil)
                    }
                }
            }
            return
        }
        if let approvedIdentifier = approvedNDEFOnlyTagIdentifier {
            guard approvedIdentifier == uid else {
                completion(nil, "the scanned tag did not match the tag approved for an NDEF-only write")
                return
            }
            approvedNDEFOnlyTagIdentifier = nil
            completion(nil, nil)
            return
        }
        guard let tag, NFCService.familyAllowed(tag.value) else {
            completion(nil, "password protection is supported only for identified NTAG213/215/216 tags")
            return
        }
        guard uid.count == 7 else { completion(nil, "the tag UID is not the required 7 bytes"); return }
        do {
            do {
                guard let model = NFCService.sessionModel else {
                    completion(nil, allowCompatibleTags
                        ? "this tag could not be identified as NTAG213/215/216, even from its Capability Container; no tag-password commands were sent"
                        : "GET_VERSION did not identify an NTAG213/215/216; no tag-password commands were sent. Turn on Compatible tags in Advanced to try non-NXP tags")
                    return
                }
                tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { read, readError in
                    Task { @MainActor in
                        guard readError == nil, read.count >= 8,
                              let config = NTAG21xProtocol.Configuration(config0: read.prefix(4), config1: read.dropFirst(4).prefix(4)) else {
                            completion(nil, "NTAG configuration could not be read safely")
                            return
                        }
                        guard config.authLimit == 0, !config.protectsReads else {
                            completion(nil, "AUTHLIM must be 0 and read protection must be off; no password attempts or writes were made")
                            return
                        }
                        let credentialOptions: [(TagLockCredentials, TagLockCredentialCandidate.Source)] = self.tagLockCandidates.compactMap { candidate in
                            guard let credentials = try? TagLockCrypto.credentials(masterKey: candidate.masterKey, uid: uid) else { return nil }
                            return (credentials, candidate.source)
                        }
                        guard !credentialOptions.isEmpty else { completion(nil, "no valid master key could derive this tag's credentials"); return }
                        if config.auth0 == 0xFF {
                            let selectedCandidate = TagLockCredentialResolver.provisioningCandidate(
                                mode: self.tagLockMode, candidates: self.tagLockCandidates)
                            guard let selectedCandidate,
                                  let selected = credentialOptions.first(where: { $0.1 == selectedCandidate.source }),
                                  let writes = NTAG21xProtocol.passwordProvisioningWrites(model: model,
                                                                                         credentials: selected.0,
                                                                                         configuration: config) else {
                                completion(nil, "the selected mode has no suitable master key or the unprotected tag configuration is not safe to modify")
                                return
                            }
                            completion(TagLockPlan(writes: writes, credentials: selected.0, alreadyProtected: false), nil)
                            return
                        }
                        self.authenticateTag(tag: tag, credentials: credentialOptions.map(\.0), index: 0,
                                             session: sessionBox) { matched in
                            guard let matched else {
                                completion(nil, self.lastAuthLostConnection ? NFCService.authConnectionLost : NFCService.lockedByAnotherKey)
                                return
                            }
                            completion(TagLockPlan(writes: nil, credentials: matched, alreadyProtected: true), nil)
                        }
                    }
                }
            }
        }
    }

    private func inspectOrSealTag(tag: NFCUncheckedBox<NFCMiFareTag>, ndefTag: NFCUncheckedBox<NFCNDEFTag>,
                                  identifier: Data, session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        guard let expectedRecord = sealExpectedRecord else {
            finishSealFailure("No prepared record is waiting to be sealed. Prepare the record again; no lock bits were written.", session: sessionBox)
            return
        }
        guard NFCService.familyAllowed(tag.value) else {
            finishSealFailure("iOS reports this tag as MIFARE family \(NFCService.familyName(tag.value.mifareFamily)), not Ultralight\(tag.value.mifareFamily == .unknown && !allowCompatibleTags ? "; turn on Compatible tags in Advanced to try it" : ""). No lock bits were written.", session: sessionBox)
            return
        }
        if let approved = sealApprovedTagIdentifier, approved != identifier {
            finishSealFailure("This is not the tag you approved. No lock bits were written.", session: sessionBox); return
        }
        do {
            do {
                guard let model = NFCService.sessionModel else {
                    self.finishSealFailure("This tag was not identified as an NTAG213/215/216\(self.allowCompatibleTags ? "" : "; turn on Compatible tags in Advanced to try non-NXP tags"). See Tag details for the probe result. No lock bits were written.", session: sessionBox)
                    return
                }
                guard !NFCService.sessionModelFromCC else {
                    self.finishSealFailure("The seal needs the chip to identify itself (GET_VERSION). This tag was only sized from its header, which clones also pass. No lock bits were written.", session: sessionBox)
                    return
                }
                if let approvedModel = self.sealApprovedModel, approvedModel != model {
                    self.finishSealFailure("This tag now identifies as \(model.rawValue), not the \(approvedModel.rawValue) you approved. No lock bits were written.", session: sessionBox)
                    return
                }
                ndefTag.value.readNDEF { message, readError in
                    Task { @MainActor in
                        guard readError == nil, let message, self.message(message, contains: expectedRecord) else {
                            self.finishSealFailure(readError == nil
                                ? "This tag does not hold the exact prepared record. No lock bits were written."
                                : "The tag's NDEF record could not be read (\(NFCService.errorCode(readError!))). No lock bits were written.", session: sessionBox)
                            return
                        }
                        tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.config0Page)) { configRead, configError in
                            Task { @MainActor in
                                guard configError == nil, configRead.count == 16,
                                      let config = NTAG21xProtocol.Configuration(config0: configRead.prefix(4), config1: configRead.dropFirst(4).prefix(4)) else {
                                    self.finishSealFailure("Tag configuration could not be read. No lock bits were written.", session: sessionBox)
                                    return
                                }
                                guard config.auth0 == 0xFF, !config.protectsReads, config.authLimit == 0 else {
                                    self.finishSealFailure("This tag has a tag password. Remove it first (Settings → Tag details → Remove tag password), then seal. No lock bits were written.", session: sessionBox)
                                    return
                                }
                                tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: 0x02)) { staticRead, staticError in
                                    guard staticError == nil, staticRead.count == 16 else {
                                        Task { @MainActor in self.finishSealFailure("Static lock bytes could not be read. No lock bits were written.", session: sessionBox) }; return
                                    }
                                    tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.dynamicLockPage)) { dynamicRead, dynamicError in
                                        Task { @MainActor in
                                            guard dynamicError == nil, dynamicRead.count == 16,
                                                  let plan = NTAG21xProtocol.wholeUserMemorySealPlan(
                                                    model: model,
                                                    capabilityContainer: Data(staticRead[4..<8]),
                                                    staticLockBytes: Data([staticRead[2], staticRead[3]]),
                                                    dynamicLockBytes: Data(dynamicRead.prefix(3)),
                                                    configuration: config) else {
                                                self.finishSealFailure("This \(model.rawValue) is already or partially locked, its Capability Container is not the factory value, or its configuration is already frozen. No additional irreversible lock bits were written.", session: sessionBox)
                                                return
                                            }
                                            guard self.sealApprovedTagIdentifier != nil else {
                                                self.sealApprovedTagIdentifier = identifier
                                                self.sealApprovedModel = model
                                                self.status = "\(model.rawValue) and the exact encrypted record verified. Confirm the irreversible action in Tagcrypt, then rescan this same tag."
                                                self.isScanning = false
                                                self.session = nil
                                                sessionBox.value.alertMessage = "Tag inspected. Confirm permanent sealing in Tagcrypt, then rescan."
                                                sessionBox.value.invalidate()
                                                self.sealConfirmationNeeded = true
                                                return
                                            }
                                            guard self.sealApprovedModel == model else {
                                                self.finishSealFailure("The approved model changed. No lock bits were written.", session: sessionBox); return
                                            }
                                            self.performSeal(plan, tag: tag, ndefTag: ndefTag,
                                                             expectedRecord: expectedRecord, session: sessionBox)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func performSeal(_ plan: NTAG21xProtocol.UserMemorySealPlan,
                             tag: NFCUncheckedBox<NFCMiFareTag>, ndefTag: NFCUncheckedBox<NFCNDEFTag>,
                             expectedRecord: Data,
                             session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        func writeNext(_ index: Int) {
            guard index < plan.writes.count else {
                // Read back every sealed structure: CC (page 3) and static lock
                // bytes (page 2) from one READ at 0x02, dynamic lock bytes at
                // 0x28, CONFIG1 (bytes 4-7 of a READ at 0x29).
                tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: NTAG21xProtocol.ntag213StaticLockPage)) { staticRead, staticError in
                    tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: plan.model.dynamicLockPage)) { dynamicRead, dynamicError in
                    tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: plan.model.config0Page)) { configRead, configError in
                        Task { @MainActor in
                            guard staticError == nil, dynamicError == nil, configError == nil,
                                  staticRead.count == 16, dynamicRead.count == 16, configRead.count == 16,
                                  Data(staticRead[4..<8]) == plan.expectedCapabilityContainer,
                                  Data([staticRead[2], staticRead[3]]) == plan.expectedStaticLockBytes,
                                  Data(dynamicRead.prefix(3)) == plan.expectedDynamicLockBytes,
                                  Data(configRead[4..<8]) == plan.expectedConfig1,
                                  configRead[3] == 0xFF else {
                                self.finishSealFailure("Lock writes were attempted, but read-back of the CC, lock bytes or configuration did not match. Treat the tag as possibly partially sealed.", session: sessionBox)
                                return
                            }
                            ndefTag.value.readNDEF { message, ndefError in
                                Task { @MainActor in
                                    guard ndefError == nil, let message, self.message(message, contains: expectedRecord) else {
                                        self.finishSealFailure("Lock bits were read back, but the encrypted NDEF record did not verify after sealing. Treat this tag as sealed and the record as unavailable.", session: sessionBox)
                                        return
                                    }
                                    self.sealExpectedRecord = nil
                                    self.sealApprovedTagIdentifier = nil
                                    self.sealApprovedModel = nil
                                    self.status = "\(plan.model.rawValue) sealed: user memory, the Capability Container and the configuration pages are permanently frozen. CC, lock bytes, CONFIG1 and the encrypted NDEF record were read back; the seal cannot be undone."
                                    self.lastOutcome = .written
                                    self.isScanning = false
                                    self.session = nil
                                    sessionBox.value.alertMessage = "Tag sealed and verified."
                                    sessionBox.value.invalidate()
                                }
                            }
                        }
                    }
                    }
                }
                return
            }
            let write = plan.writes[index]
            guard let command = NTAG21xProtocol.writePageCommand(page: write.page, data: write.bytes) else {
                finishSealFailure("Could not construct lock write. Tag may be partially sealed.", session: sessionBox); return
            }
            tag.value.sendMiFareCommand(commandPacket: command) { _, error in
                Task { @MainActor in
                    guard error == nil else {
                        self.finishSealFailure("Irreversible lock write at page \(String(format: "%02X", write.page)) failed: \(error!.localizedDescription). Treat the tag as possibly partially sealed.", session: sessionBox)
                        return
                    }
                    writeNext(index + 1)
                }
            }
        }
        writeNext(0)
    }

    private func message(_ message: NFCNDEFMessage, contains payload: Data) -> Bool {
        message.records.contains { record in
            if record.typeNameFormat == .media,
               String(data: record.type, encoding: .utf8) == VaultNDEFTextCodec.binaryMediaType {
                return record.payload == payload
            }
            guard let text = record.wellKnownTypeTextPayload().0,
                  let decoded = Data(base64Encoded: text) else { return false }
            return decoded == payload
        }
    }

    /// Sentinel refusal from prepareTagLock: AUTH0 != 0xFF and no configured
    /// candidate matched PACK. Callers stop without offering a fallback.
    nonisolated static let lockedByAnotherKey = "locked-by-another-key"
    /// Review P2-7: the tag dropped while trying keys; not a key mismatch.
    nonisolated static let authConnectionLost = "auth-connection-lost"

    /// After native MIFARE commands (the probe), Core NFC's first NDEF status
    /// query can fail on some tags (seen on Can's NTAG215 clone). Reconnect and
    /// try once more before reporting an error.
    fileprivate nonisolated static func queryNDEFStatusRetrying(_ tag: NFCUncheckedBox<NFCNDEFTag>,
                                                    session: NFCUncheckedBox<NFCTagReaderSession>,
                                                    completion: @escaping (NFCNDEFStatus, Int, Error?) -> Void) {
        tag.value.queryNDEFStatus { status, capacity, error in
            guard error != nil else { completion(status, capacity, nil); return }
            let target: NFCTag? = {
                if let mifare = tag.value as? NFCMiFareTag { return .miFare(mifare) }
                return nil
            }()
            guard let target else { completion(status, capacity, error); return }
            session.value.connect(to: target) { reconnectError in
                guard reconnectError == nil else { completion(status, capacity, error); return }
                tag.value.queryNDEFStatus { retryStatus, retryCapacity, retryError in
                    completion(retryStatus, retryCapacity, retryError)
                }
            }
        }
    }

    /// ISO/IEC 7816-6 manufacturer code (first UID byte). A matching code is
    /// not proof of origin: clones often copy NXP's 0x04.
    nonisolated static func makerName(_ code: UInt8?) -> String {
        guard let code else { return "unknown" }
        let name: String = switch code {
        case 0x04: "NXP (claimed)"
        case 0x02: "STMicroelectronics"
        case 0x05: "Infineon"
        case 0x07: "Texas Instruments"
        case 0x1D: "Shanghai Fudan Microelectronics"
        case 0x53: "Shanghai Feiju Microelectronics"
        default: "code 0x\(String(format: "%02X", code))"
        }
        return code == 0x04 || code == 0x02 || code == 0x05 || code == 0x07 || code == 0x1D || code == 0x53
            ? "\(name) (0x\(String(format: "%02X", code)))" : name
    }

    nonisolated static func familyName(_ family: NFCMiFareFamily) -> String {
        switch family {
        case .ultralight: "Ultralight"
        case .plus: "Plus"
        case .desfire: "DESFire"
        case .unknown: "unknown"
        @unknown default: "unrecognised (\(family.rawValue))"
        }
    }

    nonisolated static func hex(_ data: Data) -> String {
        data.isEmpty ? "empty" : data.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    nonisolated static func errorCode(_ error: Error) -> String {
        let ns = error as NSError
        return "\(ns.domain) \(ns.code)"
    }

    private func finishSealFailure(_ message: String, session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        sealExpectedRecord = nil
        sealApprovedTagIdentifier = nil
        sealApprovedModel = nil
        sealConfirmationNeeded = false
        status = message
        lastOutcome = .failed
        isScanning = false
        session = nil
        sessionBox.value.invalidate(errorMessage: NFCSheetText.short(message))
    }

    /// P2-1: a wrong PWD_AUTH is NAK'd and the NTAG21x leaves the ACTIVE state,
    /// so the next candidate would hit a dead connection. Reconnect to the same
    /// tag before every candidate after the first. AUTHLIM is already known to
    /// be 0, so failed attempts cannot lock the tag.
    private func authenticateTag(tag: NFCUncheckedBox<NFCMiFareTag>, credentials: [TagLockCredentials], index: Int,
                                 session sessionBox: NFCUncheckedBox<NFCTagReaderSession>,
                                 completion: @escaping (TagLockCredentials?) -> Void) {
        if index == 0 { lastAuthLostConnection = false }
        guard index < credentials.count,
              let command = NTAG21xProtocol.passwordAuthCommand(password: credentials[index].password) else {
            completion(nil); return
        }
        let attempt = {
            tag.value.sendMiFareCommand(commandPacket: command) { response, error in
                Task { @MainActor in
                    if error == nil, NTAG21xProtocol.passwordAuthMatches(response, expectedPack: credentials[index].pack) {
                        completion(credentials[index])
                    } else {
                        self.authenticateTag(tag: tag, credentials: credentials, index: index + 1,
                                             session: sessionBox, completion: completion)
                    }
                }
            }
        }
        guard index > 0 else { attempt(); return }
        sessionBox.value.connect(to: .miFare(tag.value)) { error in
            Task { @MainActor in
                guard error == nil else { self.lastAuthLostConnection = true; completion(nil); return }
                attempt()
            }
        }
    }

    private func provisionTag(tag: NFCUncheckedBox<NFCMiFareTag>, writes: [NTAG21xProtocol.PageWrite],
                              credentials: TagLockCredentials, completion: @escaping (Result<Void, NSError>) -> Void) {
        func writeNext(_ index: Int) {
            guard index < writes.count else {
                guard let auth = NTAG21xProtocol.passwordAuthCommand(password: credentials.password) else {
                    completion(.failure(NSError(domain: "TagcryptNTAGPassword", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid derived password", "stage": writes.count + 1]))); return
                }
                tag.value.sendMiFareCommand(commandPacket: auth) { response, error in
                    Task { @MainActor in
                        guard error == nil, NTAG21xProtocol.passwordAuthMatches(response, expectedPack: credentials.pack) else {
                            completion(.failure(NSError(domain: "TagcryptNTAGPassword", code: 2, userInfo: [NSLocalizedDescriptionKey: "post-write PWD_AUTH/PACK verification failed", "stage": writes.count + 1]))); return
                        }
                        tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: writes.last!.page)) { configRead, readError in
                            Task { @MainActor in
                                guard readError == nil, configRead.count >= 8,
                                      configRead[3] == 0x04,
                                      configRead[4] & 0x87 == 0 else {
                                    completion(.failure(NSError(domain: "TagcryptNTAGPassword", code: 3, userInfo: [NSLocalizedDescriptionKey: "password authenticated, but AUTH0/PROT/AUTHLIM verification failed", "stage": writes.count + 2]))); return
                                }
                                completion(.success(()))
                            }
                        }
                    }
                }
                return
            }
            guard let command = NTAG21xProtocol.writePageCommand(page: writes[index].page, data: writes[index].bytes) else {
                completion(.failure(NSError(domain: "TagcryptNTAGPassword", code: 4, userInfo: [NSLocalizedDescriptionKey: "could not construct page write at stage \(index + 1)", "stage": index + 1]))); return
            }
            tag.value.sendMiFareCommand(commandPacket: command) { _, error in
                Task { @MainActor in
                    guard error == nil else {
                        completion(.failure(NSError(domain: "TagcryptNTAGPassword", code: 5, userInfo: [NSLocalizedDescriptionKey: "page \(String(format: "%02X", writes[index].page)) failed at stage \(index + 1): \(error!.localizedDescription)", "stage": index + 1]))); return
                    }
                    writeNext(index + 1)
                }
            }
        }
        writeNext(0)
    }

    /// P2-2: the NDEF record verified, but password provisioning stopped. Report
    /// it through the error sheet and a persistent banner, never the success UI.
    private func finishPartialProvisioning(byteCount: Int, error: NSError,
                                           session sessionBox: NFCUncheckedBox<NFCTagReaderSession>) {
        let stage = (error.userInfo["stage"] as? Int) ?? 0
        let stageText = stage > 0 ? " (stage \(stage))" : ""
        tagPasswordSetupWarning = "Record written and verified (\(byteCount) NDEF bytes), but tag password setup is incomplete\(stageText): \(error.localizedDescription). Do not assume this tag is protected; test it before relying on it."
        status = "NDEF record written and verified. Tag password setup incomplete\(stageText); do not assume the tag is protected."
        writePayload = nil
        onWriteVerified?()
        lastOutcome = .failed
        isScanning = false
        session = nil
        sessionBox.value.invalidate(errorMessage: NFCSheetText.short("Record written. Tag password setup incomplete\(stageText)."))
    }

    private func finishVerifiedWrite(byteCount: Int, session sessionBox: NFCUncheckedBox<NFCTagReaderSession>, tailCleared: Bool, detail: String?) {
        let wasRecoveryShare = writePayload.map(TagcryptRecoveryShares.isBinaryShare) ?? false
        if let detail {
            status = wasRecoveryShare
                ? "Recovery share write verified, but unused-page randomization was not completed: \(detail)"
                : "NDEF write verified, but unused-page clearing was not completed: \(detail)"
        } else if tailCleared {
            status = wasRecoveryShare
                ? "Recovery share verified; unused tag memory was randomized (\(byteCount) NDEF bytes). Store the other shares separately."
                : "Write verified: the encrypted record was read back and unused tag memory was randomized (\(byteCount) NDEF bytes)."
        } else {
            status = wasRecoveryShare
                ? "Recovery share written and verified (\(byteCount) NDEF bytes). Store the other shares separately."
                : "Write verified: the encrypted NDEF record was read back (\(byteCount) bytes). Unused-page clearing is off in Settings."
        }
        writePayload = nil
        onWriteVerified?()
        lastOutcome = .written
        isScanning = false
        session = nil
        sessionBox.value.alertMessage = wasRecoveryShare
            ? "Recovery share written and verified."
            : (tailCleared ? "Encrypted record written, verified, and tag tail randomized." : "NDEF record written and verified.")
        sessionBox.value.invalidate()
    }

    /// Clears bytes after the Type 2 NDEF TLV terminator, but only on recognized
    /// NTAG21x tags with readable, unprotected configuration. Unsupported or
    /// protected tags keep their existing data; NDEF verification still stands.
    nonisolated private func wipeUnusedTagMemory(_ tag: NFCUncheckedBox<NFCMiFareTag>, ndefTag: NFCUncheckedBox<NFCNDEFTag>,
                                     expectedMessage: NFCUncheckedBox<NFCNDEFMessage>, completion: @escaping (String?) -> Void) {
        guard NFCService.familyAllowed(tag.value) else {
            completion("tag family is not a supported NTAG21x model")
            return
        }
        do {
            guard let model = NFCService.sessionModel else {
                completion("tag model is not a recognized NTAG213/215/216")
                return
            }
            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: model.configurationPage)) { config, configError in
                guard configError == nil,
                      let protection = NTAG21xProtocol.protection(fromConfigRead: config, model: model),
                      protection.auth0 == 0xFF, !protection.protectsReads else {
                    completion("tag configuration is protected, unreadable, or not in the supported unprotected mode")
                    return
                }
                self.readUserMemory(tag, model: model) { memory, readError in
                    guard let memory, readError == nil else {
                        completion(readError ?? "full user memory could not be read")
                        return
                    }
                    guard let terminator = NTAG21xProtocol.ndefTerminatorOffset(in: memory) else {
                        completion("a valid NDEF TLV terminator was not found; memory was left unchanged")
                        return
                    }
                    let clearOffset = terminator + 1
                    let randomized: Data
                    do { randomized = try NTAG21xProtocol.randomize(after: clearOffset, in: memory) }
                    catch { completion("secure random fill failed: \(error.localizedDescription)"); return }
                    self.writeUserMemoryTail(tag, model: model, memory: randomized, startingAt: clearOffset) { writeError in
                        guard writeError == nil else {
                            completion(writeError ?? "page write failed")
                            return
                        }
                        self.readUserMemory(tag, model: model) { reread, verificationError in
                            guard verificationError == nil, reread == randomized else {
                                completion(verificationError ?? "full-memory read-back did not match the randomized bytes")
                                return
                            }
                            ndefTag.value.readNDEF { readBack, ndefError in
                                guard ndefError == nil, let readBack, self.matches(readBack, expectedMessage.value) else {
                                    completion("the NDEF record did not remain readable after page clearing")
                                    return
                                }
                                completion(nil)
                            }
                        }
                    }
                }
            }
        }
    }

    nonisolated private func readUserMemory(_ tag: NFCUncheckedBox<NFCMiFareTag>, model: NTAG21xProtocol.Model,
                                completion: @escaping (Data?, String?) -> Void) {
        var memory = Data()
        func readChunk(offset: Int) {
            if offset == model.userBytes { completion(memory, nil); return }
            let page = UInt8(4 + offset / 4)
            tag.value.sendMiFareCommand(commandPacket: NTAG21xProtocol.readCommand(startingAt: page)) { response, error in
                guard error == nil else { completion(nil, error?.localizedDescription ?? "page read failed"); return }
                let count = min(16, model.userBytes - offset)
                guard response.count >= count else { completion(nil, "short raw-page read response"); return }
                memory.append(response.prefix(count))
                readChunk(offset: offset + count)
            }
        }
        readChunk(offset: 0)
    }

    nonisolated private func writeUserMemoryTail(_ tag: NFCUncheckedBox<NFCMiFareTag>, model: NTAG21xProtocol.Model,
                                     memory: Data, startingAt offset: Int, completion: @escaping (String?) -> Void) {
        let firstPage = 4 + offset / 4
        let lastPage = 4 + model.userPageCount - 1
        func writePage(_ page: Int) {
            if page > lastPage { completion(nil); return }
            let memoryOffset = (page - 4) * 4
            let bytes = Array(memory[memoryOffset..<(memoryOffset + 4)])
            let command = NTAG21xProtocol.command([0xA2, UInt8(page)] + bytes)
            tag.value.sendMiFareCommand(commandPacket: command) { _, error in
                guard error == nil else { completion(error?.localizedDescription ?? "raw page write failed"); return }
                writePage(page + 1)
            }
        }
        if offset >= model.userBytes { completion(nil) }
        else { writePage(firstPage) }
    }

    nonisolated private func matches(_ actual: NFCNDEFMessage, _ expected: NFCNDEFMessage) -> Bool {
        guard actual.records.count == expected.records.count else { return false }
        return zip(actual.records, expected.records).allSatisfy { lhs, rhs in
            lhs.typeNameFormat == rhs.typeNameFormat && lhs.type == rhs.type &&
            lhs.identifier == rhs.identifier && lhs.payload == rhs.payload
        }
    }

    private nonisolated func statusDescription(_ status: NFCNDEFStatus) -> String {
        switch status {
        case .notSupported: "not formatted for NDEF"
        case .readOnly: "read-only"
        case .readWrite: "read/write"
        @unknown default: "unknown (\(status.rawValue))"
        }
    }
}
