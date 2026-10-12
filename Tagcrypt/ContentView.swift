import SwiftUI
import VisionKit
import UIKit
import UniformTypeIdentifiers
import Photos
import AuthenticationServices
import LocalAuthentication

/// One Settings row: title, a 3–4 word caption, its control, and an optional
/// chevron that expands the full explanation underneath.
private struct SettingRow<Control: View>: View {
    let title: String
    let caption: String
    var detail: String? = nil
    var tint: Color? = nil
    @ViewBuilder var control: () -> Control
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.body)
                    Text(caption).font(.caption).foregroundStyle(tint ?? .secondary)
                }
                Spacer(minLength: 8)
                control()
                if detail != nil {
                    Button {
                        withAnimation(.easeInOut(duration: 0.18)) { expanded.toggle() }
                    } label: {
                        Image(systemName: "chevron.down")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(expanded ? 180 : 0))
                            .frame(width: 28, height: 28)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(expanded ? "Hide details" : "Show details")
                }
            }
            if expanded, let detail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .transition(.opacity)
            }
        }
        .padding(.vertical, 2)
    }
}

private extension SettingRow where Control == EmptyView {
    init(title: String, caption: String, detail: String? = nil, tint: Color? = nil) {
        self.init(title: title, caption: caption, detail: detail, tint: tint) { EmptyView() }
    }
}

private enum SettingsRiskAction {
    case compatibleTags
    case enableAdvanced
    case rawPages(Bool)
    case randomizeUnusedPages(Bool)
    case tagPasswordMode(String)
    case deleteOrganisationKey(UUID, String)
    case rotateAutoKey
}

private enum TagSize: String, CaseIterable, Identifiable {
    case ntag213 = "NTAG213"
    case ntag215 = "NTAG215"
    case ntag216 = "NTAG216"

    var id: String { rawValue }
    var bytes: Int {
        switch self {
        case .ntag213: 144
        case .ntag215: 504
        case .ntag216: 888
        }
    }
    var safeNDEFPayloadBytes: Int {
        switch self {
        case .ntag213: 128
        case .ntag215: 448
        case .ntag216: 832
        }
    }
}

private enum MainTab: String, CaseIterable, Identifiable {
    case encrypt = "Encrypt"
    case decrypt = "Decrypt"
    case vault = "Vault"

    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .encrypt: "lock.fill"
        case .decrypt: "viewfinder"
        case .vault: "lock.doc"
        }
    }
}

private enum DeferredSettingsAction {
    case registerFIDOKey
    case exportVault
    case renameFIDOKey
}

/// Shared type scale for every Tagcrypt-owned dimmed prompt.
private enum TagcryptPromptTypography {
    static let title = Font.system(size: 20, weight: .semibold, design: .rounded)
    static let body = Font.system(size: 16, weight: .regular, design: .rounded)
    static let field = Font.system(size: 17, weight: .regular, design: .rounded)
    static let supporting = Font.system(size: 14, weight: .regular, design: .rounded)
    static let action = Font.system(size: 17, weight: .semibold, design: .rounded)
    static let cancel = Font.system(size: 17, weight: .medium, design: .rounded)
    static let backdropOpacity = 0.62
}

private enum SecretEntryMode: String, CaseIterable, Identifiable {
    case single = "One secret"
    case slots = "Multiple slots"
    var id: String { rawValue }
}

private enum RecordDestination: String, CaseIterable, Identifiable {
    case nfc = "NFC tag"
    case qr = "QR code"
    var id: String { rawValue }
}

private enum RecordUnlockChoice: String, CaseIterable, Identifiable {
    case passphrase = "Passphrase"
    case fido = "FIDO key"
    case both = "Both"
    var id: String { rawValue }
    var envelopeMode: FIDOEnvelopeCrypto.UnlockMode {
        switch self {
        case .passphrase: .passphraseOnly
        case .fido: .fidoOnly
        case .both: .passphraseAndFIDO
        }
    }
}

private enum InputField: Hashable {
    case secret, passphrase, confirmation, decryptPassphrase
    case nickname, shareA, shareB, prompt
    case slotTitle(UUID), slotSecret(UUID)
}

private enum QRPreviewAction {
    case share
    case export
}

private struct SecretSlotDraft: Identifiable, Equatable {
    var id = UUID()
    var title: String
    var secret = ""
    var revealed = false
}

private struct TagcryptVaultExport: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

private struct TagcryptVaultBackup: Codable {
    var entries: [TagcryptVaultEntry]
    var tagLockKeys: TagLockKeyBundle?
}

private struct FIDORecordKeyCandidate: Identifiable {
    let credentialID: Data
    let prfInput: Data
    let ordinal: Int
    var id: Data { credentialID }
}

private enum TagcryptAppearance: String, CaseIterable, Identifiable {
    case light, dark, system
    var id: String { rawValue }
    var title: String { self == .system ? "Device Auto" : rawValue.capitalized }
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .dark: .dark
        case .light: .light
        }
    }
}

private struct TagcryptPalette {
    let isDark: Bool

    var background: Color { isDark ? Color(red: 0.025, green: 0.055, blue: 0.050) : Color(red: 0.94, green: 0.965, blue: 0.955) }
    var surface: Color { isDark ? Color(red: 0.055, green: 0.095, blue: 0.085) : Color.white }
    var bottomBar: Color { isDark ? Color(red: 0.035, green: 0.085, blue: 0.075) : Color(red: 0.88, green: 0.925, blue: 0.905) }
    var border: Color { isDark ? Color(red: 0.12, green: 0.22, blue: 0.19) : Color(red: 0.81, green: 0.87, blue: 0.84) }
    var input: Color { isDark ? Color(red: 0.035, green: 0.07, blue: 0.063) : Color(red: 0.965, green: 0.98, blue: 0.975) }
    var primary: Color { isDark ? Color(red: 0.90, green: 0.95, blue: 0.93) : Color(red: 0.055, green: 0.13, blue: 0.11) }
    var secondary: Color { isDark ? Color(red: 0.64, green: 0.73, blue: 0.69) : Color(red: 0.28, green: 0.37, blue: 0.33) }
    var muted: Color { isDark ? Color(red: 0.47, green: 0.57, blue: 0.53) : Color(red: 0.39, green: 0.48, blue: 0.44) }
    var accent: Color { Color(red: 0.90, green: 0.66, blue: 0.30) }
    var accentText: Color { isDark ? accent : Color(red: 0.52, green: 0.31, blue: 0.05) }
    var onAccent: Color { Color(red: 0.015, green: 0.07, blue: 0.06) }
    var selectedTab: Color { isDark ? accent.opacity(0.15) : accent.opacity(0.12) }
}

private final class TagcryptTheme: ObservableObject {
    @Published var appearance: TagcryptAppearance {
        didSet { UserDefaults.standard.set(appearance.rawValue, forKey: "tagcrypt.theme.appearance") }
    }

    init() {
        appearance = TagcryptAppearance(rawValue: UserDefaults.standard.string(forKey: "tagcrypt.theme.appearance") ?? "dark") ?? .dark
    }

    func palette(for systemScheme: ColorScheme) -> TagcryptPalette {
        let dark = appearance == .dark || (appearance == .system && systemScheme == .dark)
        return TagcryptPalette(isDark: dark)
    }
}

struct ContentView: View {
    private static let safetyNoticeText = Bundle.main.url(forResource: "SafetyNoticeV4", withExtension: "txt")
        .flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "The safety notice could not be loaded. Please update Tagcrypt before continuing."
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.colorScheme) private var systemColorScheme
    @StateObject private var theme = TagcryptTheme()
    @StateObject private var nfc = NFCService()
    @StateObject private var fido = FIDOKeyManager()
    @StateObject private var applePasswords = ApplePasswordsPicker()
    @State private var secret = ""
    @State private var secretEntryMode: SecretEntryMode = .single
    @State private var secretSlots = [SecretSlotDraft(title: "Password 1")]
    @State private var decryptedVault: PasswordVault?
    @State private var passphrase = ""
    @State private var passphraseConfirmation = ""
    @State private var generatedPassphraseValue = ""
    @State private var generatedPassphraseIsSaved = false
    @State private var generatedPassphraseToInstall: String?
    @State private var rotationVaultLabel = ""
    @FocusState private var rotationVaultLabelFocused: Bool
    @State private var showPassphraseRotationPrompt = false
    @State private var archivedPassphrases = [ArchivedVaultPassphrase]()
    @State private var vaultEntries = [TagcryptVaultEntry]()
    @State private var revealedVaultEntryIDs = Set<UUID>()
    @State private var vaultSelectionMode = false
    @State private var selectedVaultEntryIDs = Set<UUID>()
    @State private var selectedArchivedPhraseIDs = Set<UUID>()
    @State private var showBulkDeleteConfirmation = false
    @State private var swipedVaultEntryID: UUID?
    @State private var bulkDeleteSelectionCount = 0
    @State private var vaultExportSelection: [TagcryptVaultEntry]?
    @State private var tagNickname = ""
    @State private var vaultExportDocument: TagcryptVaultExport?
    @State private var vaultExportFilename = "Tagcrypt-recovery-vault.tagcryptvault"
    @State private var showVaultExportWarning = false
    @State private var showVaultExportFilePicker = false
    @State private var showCSVExportFilePicker = false
    @State private var showCSVExportWarning = false
    @State private var vaultExportPassphrase = ""
    @State private var tagLockOrganisationLabel = ""
    @State private var showVaultImportPicker = false
    @State private var vaultRenameTarget: TagcryptVaultEntry?
    @State private var vaultRenameDraft = ""
    @State private var showPassphraseSavedToast = false
    @State private var keyPendingForget: RegisteredFIDOKey?
    @State private var showForgetFIDOKeyConfirmation = false
    @State private var isRecoveryVaultUnlocked = false
    @State private var isRecoveryVaultAuthenticating = false
    @State private var revealedArchivedPassphraseIDs = Set<UUID>()
    @State private var customPassphraseAcknowledged = false
    @State private var showCustomPassphraseWarning = false
    @State private var showSecret = false
    @State private var showPassphrase = false
    @State private var isCryptoWorking = false
    @State private var cryptoOperation = UUID()
    @State private var revealGeneration = UUID()
    @State private var selectedSize: TagSize = .ntag213
    @State private var adaptiveNDEFCapacity: Int?
    @State private var destination: RecordDestination = .nfc
    @FocusState private var focusedInput: InputField?
    @AppStorage("tagcrypt.passphrase.mode") private var passphraseMode = "perTag"
    @AppStorage("tagcrypt.vault.requireFaceID.v2") private var vaultRequiresFaceID = true
    @AppStorage("tagcrypt.fido.requireKeyPIN") private var requireFIDOKeyPIN = TagcryptConfigurationDefaults.requireFIDOKeyPIN
    @AppStorage("tagcrypt.nfc.overwritePolicy") private var nfcOverwritePolicyRaw = TagcryptConfigurationDefaults.nfcOverwritePolicyRaw
    @AppStorage("tagcrypt.onboarding.acknowledgedVersion") private var onboardingAcknowledgedVersion = ""
    @AppStorage("tagcrypt.notice.acknowledgedAt") private var noticeAcknowledgedAt = ""
    @AppStorage("tagcrypt.healthReminder.enabled") private var healthReminderEnabled = false
    @AppStorage("tagcrypt.record.padding.enabled") private var paddedRecordsEnabled = TagcryptConfigurationDefaults.paddedRecordsEnabled
    @AppStorage("tagcrypt.nfc.wipeUnusedPages") private var wipeUnusedTagPages = TagcryptConfigurationDefaults.wipeUnusedTagPages
    @AppStorage("tagcrypt.nfc.rawPageMode") private var rawPageModeEnabled = TagcryptConfigurationDefaults.rawPageModeEnabled
    @AppStorage("tagcrypt.ntag.lockMode") private var tagLockModeRaw = TagcryptConfigurationDefaults.tagLockModeRaw
    @AppStorage("tagcrypt.ntag.allowCompatible") private var allowCompatibleTags = false
    @AppStorage("tagcrypt.settings.advanced") private var advancedSettingsEnabled = TagcryptConfigurationDefaults.advancedSettingsEnabled
    @State private var showAdvancedSettingsWarning = false
    @State private var organisationKeyListRevision = 0
    /// Review P3-10: Organisation keys read from the Keychain once per change, not per render.
    @State private var organisationKeysCache: [TagLockOrganisationKey] = []
    @State private var showTagKeyRiskAlert = false
    @State private var showIdentifyTag = false
    @State private var showPassphraseOptions = false
    @State private var showSplitShares = false
    @State private var showRestoreShares = false
    @State private var writtenShareIndices: Set<Int> = []
    @State private var writingShareIndex: Int?
    @State private var showCompactHeader = false
    @State private var scrollTracker = ScrollDirectionTracker()
    @State private var pendingSettingsRiskAction: SettingsRiskAction?
    @State private var healthReminderStatus = ""
    @State private var selectedTab: MainTab = .encrypt
    @State private var showSettings = false
    @State private var deferredSettingsAction: DeferredSettingsAction?
    @State private var showFirstUseNotice = false
    @State private var onboardingProgress = TagcryptOnboardingProgress()
    @State private var preparedRecord: Data?
    @State private var pendingEncryptedRecord: Data?
    @State private var pendingRecordSource = "NFC tag"
    @State private var qrPreviewImage: UIImage?
    @State private var qrShareImage: UIImage?
    @State private var qrExportDocument: TagcryptQRDocument?
    @State private var showQRPreview = false
    @State private var showQRShare = false
    @State private var showQRFileExporter = false
    @State private var qrPreviewActionAfterDismissal: QRPreviewAction?
    @State private var isFIDONamePromptPresented = false
    @State private var fidoNameDraft = ""
    @State private var confirmedDifferentPhysicalFIDOKey = false
    @State private var keyBeingRenamed: RegisteredFIDOKey?
    @State private var showRenameFIDOKeySheet = false
    @State private var renameFIDOKeyError: String?
    @State private var selectedFIDOKeyIDs = Set<Data>()
    @State private var showRecoveryPhrasePicker = false
    @State private var showRecoveryShares = false
    @State private var recoveryShareExports: [String] = []
    @State private var preparedRecoveryShareIndex: Int?
    @State private var writingRecoveryShare = false
    @State private var showRecoveryShareImport = false
    @State private var recoveryShareOne = ""
    @State private var recoveryShareTwo = ""
    @State private var showQRScanner = false
    @AppStorage("tagcrypt.fido.enabled") private var legacyUseSecurityKeyUnlock = false
    @AppStorage("tagcrypt.record.unlockMode") private var recordUnlockChoiceRaw = "Passphrase"
    @AppStorage("tagcrypt.record.unlockMode.migrated") private var recordUnlockChoiceMigrated = false
    @State private var banner: String?

    private var recordUnlockChoice: RecordUnlockChoice {
        RecordUnlockChoice(rawValue: recordUnlockChoiceRaw) ?? .passphrase
    }
    private var tagLockOrganisationKeyCount: Int { organisationKeysCache.count }
    private var useSecurityKeyUnlock: Bool { recordUnlockChoice != .passphrase }
    private var passphraseIsRequiredForRecord: Bool { recordUnlockChoice != .fido }
    /// Mirrors VaultCrypto.seal, which enforces the same assessment (16+
    /// UTF-8 bytes, ~80 estimated bits or a generated phrase, no obvious
    /// fragments). A length-only check let the prompt accept phrases that
    /// sealing then refused.
    private var vaultExportPassphraseIsLongEnough: Bool {
        TagcryptPassphraseAssessment.evaluate(vaultExportPassphrase).meetsMinimum
    }

    @ViewBuilder
    private var vaultExportPassphraseStrength: some View {
        if vaultExportPassphrase.isEmpty {
            Text("Enter a passphrase to lock backups. It needs an estimated 80 bits, or use a generated phrase.")
                .font(.caption2).foregroundStyle(palette.muted)
        } else {
            let assessment = TagcryptPassphraseAssessment.evaluate(vaultExportPassphrase)
            Label("Strength: \(assessment.level.title)",
                  systemImage: assessment.meetsMinimum ? "checkmark.shield" : "exclamationmark.shield")
                .font(.caption.weight(.semibold))
                .foregroundStyle(assessment.meetsMinimum ? palette.secondary : .red)
            Text(assessment.meetsMinimum
                 ? assessment.guidance
                 : (assessment.guidance.isEmpty ? "Choose a longer or more varied passphrase." : assessment.guidance))
                .font(.caption2).foregroundStyle(palette.muted)
        }
    }
    private var pendingRecordUnlockMode: FIDOEnvelopeCrypto.UnlockMode {
        guard let pendingEncryptedRecord else { return .passphraseOnly }
        return (try? FIDOEnvelopeCrypto.unlockMode(in: pendingEncryptedRecord)) ?? .passphraseOnly
    }

    private var approximateRecordSize: Int {
        if let index = preparedRecoveryShareIndex,
           recoveryShareExports.indices.contains(index),
           let share = try? TagcryptRecoveryShares.binaryData(from: recoveryShareExports[index]) {
            return rawPageModeEnabled ? selectedSize.bytes : VaultNDEFTextCodec.binaryShareMessageLength(byteCount: share.count)
        }
        guard hasEncryptableContent else { return 0 }
        if useSecurityKeyUnlock, !selectedFIDOKeys.isEmpty {
            if rawPageModeEnabled {
                return (try? FIDOEnvelopeCrypto.estimatedRecordByteLength(vault: vaultDraft, credentialIDs: selectedFIDOKeys.map(\.credentialID), mode: recordUnlockChoice.envelopeMode, padded: paddedRecordsEnabled, targetRecordLength: paddedRecordsEnabled ? nfcTargetRecordLength : nil)) ?? Int.max
            }
            return (try? FIDOEnvelopeCrypto.estimatedNDEFLength(vault: vaultDraft, credentialIDs: selectedFIDOKeys.map(\.credentialID), mode: recordUnlockChoice.envelopeMode, padded: paddedRecordsEnabled, targetRecordLength: paddedRecordsEnabled ? nfcTargetRecordLength : nil)) ?? Int.max
        }
        guard let binaryLength = try? VaultCrypto.estimatedRecordByteLength(vault: vaultDraft, padded: paddedRecordsEnabled, targetRecordLength: paddedRecordsEnabled ? nfcTargetRecordLength : nil) else { return 0 }
        return rawPageModeEnabled ? binaryLength : VaultNDEFTextCodec.binaryMessageLength(byteCount: binaryLength)
    }
    private var hasEncryptableContent: Bool {
        secretEntryMode == .single ? !secret.isEmpty : secretSlots.contains { !$0.secret.isEmpty }
    }
    private var vaultDraft: PasswordVault {
        if secretEntryMode == .single {
            return PasswordVault(secret: secret)
        }
        let slots = secretSlots.filter { !$0.secret.isEmpty }.map { slot in
            let title = slot.title.trimmingCharacters(in: .whitespacesAndNewlines)
            return VaultSecretSlot(title: title.isEmpty ? "Secret" : title, secret: slot.secret)
        }
        return PasswordVault(secret: "", slots: slots)
    }
    private var estimatedNDEFCapacity: Int { max(0, selectedSize.bytes - 12) }
    private var selectedNFCCapacity: Int {
        rawPageModeEnabled ? selectedSize.bytes : (adaptiveNDEFCapacity ?? estimatedNDEFCapacity)
    }
    private var nfcTargetRecordLength: Int {
        rawPageModeEnabled ? selectedNFCCapacity : min(
            selectedSize.safeNDEFPayloadBytes,
            AdaptiveNDEFCapacityPolicy.maximumPayloadBytes(fitting: selectedNFCCapacity,
                                                            messageLength: VaultNDEFTextCodec.binaryMessageLength)
        )
    }
    private var estimatedQRPayloadLength: Int {
        guard hasEncryptableContent else { return 0 }
        let base64Length: Int
        if useSecurityKeyUnlock, !selectedFIDOKeys.isEmpty {
            base64Length = (try? FIDOEnvelopeCrypto.estimatedBase64TextLength(vault: vaultDraft, credentialIDs: selectedFIDOKeys.map(\.credentialID), mode: recordUnlockChoice.envelopeMode)) ?? Int.max
        } else {
            base64Length = (try? VaultCrypto.estimatedBase64TextLength(vault: vaultDraft, padded: true)) ?? Int.max
        }
        let prefixLength = "TAGCRYPT1:".utf8.count
        guard base64Length <= TagcryptQRCodec.maximumPayloadBytes - prefixLength else { return Int.max }
        return prefixLength + base64Length
    }
    private var palette: TagcryptPalette { theme.palette(for: systemColorScheme) }
    private var selectedFIDOKeys: [RegisteredFIDOKey] {
        let selected = fido.registeredKeys.filter { selectedFIDOKeyIDs.contains($0.credentialID) }
        return selected.isEmpty ? Array(fido.registeredKeys.prefix(1)) : selected
    }
    private var fidoNameAlreadyRegistered: Bool {
        let proposed = fidoNameDraft.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
        guard !proposed.isEmpty else { return false }
        return fido.registeredKeys.contains {
            $0.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
                .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current) == proposed
        }
    }
    private var matchingFIDOKeysForScannedRecord: [RegisteredFIDOKey] {
        guard let pendingEncryptedRecord,
              let parameters = try? FIDOEnvelopeCrypto.fidoParameters(in: pendingEncryptedRecord) else { return [] }
        let ids = Set(parameters.map(\.credentialID))
        return fido.registeredKeys.filter { ids.contains($0.credentialID) }
    }
    private var unlistedFIDOParametersForScannedRecord: [FIDORecordKeyCandidate] {
        guard let pendingEncryptedRecord,
              let parameters = try? FIDOEnvelopeCrypto.fidoParameters(in: pendingEncryptedRecord) else { return [] }
        let knownIDs = Set(fido.registeredKeys.map(\.credentialID))
        return parameters.enumerated().compactMap { index, parameter in
            guard !knownIDs.contains(parameter.credentialID) else { return nil }
            return FIDORecordKeyCandidate(credentialID: parameter.credentialID, prfInput: parameter.prfInput, ordinal: index + 1)
        }
    }

    var body: some View {
        ZStack {
            palette.background.ignoresSafeArea()
            if selectedTab == .vault {
                VStack(spacing: 0) {
                    header.padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 8)
                    ScrollView {
                        vaultScreen.padding(.horizontal, 20).padding(.bottom, 30)
                    }
                }
                .frame(maxWidth: 560).frame(maxWidth: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        GeometryReader { geometry in
                            Color.clear.preference(key: MainScrollOffsetKey.self,
                                                   value: geometry.frame(in: .named("mainScroll")).minY)
                        }
                        .frame(height: 0)
                        header
                        if selectedTab == .encrypt {
                        if destination == .nfc { identifyTagCard }
                        secretCard
                        tagCard
                        encryptActions
                        if nfc.isScanning || preparedRecord != nil || nfc.tagPasswordSetupWarning != nil { statusCard }
                        if destination == .nfc { splitSharesCard }
                        passphraseCard
                        } else {
                            decryptScreen
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 18)
                    .padding(.bottom, 34)
                    .frame(maxWidth: 560)
                    .frame(maxWidth: .infinity)
                }
                .coordinateSpace(name: "mainScroll")
                .modifier(MainScrollOffsetReader { handleMainScroll($0) })
                .overlay(alignment: .top) {
                    if showCompactHeader { compactHeader.transition(.move(edge: .top).combined(with: .opacity)) }
                }
                .onChange(of: selectedTab) { _ in
                    scrollTracker.reset()
                    showCompactHeader = false
                }
            }
        }
        .overlay(alignment: .top) {
            if showPassphraseSavedToast {
                Label("Saved to Recovery Vault", systemImage: "checkmark.circle.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(palette.primary)
                    .padding(.horizontal, 16).padding(.vertical, 11)
                    .background(palette.surface, in: Capsule())
                    .overlay(Capsule().stroke(palette.border, lineWidth: 1))
                    .shadow(color: .black.opacity(0.16), radius: 12, y: 5)
                    .padding(.top, 8)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { bottomNavigation }
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button { focusedInput = nil } label: {
                    Image(systemName: "keyboard.chevron.compact.down")
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .accessibilityLabel("Dismiss keyboard")
            }
        }
        .overlay {
            if scenePhase != .active {
                if scenePhase == .inactive && nfc.readerPresentationActive {
                    Color.black.opacity(palette.isDark ? 0.24 : 0.18)
                        .ignoresSafeArea()
                        .overlay(alignment: .top) {
                            Label("NFC session in progress", systemImage: "wave.3.right")
                                .font(.caption.weight(.semibold))
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(.ultraThinMaterial, in: Capsule())
                                .padding(.top, 54)
                        }
                        .zIndex(10)
                } else {
                    palette.background.ignoresSafeArea()
                        .overlay {
                            Label("Tagcrypt hidden", systemImage: "lock.fill")
                                .font(.headline)
                                .foregroundStyle(palette.accentText)
                        }
                        .zIndex(10)
                }
            }
        }
        .overlay {
            if showPassphraseRotationPrompt {
                passphraseRotationPrompt
                    .zIndex(20)
            } else if showVaultExportWarning {
                vaultExportWarningPrompt
                    .zIndex(20)
            } else if showCSVExportWarning {
                csvExportWarningPrompt
                    .zIndex(20)
            } else if showCustomPassphraseWarning {
                customPassphraseWarningPrompt
                    .zIndex(20)
            } else if vaultRenameTarget != nil {
                vaultRenamePrompt
                    .zIndex(20)
            } else if isFIDONamePromptPresented {
                fidoRegistrationPrompt
                    .zIndex(20)
            } else if nfc.overwriteConfirmationNeeded {
                overwriteConfirmation
                    .zIndex(20)
            } else if nfc.sealConfirmationNeeded {
                wholeMemorySealConfirmation
                    .zIndex(20)
            } else if nfc.tagProtectionFallbackNeeded {
                tagProtectionFallbackConfirmation
                    .zIndex(20)
            } else if nfc.capacityAdaptationNeeded {
                capacityAdaptationPrompt
                    .zIndex(20)
            } else if banner != nil {
                messagePrompt
                    .zIndex(20)
            }
        }
        .preferredColorScheme(theme.appearance.colorScheme)
        .sheet(isPresented: $showSettings, onDismiss: presentDeferredSettingsAction) {
            // Sheets are separate presentations and keep their scheme until
            // re-presented; apply the chosen theme inside so it changes live.
            settingsSheet
                .preferredColorScheme(theme.appearance.colorScheme)
                .environment(\.colorScheme, theme.appearance.colorScheme ?? systemColorScheme)
        }
        .confirmationDialog("Delete \(bulkDeleteSelectionCount) selected recovery entries?", isPresented: $showBulkDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete selected entries", role: .destructive) { Task { await deleteSelectedRecoveryEntries() } }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This removes the selected passphrases from this iPhone's Recovery Vault and archive. Existing tags and QR codes are not changed.")
        }
        .sheet(isPresented: $showRenameFIDOKeySheet, onDismiss: { keyBeingRenamed = nil }) { renameFIDOKeySheet }
        .sheet(isPresented: $showRecoveryPhrasePicker) { recoveryPhrasePickerSheet }
        .sheet(isPresented: $showRecoveryShares) {
            NavigationStack {
                List {
                    ForEach(recoveryShareExports.indices, id: \.self) { index in
                        Section("Recovery share \(index + 1) of 3") {
                            Text(recoveryShareExports[index])
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                                .privacySensitive()
                            Button("Copy share \(index + 1)") { copySecret(recoveryShareExports[index]) }
                            Button("Prepare share \(index + 1) for \(selectedSize.rawValue)") {
                                prepareRecoveryShareForNFC(index: index)
                            }
                            .disabled(!recoveryShareFitsSelectedNFC(index: index))
                            Text(rawPageModeEnabled
                                 ? "Fits selected raw memory: \(recoveryShareFitsSelectedNFC(index: index) ? "yes" : "no")"
                                 : "Estimated NDEF size: \(recoveryShareNDEFSize(index: index)) / \(estimatedNDEFCapacity) bytes")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .navigationTitle("2-of-3 recovery shares")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Done") { showRecoveryShares = false }
                    }
                }
                .safeAreaInset(edge: .bottom) {
                    Text("Store each share separately. Any two reconstruct only the encrypted record; one share cannot recover it. Keep the passphrase or required security key separately.")
                        .font(.footnote).foregroundStyle(.secondary).padding()
                        .background(.regularMaterial)
                }
            }
            .presentationDetents([.medium, .large])
        }
        .sheet(isPresented: $showRecoveryShareImport) {
            NavigationStack {
                Form {
                    Section("First share") {
                        TextEditor(text: $recoveryShareOne).font(.system(.footnote, design: .monospaced)).frame(minHeight: 90)
                    }
                    Section("Second share") {
                        TextEditor(text: $recoveryShareTwo).font(.system(.footnote, design: .monospaced)).frame(minHeight: 90)
                    }
                    Section {
                        Text("Shares can be entered in either order. The recovered output is the encrypted record; decryption still requires its passphrase or security key.")
                            .font(.footnote).foregroundStyle(.secondary)
                        Button("Reconstruct encrypted record") { combineRecoveryShares() }
                            .disabled(recoveryShareOne.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || recoveryShareTwo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .navigationTitle("Restore from shares")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Cancel") { showRecoveryShareImport = false } } }
            }
            .presentationDetents([.medium, .large])
        }
        .sheet(isPresented: $showQRPreview, onDismiss: presentPendingQRAction) { qrPreviewSheet }
        .sheet(isPresented: $showQRShare) {
            if let qrShareImage {
                TagcryptQRShareSheet(image: qrShareImage)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "qrcode")
                        .font(.largeTitle)
                    Text("QR image unavailable")
                        .font(.headline)
                    Text("Close this sheet and create the encrypted QR again.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    Button("Done") { showQRShare = false }
                        .buttonStyle(.borderedProminent)
                }
                .padding(28)
            }
        }
        .fileExporter(
            isPresented: $showQRFileExporter,
            document: qrExportDocument,
            contentType: .png,
            defaultFilename: "Tagcrypt-encrypted-QR"
        ) { result in
            if case .failure(let error) = result { banner = "Could not save QR PNG: \(error.localizedDescription)" }
        }
        .fileExporter(isPresented: $showVaultExportFilePicker, document: vaultExportDocument,
                      contentType: .data, defaultFilename: vaultExportFilename) { result in
            if case .failure(let error) = result { banner = "Could not export the encrypted file: \(error.localizedDescription)" }
            if case .success = result {
                banner = vaultExportFilename.contains("organisation")
                    ? "Encrypted Organisation key bundle saved. Keep its passphrase separate."
                    : "Encrypted Recovery Vault backup saved. Keep its export passphrase separately."
            }
        }
        .fileExporter(isPresented: $showCSVExportFilePicker, document: vaultExportDocument,
                      contentType: .data, defaultFilename: "Tagcrypt-recovery-vault.csv.tagcrypt") { result in
            if case .failure(let error) = result { banner = "Could not export encrypted CSV backup: \(error.localizedDescription)" }
            if case .success = result { banner = "Encrypted CSV backup saved. Import it in Tagcrypt with the backup passphrase." }
        }
        .fileImporter(isPresented: $showVaultImportPicker, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                // P3-3: Argon2id (64 MiB) runs off the main actor, like the
                // encrypt/decrypt paths; the UI stays responsive on older phones.
                // Read the picked file inside the importer callback, while access is granted.
                let pickedData: Data
                do { pickedData = try Data(contentsOf: url) }
                catch { banner = "Could not read the selected file. \(error.localizedDescription)"; return }
                Task { @MainActor in
                do {
                    let data = pickedData
                    let text = String(decoding: data, as: UTF8.self)
                    let prefix: String
                    if text.hasPrefix("TAGCRYPTVAULT1:") { prefix = "TAGCRYPTVAULT1:" }
                    else if text.hasPrefix("TAGCRYPTCSV1:") { prefix = "TAGCRYPTCSV1:" }
                    else if text.hasPrefix("TAGCRYPTLOCK1:") { prefix = "TAGCRYPTLOCK1:" }
                    else { throw VaultError.malformedRecord }
                    guard let record = Data(base64Encoded: String(text.dropFirst(prefix.count))) else { throw VaultError.malformedRecord }
                    guard let phrase = vaultExportPassphrase.isEmpty ? nil : vaultExportPassphrase else {
                        banner = "Enter the backup passphrase before importing this encrypted file."
                        return
                    }
                    banner = "Decrypting the backup…"
                    let decoded = try await Task.detached(priority: .userInitiated) {
                        try VaultCrypto.open(record, passphrase: phrase)
                    }.value
                    let contents = decoded.slots?.first(where: { $0.title == "Recovery Vault backup" || $0.title == "Tag lock key bundle" })?.secret ?? decoded.secret
                    let imported: [TagcryptVaultEntry]
                    var importedTagLockKeys: TagLockKeyBundle?
                    if prefix == "TAGCRYPTLOCK1:" {
                        guard let json = contents.data(using: .utf8) else { throw VaultError.malformedRecord }
                        importedTagLockKeys = try JSONDecoder().decode(TagLockKeyBundle.self, from: json)
                        imported = []
                    }
                    else if prefix == "TAGCRYPTCSV1:" { imported = try decodeVaultCSV(contents) }
                    else {
                        guard let json = contents.data(using: .utf8) else { throw VaultError.malformedRecord }
                        if let backup = try? JSONDecoder().decode(TagcryptVaultBackup.self, from: json) {
                            imported = backup.entries
                            importedTagLockKeys = backup.tagLockKeys
                        } else {
                            // Backward compatibility with TAGCRYPTVAULT1 files that
                            // contained only the entry array.
                            imported = try JSONDecoder().decode([TagcryptVaultEntry].self, from: json)
                        }
                    }
                    if let importedTagLockKeys {
                        try TagLockKeyStore.importBundle(importedTagLockKeys)
                        organisationKeyListRevision += 1
                    }
                    let current = try TagcryptVaultStore.load()
                    let ids = Set(current.map(\.id))
                    vaultEntries = current + imported.filter { !ids.contains($0.id) }
                    try TagcryptVaultStore.save(vaultEntries)
                    banner = prefix == "TAGCRYPTLOCK1:" ? "Imported encrypted Organisation tag-lock key bundle." : "Imported \(imported.count) encrypted Vault entries\(importedTagLockKeys == nil ? "" : " and tag-lock recovery keys")."
                } catch { banner = "Could not import the encrypted Vault backup. Check the file and backup passphrase. \(error.localizedDescription)" }
                }
            case .failure(let error): banner = "Could not open the encrypted Vault backup: \(error.localizedDescription)"
            }
        }
        .sheet(isPresented: $showQRScanner) {
            NavigationStack {
                TagcryptQRScanner(onResult: acceptScannedQR, onFailure: { banner = $0 })
                    .ignoresSafeArea()
                    .navigationTitle("Scan encrypted QR")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Cancel") { showQRScanner = false } } }
            }
            .presentationDetents([.large])
        }
        .fullScreenCover(isPresented: $showFirstUseNotice) {
            firstUseNotice
                .interactiveDismissDisabled()
                // Same as Settings: apply the chosen theme inside the cover so
                // system controls (toggles, pickers) match the light palette.
                .preferredColorScheme(theme.appearance.colorScheme)
                .environment(\.colorScheme, theme.appearance.colorScheme ?? systemColorScheme)
        }
        .onChange(of: scenePhase) { phase in
            if phase == .background {
                cryptoOperation = UUID()
                isCryptoWorking = false
                secret = ""
                passphrase = ""
                passphraseConfirmation = ""
                generatedPassphraseValue = ""
                generatedPassphraseToInstall = nil
                rotationVaultLabel = ""
                generatedPassphraseIsSaved = false
                showPassphraseRotationPrompt = false
                vaultEntries = []
                archivedPassphrases = []
                isRecoveryVaultUnlocked = false
                revealedVaultEntryIDs = []
                revealedArchivedPassphraseIDs = []
                vaultRenameTarget = nil
                vaultRenameDraft = ""
                vaultExportDocument = nil
                showVaultExportWarning = false
                showVaultExportFilePicker = false
                showCSVExportFilePicker = false
                showCSVExportWarning = false
                showVaultImportPicker = false
                vaultExportPassphrase = ""
                showRecoveryPhrasePicker = false
                isFIDONamePromptPresented = false
                fidoNameDraft = ""
                customPassphraseAcknowledged = false
                showSecret = false
                showPassphrase = false
                secretSlots = [SecretSlotDraft(title: "Password 1")]
                decryptedVault = nil
                preparedRecord = nil
                pendingEncryptedRecord = nil
            } else if phase == .active {
                nfc.readerPresentationDidDismiss()
                #if DEBUG
                guard screenshotPreviewMode == nil else { return }
                #endif
                restoreGeneratedPassphrase()
                refreshArchivedPassphrases()
                refreshVaultEntries()
            }
        }
        .onChange(of: secret) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: secretSlots) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: secretEntryMode) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: showSecret) { visible in
            let generation = UUID()
            revealGeneration = generation
            guard visible else { return }
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 60_000_000_000)
                if revealGeneration == generation { showSecret = false }
            }
        }
        .onChange(of: passphrase) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: passphraseConfirmation) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: selectedSize) { _ in
            preparedRecord = nil
            adaptiveNDEFCapacity = nil
        }
        .onChange(of: destination) { _ in
            preparedRecord = nil
            adaptiveNDEFCapacity = nil
        }
        .onChange(of: recordUnlockChoiceRaw) { _ in
            preparedRecord = nil
            invalidateCryptoOperation()
        }
        .onChange(of: pendingEncryptedRecord) { _ in
            invalidateCryptoOperation()
        }
        .onChange(of: nfc.identifiedSizeName) { name in
            guard let name, let size = TagSize(rawValue: name), size != selectedSize else { return }
            withAnimation(.easeInOut(duration: 0.2)) { selectedSize = size }
            nfc.setStatus("Tag size set to \(name) from the scan.")
        }
        .onChange(of: selectedTab) { tab in
            if tab == .vault && vaultRequiresFaceID && !isRecoveryVaultUnlocked {
                Task { await authenticateRecoveryVault() }
            }
            if tab != .vault {
                isRecoveryVaultUnlocked = false
                vaultSelectionMode = false
                selectedVaultEntryIDs.removeAll()
                selectedArchivedPhraseIDs.removeAll()
            }
        }
        .onAppear {
            if !recordUnlockChoiceMigrated {
                if legacyUseSecurityKeyUnlock { recordUnlockChoiceRaw = RecordUnlockChoice.both.rawValue }
                legacyUseSecurityKeyUnlock = false
                recordUnlockChoiceMigrated = true
            }
            #if DEBUG
            if screenshotPreviewMode != nil {
                configureScreenshotPreview()
            } else {
                showFirstUseNotice = !TagcryptOnboarding.isComplete(acknowledgedVersion: onboardingAcknowledgedVersion)
                restoreGeneratedPassphrase()
                restoreFIDOProfiles()
                refreshArchivedPassphrases()
                refreshVaultEntries()
            }
            #else
            showFirstUseNotice = !TagcryptOnboarding.isComplete(acknowledgedVersion: onboardingAcknowledgedVersion)
            restoreGeneratedPassphrase()
            restoreFIDOProfiles()
            refreshArchivedPassphrases()
            refreshVaultEntries()
            #endif
            nfc.onRead = { record in
                Task { @MainActor in
                    pendingEncryptedRecord = record
                    pendingRecordSource = "NFC tag"
                    preparedRecord = nil
                    decryptedVault = nil
                    showSecret = false
                    if VaultCrypto.requiresPassphrase(for: record) {
                        passphraseConfirmation = ""
                        selectedTab = .decrypt
                        nfc.setStatus("Encrypted record read. Check the saved passphrase or enter this tag's passphrase, then decrypt.")
                    } else {
                        selectedTab = .decrypt
                        nfc.setStatus("Security-key record read. Unlock it with a registered key.")
                    }
                }
            }
            nfc.onRecoveryShare = { share in
                Task { @MainActor in
                    let trimmed = share.trimmingCharacters(in: .whitespacesAndNewlines)
                    if [recoveryShareOne, recoveryShareTwo].contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines) == trimmed }) {
                        banner = "That share is already in. Scan a different tag from the same set."
                        return
                    }
                    if recoveryShareOne.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        recoveryShareOne = share
                    } else if recoveryShareTwo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        recoveryShareTwo = share
                    } else {
                        banner = "Two shares are already in. Rebuild the record or clear them before scanning another."
                        return
                    }
                    selectedTab = .decrypt
                    showRestoreShares = true
                    if !recoveryShareOne.isEmpty && !recoveryShareTwo.isEmpty {
                        combineRecoveryShares()
                    } else {
                        nfc.setStatus("Share 1 of 2 read. Scan a second share tag from the same set.")
                    }
                }
            }
            nfc.allowCompatibleTags = allowCompatibleTags
            organisationKeysCache = (try? TagLockKeyStore.loadOrganisationKeys()) ?? []
            nfc.onWriteVerified = {
                if writingRecoveryShare {
                    writingRecoveryShare = false
                    if let index = writingShareIndex { writtenShareIndices.insert(index) }
                    writingShareIndex = nil
                } else {
                    associateCurrentPassphraseWithWrittenTag()
                }
            }
        }
    }

    private var passphraseRotationPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text("Keep the current passphrase?").font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("This phrase may unlock tags you already wrote. Save it to the Vault, or replace it without saving a new copy. Discarding may make records that use it unrecoverable. Existing saved copies remain unchanged.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                TextField("Name this passphrase in the Vault", text: $rotationVaultLabel)
                    .focused($focusedInput, equals: .prompt)
                    .textInputAutocapitalization(.words).autocorrectionDisabled()
                    .font(TagcryptPromptTypography.field)
                    .focused($rotationVaultLabelFocused)
                    .submitLabel(.done)
                    .onSubmit { rotationVaultLabelFocused = false }
                    .padding(12).background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                Button("Save with this name & generate new") {
                    rotationVaultLabelFocused = false
                    confirmPassphraseRotation()
                }
                    .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                    .disabled(rotationVaultLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                Button("Discard current phrase & generate new", role: .destructive) {
                    rotationVaultLabelFocused = false
                    discardCurrentPassphraseAndRotate()
                }
                    .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                    .foregroundStyle(.red).background(Color.red.opacity(0.10), in: Capsule())
                Button("Cancel", role: .cancel) {
                    generatedPassphraseToInstall = nil
                    rotationVaultLabel = ""
                    showPassphraseRotationPrompt = false
                }
                .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1))
            .padding(24)
        }
        .transition(.opacity)
    }

    private var vaultExportWarningPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text(vaultExportSelection.map { "Back up \($0.count) selected entries" } ?? "Back up your Recovery Vault")
                    .font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("The default backup is encrypted. Choose a separate, strong backup passphrase and keep it somewhere safe; Tagcrypt cannot recover it.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                SecureField("Passphrase to lock this backup", text: $vaultExportPassphrase)
                    .focused($focusedInput, equals: .prompt)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(TagcryptPromptTypography.field)
                    .padding(12).background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                    .privacySensitive()
                vaultExportPassphraseStrength
                Button("Save encrypted backup to Files") { prepareVaultExport() }
                .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                .disabled(!vaultExportPassphraseIsLongEnough)
                .opacity(vaultExportPassphraseIsLongEnough ? 1 : 0.48)
                Button("Export encrypted CSV backup…") {
                    showVaultExportWarning = false
                    showCSVExportWarning = true
                }
                .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.accentText)
                Button("Cancel") { showVaultExportWarning = false }
                    .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1))
            .padding(24)
        }
        .transition(.opacity)
    }

    private var csvExportWarningPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text(vaultExportSelection.map { "Back up \($0.count) selected entries as CSV" } ?? "Back up the Vault as CSV")
                    .font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("The CSV is encrypted before it is saved. Choose a separate, strong backup passphrase. The saved file is not a readable CSV until it is decrypted.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                SecureField("Passphrase to lock this backup", text: $vaultExportPassphrase)
                    .focused($focusedInput, equals: .prompt)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(TagcryptPromptTypography.field)
                    .padding(12).background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                    .privacySensitive()
                vaultExportPassphraseStrength
                Button("Save encrypted CSV backup") { prepareCSVExport() }
                .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                .disabled(!vaultExportPassphraseIsLongEnough)
                .opacity(vaultExportPassphraseIsLongEnough ? 1 : 0.48)
                Button("Cancel") { showCSVExportWarning = false }
                    .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1))
            .padding(24)
        }
        .transition(.opacity)
    }

    private func prepareVaultExport() {
        guard vaultExportPassphraseIsLongEnough else { return }
        do {
            let entries: [TagcryptVaultEntry]
            if let vaultExportSelection { entries = vaultExportSelection }
            else { entries = try vaultExportEntries() }
            let keyBundle = vaultExportSelection == nil ? try TagLockKeyStore.exportBundle(includeAutoKey: true) : nil
            let backup = TagcryptVaultBackup(entries: entries, tagLockKeys: keyBundle)
            let json = try JSONEncoder().encode(backup)
            let encryptedBackup = PasswordVault(secret: "", slots: [VaultSecretSlot(title: "Recovery Vault backup", secret: String(decoding: json, as: UTF8.self))])
            let payload = try VaultCrypto.seal(encryptedBackup, passphrase: vaultExportPassphrase)
            vaultExportDocument = TagcryptVaultExport(data: Data(("TAGCRYPTVAULT1:" + payload.base64EncodedString()).utf8))
            vaultExportFilename = "Tagcrypt-recovery-vault.tagcryptvault"
            showVaultExportWarning = false
            showVaultExportFilePicker = true
        } catch {
            showVaultExportWarning = false
            banner = "Could not prepare the encrypted Vault backup. \(error.localizedDescription)"
        }
    }

    private func prepareTagLockKeyExport() {
        guard vaultExportPassphraseIsLongEnough else { return }
        do {
            let keys = try TagLockKeyStore.loadOrganisationKeys()
            guard !keys.isEmpty else { banner = "Create an Organisation key before exporting."; return }
            let bundle = TagLockKeyBundle(autoKey: nil, organisationKeys: keys)
            let json = try JSONEncoder().encode(bundle)
            let vault = PasswordVault(secret: "", slots: [VaultSecretSlot(title: "Tag lock key bundle", secret: String(decoding: json, as: UTF8.self))])
            let payload = try VaultCrypto.seal(vault, passphrase: vaultExportPassphrase)
            vaultExportDocument = TagcryptVaultExport(data: Data(("TAGCRYPTLOCK1:" + payload.base64EncodedString()).utf8))
            vaultExportFilename = "Tagcrypt-organisation-keys.tagcryptlock"
            showVaultExportFilePicker = true
        } catch {
            banner = "Could not prepare the encrypted Organisation key bundle. \(error.localizedDescription)"
        }
    }

    private var customPassphraseWarningPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text("Custom passphrases are not strength-scored").font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("A phrase can meet the minimum length and still be easy to guess. Anyone with a copy of the tag can make offline guesses. Tagcrypt recommends its randomly generated passphrase; keep a separate recovery copy either way.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                Button("Continue with my own phrase") { customPassphraseAcknowledged = true; showCustomPassphraseWarning = false }
                    .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13).foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                Button("Cancel") { showCustomPassphraseWarning = false }
                    .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1)).padding(24)
        }
    }

    private var messagePrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text("Tagcrypt").font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text(banner ?? "").font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                Button("OK") { banner = nil }
                    .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                    .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1)).padding(24)
        }
    }

    private var vaultRenamePrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text("Rename saved label").font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                TextField("Tag nickname", text: $vaultRenameDraft)
                    .focused($focusedInput, equals: .prompt)
                    .textInputAutocapitalization(.words).autocorrectionDisabled().font(.system(size: 17, design: .rounded)).padding(12)
                    .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                Button("Save label") {
                    guard let vaultRenameTarget else { return }
                    do {
                        vaultEntries = try TagcryptVaultStore.rename(vaultRenameTarget, to: vaultRenameDraft)
                        self.vaultRenameTarget = nil
                    } catch {
                        self.vaultRenameTarget = nil
                        banner = "Could not rename the Vault entry. \(error.localizedDescription)"
                    }
                }
                .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                Button("Cancel") { vaultRenameTarget = nil }
                    .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1)).padding(24)
        }
    }

    private var fidoRegistrationPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 14) {
                Text("Name this security key").font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                TextField("Key name", text: $fidoNameDraft)
                    .focused($focusedInput, equals: .prompt)
                    .textInputAutocapitalization(.words).autocorrectionDisabled().font(.system(size: 17, design: .rounded)).padding(12)
                    .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                Text("Use a label you can recognize, such as YubiKey USB-C.")
                    .font(TagcryptPromptTypography.supporting).foregroundStyle(palette.secondary)
                if !fido.registeredKeys.isEmpty {
                    Text("A security key can create more than one credential. Apple does not provide Tagcrypt with a reliable physical-key serial, so different registrations may still be the same key.")
                        .font(TagcryptPromptTypography.supporting).foregroundStyle(palette.secondary)
                    Toggle("I am registering a different physical key", isOn: $confirmedDifferentPhysicalFIDOKey)
                        .font(TagcryptPromptTypography.supporting)
                        .tint(palette.accent)
                }
                if fidoNameAlreadyRegistered {
                    Text("That name is already in your registered list. A different name does not prove this is a separate physical key.")
                        .font(.system(size: 14, weight: .medium, design: .rounded)).foregroundStyle(.red)
                }
                Button("Register key") {
                    let name = fidoNameDraft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !name.isEmpty else { return }
                    isFIDONamePromptPresented = false
                    Task { await registerFIDOKey(named: name) }
                }
                .disabled(fidoNameDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || fidoNameAlreadyRegistered || (!fido.registeredKeys.isEmpty && !confirmedDifferentPhysicalFIDOKey))
                .font(TagcryptPromptTypography.action).frame(maxWidth: .infinity).padding(.vertical, 13)
                .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                Button("Cancel") { isFIDONamePromptPresented = false; confirmedDifferentPhysicalFIDOKey = false }
                    .font(TagcryptPromptTypography.cancel).frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1)).padding(24)
        }
    }

    private var overwriteConfirmation: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity)
                .ignoresSafeArea()
                .contentShape(Rectangle())
                .onTapGesture { nfc.cancelOverwrite() }

            VStack(alignment: .leading, spacing: 16) {
                Text("Replace this tag’s existing data?")
                    .font(TagcryptPromptTypography.title)
                    .foregroundStyle(palette.primary)
                Text("Writing replaces every record currently stored on this tag. Nothing will be written until you confirm.")
                    .font(TagcryptPromptTypography.body)
                    .foregroundStyle(palette.secondary)
                Button(role: .destructive) {
                    nfc.confirmOverwrite()
                } label: {
                    Text("Replace existing tag data")
                        .font(TagcryptPromptTypography.action)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .background(palette.input, in: Capsule())
                }
                .tint(.red)
                Button("Cancel", role: .cancel) { nfc.cancelOverwrite() }
                    .font(TagcryptPromptTypography.cancel)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .foregroundStyle(palette.secondary)
            }
            .padding(22)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(palette.border, lineWidth: 1)
            }
            .padding(.horizontal, 28)
            .accessibilityAddTraits(.isModal)
        }
        .transition(.opacity)
        .animation(.easeInOut(duration: 0.18), value: nfc.overwriteConfirmationNeeded)
    }

    private var wholeMemorySealConfirmation: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity)
                .ignoresSafeArea()
                .contentShape(Rectangle())
                .onTapGesture { nfc.cancelWholeMemorySeal() }

            VStack(alignment: .leading, spacing: 16) {
                Text("Permanently seal this tag?")
                    .font(TagcryptPromptTypography.title)
                    .foregroundStyle(palette.primary)
                Text("This irreversibly freezes all user-memory pages, the Capability Container and the configuration pages, so the tag reports read-only and no password can be added later. The encrypted record should remain readable, but it can never be replaced, and Tagcrypt cannot recover it if the tag or record is damaged. The tag's reported model is not proof of genuine NXP silicon. This seal is experimental: it has been verified on one NTAG216-compatible tag, not yet on genuine NXP chips. Confirm only for a disposable tag.")
                    .font(TagcryptPromptTypography.body)
                    .foregroundStyle(palette.secondary)
                Button(role: .destructive) { nfc.confirmWholeMemorySeal() } label: {
                    Text("I understand — rescan this tag to seal it")
                        .font(TagcryptPromptTypography.action)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .background(palette.input, in: Capsule())
                }
                .tint(.red)
                Button("Cancel — write no lock bits", role: .cancel) { nfc.cancelWholeMemorySeal() }
                    .font(TagcryptPromptTypography.cancel)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .foregroundStyle(palette.secondary)
            }
            .padding(22)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(palette.border, lineWidth: 1)
            }
            .padding(.horizontal, 28)
            .accessibilityAddTraits(.isModal)
        }
        .transition(.opacity)
        .animation(.easeInOut(duration: 0.18), value: nfc.sealConfirmationNeeded)
    }

    private var capacityAdaptationPrompt: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 16) {
                Text("Fit this tag’s capacity?")
                    .font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("This tag reports \(nfc.reportedNDEFCapacity ?? 0) NDEF bytes; the prepared record needs \(nfc.requiredNDEFMessageBytes ?? 0). Nothing was written. Tagcrypt can encrypt a compact record sized to the capacity this tag reported.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                if preparedRecoveryShareIndex != nil {
                    Text("Recovery shares cannot be resized. Choose a larger tag or a different carrier.")
                        .font(TagcryptPromptTypography.supporting).foregroundStyle(palette.secondary)
                } else {
                    Button {
                        guard let capacity = nfc.reportedNDEFCapacity else { return }
                        adaptiveNDEFCapacity = capacity
                        nfc.dismissCapacityAdaptation()
                        Task { await encrypt() }
                    } label: {
                        Text("Re-encrypt for this tag")
                            .font(TagcryptPromptTypography.action)
                            .frame(maxWidth: .infinity).padding(.vertical, 13)
                            .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                    }
                }
                Button("Cancel — nothing was written", role: .cancel) { nfc.dismissCapacityAdaptation() }
                    .font(TagcryptPromptTypography.cancel)
                    .frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1))
            .padding(.horizontal, 28).accessibilityAddTraits(.isModal)
        }
        .transition(.opacity)
    }

    private var tagProtectionFallbackConfirmation: some View {
        ZStack {
            Color.black.opacity(TagcryptPromptTypography.backdropOpacity).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 16) {
                Text("Tag protection isn’t available")
                    .font(TagcryptPromptTypography.title).foregroundStyle(palette.primary)
                Text("\(nfc.tagProtectionFallbackReason). The tag may still support ordinary encrypted NDEF. Tagcrypt has not written anything yet.")
                    .font(TagcryptPromptTypography.body).foregroundStyle(palette.secondary)
                Button { nfc.continueWithoutTagProtection() } label: {
                    Text("Write encrypted record only")
                        .font(TagcryptPromptTypography.action)
                        .frame(maxWidth: .infinity).padding(.vertical, 13)
                        .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                }
                Text("This same tag will be rescanned. Password protection and unused-page randomization will be skipped.")
                    .font(TagcryptPromptTypography.supporting).foregroundStyle(palette.secondary)
                Button("Cancel", role: .cancel) { nfc.cancelTagProtectionFallback() }
                    .font(TagcryptPromptTypography.cancel)
                    .frame(maxWidth: .infinity).padding(.vertical, 8).foregroundStyle(palette.secondary)
            }
            .padding(22).background(palette.surface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(palette.border, lineWidth: 1))
            .padding(.horizontal, 28).accessibilityAddTraits(.isModal)
        }
        .transition(.opacity)
    }

    private func presentPendingQRAction() {
        guard let action = qrPreviewActionAfterDismissal else { return }
        qrPreviewActionAfterDismissal = nil
        DispatchQueue.main.async {
            switch action {
            case .share: showQRShare = true
            case .export: showQRFileExporter = true
            }
        }
    }

    private func restoreFIDOProfiles() {
        do {
            try fido.restore()
        } catch {
            banner = "Saved security-key profiles could not be loaded. They were left unchanged. \(error.localizedDescription)"
        }
    }

    private func presentDeferredSettingsAction() {
        guard let action = deferredSettingsAction else { return }
        deferredSettingsAction = nil
        DispatchQueue.main.async {
            switch action {
            case .registerFIDOKey:
                isFIDONamePromptPresented = true
            case .exportVault:
                refreshVaultEntries()
                refreshArchivedPassphrases()
                showVaultExportWarning = true
            case .renameFIDOKey:
                showRenameFIDOKeySheet = true
            }
        }
    }

    /// Slim bar that slides in when the user scrolls back up, iOS-style:
    /// hidden while scrolling down, eases in after a short upward scroll.
    private var compactHeader: some View {
        HStack(spacing: 9) {
            Image("AppMark")
                .resizable()
                .scaledToFit()
                .frame(width: 24, height: 24)
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                .accessibilityHidden(true)
            Text("Tagcrypt")
                .font(.system(size: 17, weight: .semibold, design: .serif))
                .foregroundStyle(palette.primary)
            Text(selectedTab == .vault ? "Recovery Vault" : selectedTab.rawValue)
                .font(.system(size: 15, weight: .regular, design: .rounded))
                .foregroundStyle(palette.muted)
            Spacer()
            Button { showSettings = true } label: {
                Image(systemName: "gearshape")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(palette.secondary)
                    .frame(width: 34, height: 34)
                    .background(palette.surface.opacity(0.7), in: Circle())
            }
            .accessibilityLabel("Settings")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 7)
        .frame(maxWidth: 560)
        .frame(maxWidth: .infinity)
        .background {
            Rectangle()
                .fill(.ultraThinMaterial)
                .overlay(alignment: .bottom) {
                    Rectangle().fill(palette.border.opacity(0.6)).frame(height: 0.5)
                }
                .ignoresSafeArea(edges: .top)
        }
    }

    private func handleMainScroll(_ offset: CGFloat) {
        let delta = scrollTracker.update(offset)
        // Near the top the full header is on screen: no compact bar.
        if offset > -90 {
            if showCompactHeader { withAnimation(.easeOut(duration: 0.22)) { showCompactHeader = false } }
            return
        }
        if delta < -3 {
            if showCompactHeader { withAnimation(.easeInOut(duration: 0.28)) { showCompactHeader = false } }
        } else if scrollTracker.upwardTravel > 16, !showCompactHeader {
            withAnimation(.spring(response: 0.55, dampingFraction: 0.9)) { showCompactHeader = true }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 10) {
                Image("AppMark")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 34, height: 34)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .accessibilityHidden(true)
                Text("Tagcrypt")
                    .font(.system(size: 22, weight: .bold, design: .serif))
                    .foregroundStyle(palette.primary)
                Spacer()
                Button { showSettings = true } label: {
                    Image(systemName: "gearshape")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(palette.secondary)
                        .frame(width: 42, height: 42)
                        .background(palette.surface, in: Circle())
                }
                .accessibilityLabel("Settings")
            }
            Text(selectedTab == .vault ? "Recovery Vault" : selectedTab.rawValue)
                .font(.system(size: 29, weight: .semibold, design: .rounded))
                .foregroundStyle(palette.primary)
        }
    }

    private var secretCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("SECRET", detail: secretEntryMode == .single ? "One secret" : "Named slots share one passphrase")
            Picker("Secret format", selection: $secretEntryMode) {
                ForEach(SecretEntryMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            if secretEntryMode == .single {
                secretEditor
            } else {
                ForEach($secretSlots) { $slot in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            TextField("Slot name", text: $slot.title)
                                .focused($focusedInput, equals: .slotTitle(slot.id))
                                .textInputAutocapitalization(.words)
                                .autocorrectionDisabled()
                            if secretSlots.count > 1 {
                                Button(role: .destructive) {
                                    secretSlots.removeAll { $0.id == slot.id }
                                } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .accessibilityLabel("Remove \(slot.title.isEmpty ? "secret" : slot.title) slot")
                            }
                        }
                        HStack(spacing: 8) {
                            Group {
                                if slot.revealed {
                                    TextField("Password or secret", text: $slot.secret)
                                        .focused($focusedInput, equals: .slotSecret(slot.id))
                                } else {
                                    SecureField("Password or secret", text: $slot.secret)
                                        .focused($focusedInput, equals: .slotSecret(slot.id))
                                }
                            }
                            // This field captures an existing secret for encryption. Mark it
                            // as an existing password so iOS doesn't offer a generated one.
                            .textContentType(.oneTimeCode)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.system(.body, design: .monospaced))
                            .privacySensitive()
                            Button { slot.revealed.toggle() } label: {
                                Image(systemName: slot.revealed ? "eye.slash" : "eye")
                                    .foregroundStyle(palette.secondary)
                            }
                            .accessibilityLabel(slot.revealed ? "Hide slot secret" : "Reveal slot secret")
                        }
                    }
                    .padding(12)
                    .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                }
                Button {
                    secretSlots.append(SecretSlotDraft(title: "Password \(secretSlots.count + 1)"))
                } label: {
                    Label("Add another slot", systemImage: "plus.circle")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(palette.accentText)
                }
                .buttonStyle(.plain)
            }

            HStack(alignment: .firstTextBaseline) {
                Text(hasEncryptableContent
                     ? (destination == .nfc
                        ? "About \(approximateRecordSize) / \(selectedNFCCapacity) bytes \(rawPageModeEnabled ? "in raw memory" : "in NDEF")"
                        : "About \(estimatedQRPayloadLength) / \(TagcryptQRCodec.maximumPayloadBytes) bytes in QR")
                     : "Enter a secret to estimate the total write size")
                    .font(.caption)
                    .foregroundStyle(palette.muted)
                Spacer(minLength: 8)
                Button("Clear") {
                    secret = ""
                    secretSlots = [SecretSlotDraft(title: "Password 1")]
                    preparedRecord = nil
                    showSecret = false
                }
                .font(.caption)
                .foregroundStyle(palette.accentText)
            }
        }
        .padding(18)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))
    }

    private var secretEditor: some View {
        HStack(alignment: .top, spacing: 10) {
            Group {
                if showSecret {
                    TextEditor(text: $secret)
                        .focused($focusedInput, equals: .secret)
                } else {
                    SecureField("Type a password or recovery secret", text: $secret)
                        .textContentType(.oneTimeCode)
                        .focused($focusedInput, equals: .secret)
                        .padding(.top, 8)
                }
            }
            .font(.system(.body, design: .monospaced))
            .foregroundStyle(palette.primary)
            .tint(palette.accentText)
            .privacySensitive()
            .frame(minHeight: 94)
            .scrollContentBackground(.hidden)
            Button { showSecret.toggle() } label: {
                Image(systemName: showSecret ? "eye.slash" : "eye")
                    .foregroundStyle(palette.secondary)
                    .padding(8)
            }
            .accessibilityLabel(showSecret ? "Hide secret" : "Reveal secret")
        }
    }

    private var tagCard: some View {
        VStack(alignment: .leading, spacing: 13) {
            sectionTitle("SAVE TO", detail: "Choose a destination")
            Picker("Save to", selection: $destination) {
                ForEach(RecordDestination.allCases) { choice in
                    Text(choice.rawValue).tag(choice)
                }
            }
            .pickerStyle(.segmented)

            if destination == .nfc {
                HStack(spacing: 8) {
                    ForEach(TagSize.allCases) { size in
                        Button {
                            selectedSize = size
                        } label: {
                            VStack(spacing: 4) {
                                Text(size.rawValue).font(.system(size: 13, weight: .semibold))
                                Text("\(size.bytes) B").font(.caption2.monospacedDigit())
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .foregroundStyle(selectedSize == size ? palette.onAccent : palette.secondary)
                            .background(selectedSize == size ? palette.accent : palette.input, in: RoundedRectangle(cornerRadius: 12))
                        }
                        .buttonStyle(.plain)
                    }
                }
                if hasEncryptableContent || preparedRecoveryShareIndex != nil {
                    HStack(spacing: 8) {
                        Image(systemName: approximateRecordSize > selectedNFCCapacity ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(approximateRecordSize > selectedNFCCapacity ? Color.orange : Color.green)
                        Text("About \(approximateRecordSize) / \(selectedNFCCapacity) bytes \(rawPageModeEnabled ? "in raw memory" : "in NDEF")")
                            .foregroundStyle(palette.secondary)
                    }
                    .font(.caption)
                } else {
                    Text("Tag capacity is checked again before writing.")
                        .font(.caption)
                        .foregroundStyle(palette.secondary)
                }
            } else {
                Text(hasEncryptableContent
                     ? "About \(estimatedQRPayloadLength) / \(TagcryptQRCodec.maximumPayloadBytes) bytes. Larger records create denser codes."
                     : "QR size adjusts to the encrypted record.")
                    .font(.caption)
                    .foregroundStyle(palette.secondary)
            }
            TextField("Tag nickname (optional)", text: $tagNickname)
                .focused($focusedInput, equals: .nickname)
                .textInputAutocapitalization(.words)
                .autocorrectionDisabled()
                .padding(12)
                .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
            Text(recordUnlockChoice == .fido
                 ? "After an NFC write is verified, Tagcrypt saves its label and selected key names to this iPhone's Vault."
                 : "After an NFC write is verified, Tagcrypt saves its passphrase and label to this iPhone's Vault.")
                .font(.caption).foregroundStyle(palette.muted)
        }
        .padding(18)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))
    }

    private var passphraseCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            sectionTitle("UNLOCK METHOD", detail: "Choose how this record can be opened")
            Picker("Unlock method", selection: $recordUnlockChoiceRaw) {
                ForEach(RecordUnlockChoice.allCases) { choice in
                    Text(choice.rawValue).tag(choice.rawValue)
                }
            }
            .pickerStyle(.segmented)
            Divider().overlay(palette.border)
            if passphraseIsRequiredForRecord {
                sectionTitle("PASSPHRASE", detail: passphraseMode == "perTag" ? "For this record" : "Saved default")
            HStack(spacing: 8) {
                Group {
                    if showPassphrase {
                        TextField("Enter a passphrase", text: $passphrase)
                            .focused($focusedInput, equals: .passphrase)
                    } else {
                        SecureField("Enter a passphrase", text: $passphrase)
                            .focused($focusedInput, equals: .passphrase)
                    }
                }
                .textContentType(.newPassword)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
                .privacySensitive()
                Button { showPassphrase.toggle() } label: {
                    Image(systemName: showPassphrase ? "eye.slash" : "eye")
                        .foregroundStyle(palette.secondary)
                }
                .accessibilityLabel(showPassphrase ? "Hide passphrase" : "Reveal passphrase")
            }
            .padding(13)
            .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
            if passphraseMode == "perTag" {
                SecureField("Confirm passphrase before encrypting", text: $passphraseConfirmation)
                    .focused($focusedInput, equals: .confirmation)
                    .textContentType(.newPassword)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                    .padding(13)
                    .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                    .privacySensitive()
            }
            if passphraseIsRequiredForRecord &&
                passphrase.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping.count < 16 {
                Text(passphrase.isEmpty ? "Enter at least 16 characters." : "Use at least 16 characters.")
                    .font(.caption2).foregroundStyle(.red)
            }
            if passphraseIsRequiredForRecord, !passphrase.isEmpty {
                let assessment = TagcryptPassphraseAssessment.evaluate(passphrase)
                Label("Passphrase strength: \(assessment.level.title)", systemImage: assessment.meetsMinimum ? "checkmark.shield" : "exclamationmark.shield")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(assessment.meetsMinimum ? palette.secondary : .red)
                Text(assessment.meetsMinimum
                     ? assessment.guidance
                     : "Choose a longer or more varied passphrase. New records require an estimated 80 bits or a generated phrase.")
                    .font(.caption2).foregroundStyle(palette.muted)
            }
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { showPassphraseOptions.toggle() }
            } label: {
                HStack {
                    Label("Passphrase options", systemImage: "key")
                        .font(.subheadline.weight(.medium))
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.semibold))
                        .rotationEffect(.degrees(showPassphraseOptions ? 180 : 0))
                }
                .foregroundStyle(palette.accentText)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if showPassphraseOptions {
            passphraseActionButton("Generate random 24-character passphrase", action: requestGeneratedPassphrase)
            passphraseActionButton("Generate memorable 12-word phrase", action: requestMemorablePassphrase)
            passphraseActionButton("Use my own passphrase", action: { showCustomPassphraseWarning = true })
                .disabled(!TagcryptPassphraseAssessment.evaluate(passphrase).meetsMinimum)
            passphraseActionButton("Save this passphrase now", action: { saveCurrentPassphraseToVault(destinationName: "Recovery phrase") })
                .disabled(passphrase.isEmpty)
            Text("Saves or updates the separate “Recovery phrase” entry. A verified NFC write also saves the phrase with its tag nickname; the secret text is not stored in the Vault.")
                .font(.caption).foregroundStyle(palette.muted)
            }
            Divider().overlay(palette.border)
            } else {
                Text("This record will be unlocked with a selected FIDO2 key. No passphrase recovery route will be included.")
                    .font(.caption).foregroundStyle(palette.secondary)
                Divider().overlay(palette.border)
            }
            if useSecurityKeyUnlock {
                if fido.registeredKeys.isEmpty {
                    Button("Register a FIDO2 key in Settings") { showSettings = true }
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(palette.accentText)
                } else {
                    Text("Choose one or more keys for this record (up to 3).")
                        .font(.caption)
                        .foregroundStyle(palette.secondary)
                    ForEach(fido.registeredKeys, id: \.credentialID) { key in
                        Toggle(key.displayName, isOn: Binding(
                            get: { selectedFIDOKeyIDs.isEmpty ? key.credentialID == fido.registeredKeys.first?.credentialID : selectedFIDOKeyIDs.contains(key.credentialID) },
                            set: { enabled in
                                if enabled {
                                    guard selectedFIDOKeyIDs.count < 3 else { banner = "A record can include up to three security keys."; return }
                                    if selectedFIDOKeyIDs.isEmpty, let firstID = fido.registeredKeys.first?.credentialID {
                                        selectedFIDOKeyIDs.insert(firstID)
                                    }
                                    selectedFIDOKeyIDs.insert(key.credentialID)
                                } else {
                                    let selectedCount = selectedFIDOKeyIDs.isEmpty ? 1 : selectedFIDOKeyIDs.count
                                    guard selectedCount > 1 else { banner = "Keep at least one key selected, or turn off FIDO2 for this record."; return }
                                    selectedFIDOKeyIDs.remove(key.credentialID)
                                }
                                preparedRecord = nil
                            }
                        ))
                        .tint(palette.accent)
                    }
                }
            }
            Text(unlockMethodExplanation)
                .font(.caption)
                .foregroundStyle(recordUnlockChoice == .fido ? Color.red : palette.muted)
        }
        .padding(18)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))
    }

    private var unlockMethodExplanation: String {
        switch recordUnlockChoice {
        case .passphrase: "A passphrase unlocks this record."
        case .fido: "Only a selected key can unlock this record. Losing every selected key makes it unrecoverable."
        case .both: "Normal unlock requires both the passphrase and a selected key. Passphrase-only emergency recovery remains available."
        }
    }

    private func passphraseActionButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 11) {
                Image(systemName: "circle.fill").font(.system(size: 6, weight: .bold))
                Text(title).font(.subheadline.weight(.medium))
                Spacer(minLength: 0)
            }
            .foregroundStyle(palette.accentText)
            .frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
            .padding(.horizontal, 12)
            .background(palette.input, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(.plain)
    }

    private var encryptActions: some View {
        VStack(spacing: 10) {
            Button { Task { await encrypt() } } label: {
                Label(isCryptoWorking ? "Encrypting…" : (destination == .nfc ? "Encrypt & prepare tag" : "Encrypt & create QR"),
                      systemImage: destination == .nfc ? "lock.fill" : "qrcode")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(palette.onAccent)
                    .background(palette.accent, in: RoundedRectangle(cornerRadius: 15))
            }
            .disabled(!hasEncryptableContent || (destination == .qr && estimatedQRPayloadLength > TagcryptQRCodec.maximumPayloadBytes)
                      || (passphraseIsRequiredForRecord && !TagcryptPassphraseAssessment.evaluate(passphrase).meetsMinimum)
                      || (passphraseIsRequiredForRecord && passphraseMode == "perTag" && passphraseConfirmation.isEmpty)
                      || (passphraseIsRequiredForRecord && passphrase != generatedPassphraseValue && !customPassphraseAcknowledged)
                      || (useSecurityKeyUnlock && fido.registeredKeys.isEmpty) || nfc.isScanning || isCryptoWorking)

            if destination == .nfc {
                Button(action: write) {
                    Label(preparedRecoveryShareIndex.map { "Write recovery share \($0 + 1) of 3" } ?? "Write prepared record", systemImage: "wave.3.right")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(palette.primary)
                        .background(palette.input, in: RoundedRectangle(cornerRadius: 14))
                }
                .disabled(preparedRecord == nil || nfc.isScanning || isCryptoWorking)
            }
            if passphraseIsRequiredForRecord && hasEncryptableContent
                && (!TagcryptPassphraseAssessment.evaluate(passphrase).meetsMinimum
                    || (passphrase != generatedPassphraseValue && !customPassphraseAcknowledged)) {
                Label("Set the passphrase under Unlock method below.", systemImage: "arrow.down.circle")
                    .font(.caption)
                    .foregroundStyle(palette.muted)
            }
            if preparedRecord != nil {
                Button {
                    Task { await savePreparedPayloadToVault() }
                } label: {
                    Label("Save encrypted copy to Recovery Vault", systemImage: "archivebox")
                        .frame(maxWidth: .infinity).padding(.vertical, 12)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(palette.accentText)
                }
                .disabled(isCryptoWorking || isRecoveryVaultAuthenticating)
            }
        }
        .buttonStyle(.plain)
    }

    private func disclosureHeader(_ title: String, systemImage: String, isOpen: Binding<Bool>) -> some View {
        Button {
            withAnimation(.easeInOut(duration: 0.2)) { isOpen.wrappedValue.toggle() }
        } label: {
            HStack {
                Label(title, systemImage: systemImage).font(.system(size: 14, weight: .medium))
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.caption.weight(.semibold))
                    .rotationEffect(.degrees(isOpen.wrappedValue ? 180 : 0))
            }
            .foregroundStyle(palette.accentText)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func smallActionLabel(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .frame(maxWidth: .infinity).padding(.vertical, 10)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(palette.primary)
            .background(palette.input, in: RoundedRectangle(cornerRadius: 11))
    }

    /// Encrypt page: split the prepared record into three share tags (any two rebuild it).
    private var splitSharesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            disclosureHeader("Split into 3 tags (any 2 restore)", systemImage: "square.stack.3d.up", isOpen: $showSplitShares)
            if showSplitShares {
                Text("Writes the encrypted record as three shares on three tags. Any two rebuild it; one alone reveals nothing. You still need the passphrase or security key to decrypt. Keep the tags in different places.")
                    .font(.caption).foregroundStyle(palette.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if recoveryShareExports.isEmpty {
                    Button {
                        guard let record = preparedRecord, preparedRecoveryShareIndex == nil else { return }
                        do {
                            recoveryShareExports = try TagcryptRecoveryShares.split(record)
                            writtenShareIndices = []
                        } catch { banner = "Could not split this record into shares. \(error.localizedDescription)" }
                    } label: { smallActionLabel("Create 3 shares from this record", systemImage: "square.split.2x1") }
                    .buttonStyle(.plain)
                    .disabled(preparedRecord == nil || preparedRecoveryShareIndex != nil || isCryptoWorking)
                    if preparedRecord == nil {
                        Text("Tap Encrypt & prepare tag first.").font(.caption2).foregroundStyle(palette.muted)
                    }
                } else {
                    ForEach(recoveryShareExports.indices, id: \.self) { index in
                        HStack(spacing: 8) {
                            Image(systemName: writtenShareIndices.contains(index) ? "checkmark.circle.fill" : "\(index + 1).circle")
                                .foregroundStyle(writtenShareIndices.contains(index) ? Color.green : palette.secondary)
                            Text("Share \(index + 1)").font(.subheadline.weight(.medium)).foregroundStyle(palette.primary)
                            Spacer()
                            Button {
                                writingShareIndex = index
                                prepareRecoveryShareForNFC(index: index)
                                if preparedRecoveryShareIndex == index { write() }
                            } label: {
                                Label(writtenShareIndices.contains(index) ? "Rewrite" : "Write", systemImage: "wave.3.right")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 10).padding(.vertical, 7)
                                    .foregroundStyle(palette.onAccent)
                                    .background(palette.accent, in: Capsule())
                            }
                            .disabled(!recoveryShareFitsSelectedNFC(index: index) || nfc.isScanning)
                            Button { copySecret(recoveryShareExports[index]) } label: {
                                Image(systemName: "doc.on.doc").font(.caption).foregroundStyle(palette.secondary)
                                    .padding(7).background(palette.input, in: Circle())
                            }
                            .accessibilityLabel("Copy share \(index + 1) as text")
                        }
                        .buttonStyle(.plain)
                    }
                    if recoveryShareExports.indices.contains(0), !recoveryShareFitsSelectedNFC(index: 0) {
                        Text("A share is the same size as the record; pick a larger tag size above.")
                            .font(.caption2).foregroundStyle(.red)
                    }
                    Button("Clear shares") {
                        recoveryShareExports = []
                        writtenShareIndices = []
                        if preparedRecoveryShareIndex != nil { preparedRecord = nil; preparedRecoveryShareIndex = nil }
                    }
                    .font(.caption).foregroundStyle(palette.accentText)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))
    }

    /// Decrypt page: collect two share tags (scan or paste) and rebuild the record.
    private var restoreSharesPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            disclosureHeader("Restore from 2 of 3 share tags", systemImage: "square.stack.3d.up", isOpen: $showRestoreShares)
            if showRestoreShares {
                Text("Scan two share tags from the same set, or paste share text. Tagcrypt rebuilds the encrypted record, then asks for its passphrase or key.")
                    .font(.caption).foregroundStyle(palette.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button { nfc.read(rawPageMode: rawPageModeEnabled) } label: {
                    smallActionLabel(nfc.isScanning ? "Scanning…" : "Scan a share tag", systemImage: "wave.3.right")
                }
                .buttonStyle(.plain)
                .disabled(nfc.isScanning)
                shareField("Share A", text: $recoveryShareOne, field: .shareA)
                shareField("Share B", text: $recoveryShareTwo, field: .shareB)
                HStack {
                    Button("Rebuild record") { combineRecoveryShares() }
                        .font(.subheadline.weight(.semibold))
                        .disabled(recoveryShareOne.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || recoveryShareTwo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Spacer()
                    Button("Clear") { recoveryShareOne = ""; recoveryShareTwo = "" }
                        .font(.caption)
                }
                .foregroundStyle(palette.accentText)
            }
        }
    }

    private func shareField(_ title: String, text: Binding<String>, field: InputField) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: text.wrappedValue.isEmpty ? "circle.dashed" : "checkmark.circle.fill")
                    .foregroundStyle(text.wrappedValue.isEmpty ? palette.muted : Color.green)
                Text(title + (text.wrappedValue.isEmpty ? ": scan or paste" : ": ready"))
                    .font(.caption.weight(.medium)).foregroundStyle(palette.secondary)
            }
            TextField("Paste share text", text: text, axis: .vertical)
                .focused($focusedInput, equals: field)
                .lineLimit(1...3)
                .font(.system(.caption, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .privacySensitive()
                .padding(10)
                .background(palette.input, in: RoundedRectangle(cornerRadius: 10))
        }
    }

    private var identifyTagCard: some View {
        identifyTagPanel
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))
    }

    /// "Identify my tag": read-only check of a tag before writing to it.
    private var identifyTagPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.easeInOut(duration: 0.18)) { showIdentifyTag.toggle() }
            } label: {
                HStack {
                    Label("Identify my tag", systemImage: "magnifyingglass")
                        .font(.system(size: 14, weight: .medium))
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.semibold))
                        .rotationEffect(.degrees(showIdentifyTag ? 180 : 0))
                }
                .foregroundStyle(palette.accentText)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
            }
            if showIdentifyTag {
                Text("Check what a tag is before you write: chip type, free space, whether it is locked or password-protected, and what is already on it. Reading only; nothing is written.")
                    .font(.caption).foregroundStyle(palette.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button { nfc.identifyTag() } label: {
                    Label(nfc.isScanning ? "Scanning…" : "Scan tag", systemImage: "wave.3.right")
                        .frame(maxWidth: .infinity).padding(.vertical, 11)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(palette.primary)
                        .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                }
                .disabled(nfc.isScanning || isCryptoWorking)
                if let result = nfc.identifyResult {
                    Text(result)
                        .font(.footnote)
                        .foregroundStyle(palette.primary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(palette.surface, in: RoundedRectangle(cornerRadius: 12))
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(palette.border, lineWidth: 1))
                        .textSelection(.enabled)
                }
            }
        }
    }

    private var decryptScreen: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 11) {
                sectionTitle("NFC RECORD OR RECOVERY SHARE", detail: "Scan a saved encrypted record or one of its 2-of-3 shares. Reading does not change the tag.")
                Button {
                    nfc.read(rawPageMode: rawPageModeEnabled)
                } label: {
                    Label(nfc.isScanning ? "Scanning…" : "Read tag or recovery share", systemImage: "wave.3.right")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 15)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(palette.onAccent)
                        .background(palette.accent, in: RoundedRectangle(cornerRadius: 15))
                }
                .disabled(nfc.isScanning)
                Button {
                    guard DataScannerViewController.isSupported else {
                        banner = "Live QR scanning requires a supported iPhone camera and iOS 16 or later."
                        return
                    }
                    showQRScanner = true
                } label: {
                    Label("Scan encrypted QR", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(palette.primary)
                        .background(palette.input, in: RoundedRectangle(cornerRadius: 14))
                }
                restoreSharesPanel
                if let record = pendingEncryptedRecord {
                    let unlockMode = (try? FIDOEnvelopeCrypto.unlockMode(in: record)) ?? .passphraseOnly
                    Label("Encrypted record ready · \(pendingRecordSource)", systemImage: "checkmark.circle.fill")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(Color.green)
                    if unlockMode != .fidoOnly {
                    SecureField("Enter the passphrase for this tag", text: $passphrase)
                        .textContentType(.password)
                        .focused($focusedInput, equals: .decryptPassphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                        .padding(13)
                        .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                        .privacySensitive()
                    }
                    if unlockMode == .passphraseAndFIDO {
                        Button { Task { await decryptScannedRecordWithBoth() } } label: {
                            Label("Unlock with passphrase + FIDO2 key", systemImage: "key.fill")
                                .frame(maxWidth: .infinity).padding(.vertical, 14)
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(palette.onAccent).background(palette.accent, in: RoundedRectangle(cornerRadius: 14))
                        }
                        .disabled(passphrase.isEmpty || nfc.isScanning || isCryptoWorking)
                        Button { Task { await decryptScannedRecord() } } label: {
                            Label("Emergency recovery with passphrase", systemImage: "lock.open.fill")
                                .frame(maxWidth: .infinity).padding(.vertical, 11)
                                .font(.system(size: 14, weight: .medium)).foregroundStyle(palette.accentText)
                        }
                        .disabled(passphrase.isEmpty || nfc.isScanning || isCryptoWorking)
                    } else if unlockMode != .fidoOnly {
                    Button { Task { await decryptScannedRecord() } } label: {
                        Label("Decrypt with passphrase", systemImage: "lock.open.fill")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(palette.onAccent)
                            .background(palette.accent, in: RoundedRectangle(cornerRadius: 14))
                    }
                    .disabled(passphrase.isEmpty || nfc.isScanning || isCryptoWorking)
                    }
                    if unlockMode != .fidoOnly {
                    Button {
                        requestRecoveryPhrasePicker()
                    } label: {
                        Label("Use a saved Tagcrypt recovery phrase", systemImage: "lock.doc")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(palette.accentText)
                    }
                    .disabled(vaultEntries.isEmpty && archivedPassphrases.isEmpty || nfc.isScanning || isCryptoWorking)
                    Button {
                        Task {
                            do {
                                let selectedPassword = try await applePasswords.choosePassword()
                                passphrase = selectedPassword
                                await decryptScannedRecord(using: selectedPassword)
                            } catch let error as ASAuthorizationError where error.code == .canceled {
                                nfc.setStatus("Apple Passwords selection cancelled. The scanned record is still available.")
                            } catch {
                                banner = "Apple Passwords did not return a passphrase. Choose an entry saved for Tagcrypt (tagcrypt.com), or enter it manually. \(error.localizedDescription)"
                            }
                        }
                    } label: {
                        Label("Choose from Apple Passwords", systemImage: "key.icloud")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(palette.accentText)
                    }
                    .disabled(nfc.isScanning || isCryptoWorking)
                    Text("Apple Passwords shows credentials available to Tagcrypt for its associated domain; it cannot open and search every saved Passwords item.")
                        .font(.caption2)
                        .foregroundStyle(palette.muted)
                    }
                    if VaultCrypto.requiresFIDOKey(for: record) {
                        if matchingFIDOKeysForScannedRecord.isEmpty {
                            Text("No matching key name is saved on this device. You can still try the original physical key listed in this record.")
                                .font(.caption)
                                .foregroundStyle(palette.secondary)
                        }
                        if unlockMode != .passphraseAndFIDO,
                           let parameter = (try? FIDOEnvelopeCrypto.fidoParameters(in: record))?.first {
                            Button {
                                let knownName = matchingFIDOKeysForScannedRecord.first?.displayName ?? "security key"
                                Task { await decryptScannedRecordWithFIDO(credentialID: parameter.credentialID, displayName: knownName) }
                            } label: {
                                Label(isCryptoWorking ? "Waiting for a matching security key…" : "Unlock with a security key", systemImage: "key.fill")
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 13)
                                    .font(.system(size: 15, weight: .semibold))
                                    .foregroundStyle(palette.accentText)
                                    .background(palette.selectedTab, in: RoundedRectangle(cornerRadius: 14))
                            }
                            .disabled(nfc.isScanning || isCryptoWorking)
                        }
                        if unlockMode == .passphraseAndFIDO {
                            Text("Normal unlock needs both factors. Passphrase-only emergency recovery is available above.")
                                .font(.caption).foregroundStyle(palette.secondary)
                        }
                    }
                } else {
                    Text("The scanned ciphertext stays available after a wrong passphrase so you can retry.")
                        .font(.caption)
                        .foregroundStyle(palette.secondary)
                }
            }
            .padding(18)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(palette.border, lineWidth: 1))

            if decryptedVault != nil {
                unlockedVaultCard
            }
            statusCard
        }
    }

    private var unlockedVaultCard: some View {
        Group {
            if let vault = decryptedVault {
                VStack(alignment: .leading, spacing: 10) {
                    sectionTitle("UNLOCKED SECRETS", detail: "Hidden in the app switcher; auto-hides when revealed. Clear when finished.")
                    if let slots = vault.slots, !slots.isEmpty {
                        ForEach(slots) { slot in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(slot.title)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(palette.secondary)
                                HStack {
                                    Text(showSecret ? slot.secret : String(repeating: "•", count: min(max(slot.secret.count, 8), 32)))
                                        .font(.system(.body, design: .monospaced))
                                        .foregroundStyle(palette.primary)
                                        .frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
                                        .privacySensitive()
                                    Button { showSecret.toggle() } label: {
                                        Image(systemName: showSecret ? "eye.slash" : "eye")
                                            .foregroundStyle(palette.accentText)
                                            .frame(width: 44, height: 44)
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityLabel(showSecret ? "Hide decrypted secrets" : "Reveal decrypted secrets")
                                }
                                .padding(8)
                                .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                                Button { copySecret(slot.secret) } label: {
                                    Label("Copy \(slot.title)", systemImage: "doc.on.doc")
                                        .font(.caption.weight(.medium))
                                        .foregroundStyle(palette.accentText)
                                }
                            }
                        }
                    } else {
                        HStack(alignment: .top, spacing: 8) {
                            Text(showSecret ? vault.secret : String(repeating: "•", count: min(max(vault.secret.count, 8), 32)))
                                .font(.system(.body, design: .monospaced))
                                .foregroundStyle(palette.primary)
                                .frame(maxWidth: .infinity, minHeight: 46, alignment: .leading)
                                .privacySensitive()
                                .accessibilityLabel(showSecret ? "Decrypted secret" : "Decrypted secret hidden")
                            Button { showSecret.toggle() } label: {
                                Image(systemName: showSecret ? "eye.slash" : "eye")
                                    .font(.system(size: 18, weight: .medium))
                                    .foregroundStyle(palette.accentText)
                                    .frame(width: 44, height: 44)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(showSecret ? "Hide decrypted secret" : "Reveal decrypted secret")
                        }
                        .padding(8)
                        .background(palette.input, in: RoundedRectangle(cornerRadius: 12))
                        Button { copySecret(vault.secret) } label: {
                            Label("Copy secret", systemImage: "doc.on.doc")
                                .font(.caption.weight(.medium))
                                .foregroundStyle(palette.accentText)
                        }
                    }
                    Button("Clear decrypted secrets") {
                        decryptedVault = nil
                        showSecret = false
                    }
                    .foregroundStyle(palette.accentText)
                }
                .padding(18)
                .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
            }
        }
    }

    @ViewBuilder
    private var vaultScreen: some View {
        if vaultRequiresFaceID && !isRecoveryVaultUnlocked {
            VStack(alignment: .leading, spacing: 12) {
                Label("Recovery Vault locked", systemImage: "faceid")
                    .font(.headline).foregroundStyle(palette.primary)
                Text("Authenticate with Face ID or Touch ID to view saved passphrases and recovery labels.")
                    .font(.subheadline).foregroundStyle(palette.secondary)
                Button {
                    Task { await authenticateRecoveryVault() }
                } label: {
                    Label(isRecoveryVaultAuthenticating ? "Authenticating…" : "Unlock with Face ID or device passcode", systemImage: "faceid")
                        .frame(maxWidth: .infinity).padding(.vertical, 13)
                        .foregroundStyle(palette.onAccent).background(palette.accent, in: Capsule())
                }
                .disabled(isRecoveryVaultAuthenticating)
            }
            .padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        } else {
        VStack(alignment: .leading, spacing: 14) {
            if !vaultEntries.isEmpty || !archivedPassphrases.isEmpty {
                HStack {
                    Text("Recovery entries").font(.headline).foregroundStyle(palette.primary)
                    Spacer()
                    Button(vaultSelectionMode ? "Done selecting" : "Select") {
                        vaultSelectionMode.toggle()
                        if !vaultSelectionMode {
                            selectedVaultEntryIDs.removeAll()
                            selectedArchivedPhraseIDs.removeAll()
                        }
                    }
                    .foregroundStyle(palette.accentText)
                }
                if vaultSelectionMode {
                    HStack {
                        Button("Select all") {
                            selectedVaultEntryIDs = Set(vaultEntries.map(\.id))
                            selectedArchivedPhraseIDs = Set(archivedPassphrases.map(\.id))
                        }
                        Button("Clear") { selectedVaultEntryIDs.removeAll(); selectedArchivedPhraseIDs.removeAll() }
                        Spacer()
                        Text("\(selectedVaultEntryIDs.count + selectedArchivedPhraseIDs.count) selected")
                            .font(.caption).foregroundStyle(palette.secondary)
                    }
                    HStack {
                        Button("Delete selected", role: .destructive) {
                            bulkDeleteSelectionCount = selectedVaultEntryIDs.count + selectedArchivedPhraseIDs.count
                            guard bulkDeleteSelectionCount > 0 else { return }
                            showBulkDeleteConfirmation = true
                        }
                        .disabled(selectedVaultEntryIDs.isEmpty && selectedArchivedPhraseIDs.isEmpty)
                        Spacer()
                        Button("Export selected…") {
                            let selectedVault = vaultEntries.filter { selectedVaultEntryIDs.contains($0.id) }
                            let selectedArchive = archivedPassphrases.filter { selectedArchivedPhraseIDs.contains($0.id) }.map {
                                TagcryptVaultEntry(passphrase: $0.passphrase,
                                                   nickname: $0.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Current Passphrase",
                                                   destination: "Recovery phrase archive", fidoKeyNames: [],
                                                   createdAt: $0.createdAt, updatedAt: $0.createdAt)
                            }
                            vaultExportSelection = selectedVault + selectedArchive
                            guard vaultExportSelection?.isEmpty == false else { return }
                            showVaultExportWarning = true
                        }
                        .disabled(selectedVaultEntryIDs.isEmpty && selectedArchivedPhraseIDs.isEmpty)
                    }
                    .font(.subheadline.weight(.medium))
                }
            }
            if vaultEntries.isEmpty && archivedPassphrases.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: "lock.doc").font(.title2).foregroundStyle(palette.accentText)
                    Text("Nothing saved yet").font(.headline).foregroundStyle(palette.primary)
                    Text("Save a passphrase from Encrypt. After an NFC write or QR creation, save its nickname here too.")
                        .font(.subheadline).foregroundStyle(palette.secondary)
                }
                .padding(18).frame(maxWidth: .infinity, alignment: .leading)
                .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
            }
            ForEach(vaultEntries) { entry in
                ZStack(alignment: .trailing) {
                    Button {
                        withAnimation(.easeOut(duration: 0.18)) {
                            swipedVaultEntryID = nil
                            do { vaultEntries = try TagcryptVaultStore.delete(entry) }
                            catch { banner = "Could not remove vault entry. \(error.localizedDescription)" }
                        }
                    } label: {
                        Text("Delete")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.white)
                            .frame(width: 88)
                            .frame(maxHeight: .infinity)
                            .background(Color.red)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Delete \(entry.nickname)")

                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            if vaultSelectionMode {
                                Button {
                                    if selectedVaultEntryIDs.contains(entry.id) { selectedVaultEntryIDs.remove(entry.id) }
                                    else { selectedVaultEntryIDs.insert(entry.id) }
                                } label: {
                                    Image(systemName: selectedVaultEntryIDs.contains(entry.id) ? "checkmark.circle.fill" : "circle")
                                        .font(.title3).foregroundStyle(palette.accentText)
                                }
                                .buttonStyle(.plain)
                            }
                            Label(entry.nickname, systemImage: entry.destination == RecordDestination.qr.rawValue ? "qrcode" : "wave.3.right")
                                .font(.headline).foregroundStyle(palette.primary)
                            Spacer()
                            Menu {
                                if !entry.passphrase.isEmpty {
                                    Button("Copy passphrase") { copySecret(entry.passphrase) }
                                }
                                if entry.encryptedPayload != nil {
                                    Button("Create 2-of-3 recovery shares") {
                                        guard let payload = entry.encryptedPayload else { return }
                                        do {
                                            recoveryShareExports = try TagcryptRecoveryShares.split(payload)
                                            showRecoveryShares = true
                                        } catch { banner = "Could not split this encrypted record into recovery shares. \(error.localizedDescription)" }
                                    }
                                    Button("Prepare this encrypted copy for NFC") {
                                        Task { await prepareSavedPayload(entry, as: .nfc) }
                                    }
                                    Button("Show this encrypted copy as QR") {
                                        Task { await prepareSavedPayload(entry, as: .qr) }
                                    }
                                }
                                Button("Rename tag label") {
                                    vaultRenameTarget = entry
                                    vaultRenameDraft = entry.nickname
                                }
                                Button("Delete from Vault", role: .destructive) {
                                    do { vaultEntries = try TagcryptVaultStore.delete(entry) }
                                    catch { banner = "Could not remove vault entry. \(error.localizedDescription)" }
                                }
                            } label: { Image(systemName: "ellipsis.circle").foregroundStyle(palette.accentText) }
                        }
                        HStack {
                            Text(revealedVaultEntryIDs.contains(entry.id) ? entry.passphrase : String(repeating: "•", count: min(entry.passphrase.count, 32)))
                                .font(.system(.subheadline, design: .monospaced)).foregroundStyle(palette.secondary).textSelection(.enabled).privacySensitive()
                            Spacer()
                            Button(revealedVaultEntryIDs.contains(entry.id) ? "Hide" : "Reveal") {
                                if revealedVaultEntryIDs.contains(entry.id) { revealedVaultEntryIDs.remove(entry.id) }
                                else { revealedVaultEntryIDs.insert(entry.id) }
                            }.foregroundStyle(palette.accentText)
                        }
                        if !entry.fidoKeyNames.isEmpty {
                            Label(entry.fidoKeyNames.joined(separator: ", "), systemImage: "key.fill").font(.caption).foregroundStyle(palette.secondary)
                        }
                        Text("Saved \(recoveryTimestamp(entry.updatedAt)) · stored on this iPhone")
                            .font(.caption).foregroundStyle(palette.muted)
                    }
                    .padding(16).background(palette.surface, in: RoundedRectangle(cornerRadius: 18))
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(palette.border, lineWidth: 1))
                    .offset(x: swipedVaultEntryID == entry.id ? -88 : 0)
                    .simultaneousGesture(DragGesture(minimumDistance: 24).onEnded { value in
                        guard !vaultSelectionMode, abs(value.translation.width) > abs(value.translation.height) else { return }
                        withAnimation(.easeOut(duration: 0.18)) {
                            if value.translation.width < -60 { swipedVaultEntryID = entry.id }
                            else if value.translation.width > 40 { swipedVaultEntryID = nil }
                        }
                    })
                }
                .clipShape(RoundedRectangle(cornerRadius: 18))
            }
            if !archivedPassphrases.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    sectionTitle("OLDER GENERATED PHRASES", detail: "Recovery archive on this iPhone")
                    ForEach(archivedPassphrases) { entry in
                        HStack(alignment: .top) {
                            if vaultSelectionMode {
                                Button {
                                    if selectedArchivedPhraseIDs.contains(entry.id) { selectedArchivedPhraseIDs.remove(entry.id) }
                                    else { selectedArchivedPhraseIDs.insert(entry.id) }
                                } label: {
                                    Image(systemName: selectedArchivedPhraseIDs.contains(entry.id) ? "checkmark.circle.fill" : "circle")
                                        .font(.title3).foregroundStyle(palette.accentText)
                                }
                                .buttonStyle(.plain)
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                Text(entry.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Current Passphrase")
                                    .font(.subheadline.weight(.medium)).foregroundStyle(palette.primary)
                                Text(revealedArchivedPassphraseIDs.contains(entry.id)
                                     ? entry.passphrase
                                     : String(repeating: "•", count: min(entry.passphrase.count, 32)))
                                    .font(.system(.caption, design: .monospaced)).foregroundStyle(palette.secondary).privacySensitive()
                                Text("Saved \(recoveryTimestamp(entry.createdAt))")
                                    .font(.caption).foregroundStyle(palette.muted)
                            }
                            Spacer()
                            Menu {
                                Button(revealedArchivedPassphraseIDs.contains(entry.id) ? "Hide passphrase" : "Reveal passphrase") {
                                    if revealedArchivedPassphraseIDs.contains(entry.id) { revealedArchivedPassphraseIDs.remove(entry.id) }
                                    else { revealedArchivedPassphraseIDs.insert(entry.id) }
                                }
                                Button("Copy passphrase") { copySecret(entry.passphrase) }
                                Button("Delete archived phrase", role: .destructive) {
                                    do { archivedPassphrases = try VaultPassphraseArchive.delete(entry) }
                                    catch { banner = "Could not delete the archived phrase. \(error.localizedDescription)" }
                                }
                            } label: { Image(systemName: "ellipsis.circle").foregroundStyle(palette.accentText) }
                                .accessibilityLabel("Archived phrase actions")
                        }
                    }
                }.padding(16).background(palette.surface, in: RoundedRectangle(cornerRadius: 18))
            }
        }
        }
    }

    private var bottomNavigation: some View {
        HStack(spacing: 8) {
            ForEach(MainTab.allCases) { tab in
                Button {
                    selectTab(tab)
                } label: {
                    VStack(spacing: 5) {
                        Image(systemName: tab.symbol)
                            .font(.system(size: 20, weight: .semibold))
                            .frame(height: 25)
                        Text(tab.rawValue)
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(selectedTab == tab ? palette.accentText : palette.muted)
                    .frame(maxWidth: .infinity)
                    .frame(height: 72)
                    .background(selectedTab == tab ? palette.selectedTab : Color.clear, in: RoundedRectangle(cornerRadius: 20))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selectedTab == tab ? .isSelected : [])
            }
        }
        .padding(7)
        .background(palette.bottomBar, in: RoundedRectangle(cornerRadius: 28))
        .overlay(RoundedRectangle(cornerRadius: 28).stroke(palette.border, lineWidth: 1))
        .padding(.horizontal, 18)
        .padding(.top, 7)
        .padding(.bottom, 5)
        .background(palette.background.opacity(0.97))
    }

    private var firstUseNotice: some View {
        VStack(spacing: 0) {
            HStack {
                if onboardingProgress.currentPageIndex > 0 {
                    Button { onboardingProgress.goBack() } label: {
                        Label("Back", systemImage: "chevron.left")
                    }
                    .accessibilityIdentifier("onboarding-back")
                } else {
                    Color.clear.frame(width: 60, height: 1)
                }
                Spacer()
                HStack(spacing: 8) {
                    ForEach(0..<TagcryptOnboarding.pageCount, id: \.self) { index in
                        Circle()
                            .fill(index == onboardingProgress.currentPageIndex ? palette.accent : palette.muted.opacity(0.35))
                            .frame(width: 8, height: 8)
                    }
                }
                .accessibilityLabel("Page \(onboardingProgress.currentPageIndex + 1) of \(TagcryptOnboarding.pageCount)")
                Spacer()
                Color.clear.frame(width: 60, height: 1)
            }
            .padding(.horizontal, 22)
            .padding(.top, 18)
            .padding(.bottom, 8)

            ScrollView {
                VStack(spacing: 22) {
                    Image(systemName: onboardingSymbol)
                        .font(.system(size: 48, weight: .regular))
                        .foregroundStyle(palette.accentText)
                        .padding(.top, 28)
                    Text(onboardingTitle)
                        .font(.system(size: 30, weight: .semibold, design: .rounded))
                        .foregroundStyle(palette.primary)
                        .multilineTextAlignment(.center)
                    Text(onboardingSubtitle)
                        .font(.system(size: 17, weight: .regular, design: .rounded))
                        .foregroundStyle(palette.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    onboardingPageDetails
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 22)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }

            VStack(spacing: 12) {
                Button(action: continueOnboarding) {
                    Text(onboardingProgress.isFinalPage ? "Enter Tagcrypt" : "Continue")
                        .font(.headline)
                        .foregroundStyle(palette.onAccent)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                        .background(onboardingCanContinue ? palette.accent : palette.muted.opacity(0.35), in: RoundedRectangle(cornerRadius: 15))
                }
                .disabled(!onboardingCanContinue)
                .accessibilityIdentifier("onboarding-continue")
                Text("Onboarding acknowledgement is stored on this device only.")
                    .font(.caption2)
                    .foregroundStyle(palette.muted)
            }
            .padding(.horizontal, 24)
            .padding(.top, 12)
            .padding(.bottom, 18)
            .frame(maxWidth: 600)
            .frame(maxWidth: .infinity)
            .background(palette.background)
        }
        .background(palette.background.ignoresSafeArea())
        .interactiveDismissDisabled()
    }

    private var onboardingTitle: String {
        switch onboardingProgress.currentPageIndex {
        case 0: "Welcome to Tagcrypt"
        case 1: "Choose your passphrase default"
        case 2: "Plan for recovery"
        case 3: "Set advanced preferences"
        default: "Read before your first record"
        }
    }

    private var onboardingSymbol: String {
        switch onboardingProgress.currentPageIndex {
        case 0: "lock.shield"
        case 1: "key.horizontal"
        case 2: "externaldrive.badge.icloud"
        case 3: "slider.horizontal.3"
        default: "exclamationmark.shield"
        }
    }

    private var onboardingSubtitle: String {
        switch onboardingProgress.currentPageIndex {
        case 0: "Encrypt short secrets on this device. Save only the encrypted record to an NFC tag or QR code."
        case 1: "A unique passphrase for each record is the safer default. Reuse is convenient, but links the protection of those records."
        case 2: "Your Recovery Vault is local to this device. Decide whether to require device authentication before viewing it."
        case 3: "These options affect how you use compatible tags and security keys. Advanced write features start off, and Tagcrypt asks before replacing data on a tag."
        default: "Tagcrypt can help protect a record, but it cannot guarantee that a tag, phone, passphrase, key, or backup will remain available."
        }
    }

    @ViewBuilder
    private var onboardingPageDetails: some View {
        switch onboardingProgress.currentPageIndex {
        case 0:
            onboardingInfoCard("Your secret is encrypted before it is saved. NFC tags and QR images contain the encrypted record, not the plaintext secret.")
            onboardingInfoCard("There is no Tagcrypt account or automatic cloud sync. Keep recovery material somewhere independent of your phone.")
        case 1:
            VStack(alignment: .leading, spacing: 12) {
                Picker("Appearance", selection: $theme.appearance) {
                    ForEach(TagcryptAppearance.allCases) { appearance in Text(appearance.title).tag(appearance) }
                }
                .pickerStyle(.segmented)
                Picker("Passphrase behavior", selection: $passphraseMode) {
                    Text("Per record").tag("perTag")
                    Text("Reusable default").tag("reusable")
                }
                .pickerStyle(.segmented)
                Text(passphraseMode == "perTag"
                     ? "Tagcrypt asks you to enter and confirm the phrase for each record. Use a generated phrase or another long, unique phrase."
                     : "Tagcrypt reuses the current phrase on this device. Avoid this if records have different owners or need independent protection.")
                    .font(.footnote)
                    .foregroundStyle(palette.secondary)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        case 2:
            VStack(alignment: .leading, spacing: 12) {
                Toggle("Require Face ID or device passcode to view the Recovery Vault", isOn: $vaultRequiresFaceID)
                Text("This is an in-app viewing prompt, not a separate hardware-backed lock on the Vault file. The Vault does not sync; export an encrypted backup and keep its passphrase separately.")
                    .font(.footnote)
                    .foregroundStyle(palette.secondary)
                Toggle("Remind me every 3 months to verify a copy", isOn: $healthReminderEnabled)
                Text("If enabled, iOS may ask permission for local notifications after onboarding. The reminder does not create or verify a backup for you.")
                    .font(.footnote)
                    .foregroundStyle(palette.secondary)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        case 3:
            VStack(alignment: .leading, spacing: 14) {
                Toggle("Require security-key user verification", isOn: $requireFIDOKeyPIN)
                Text("Only affects compatible FIDO PRF keys. This is not required to use passphrase-only records.")
                    .font(.footnote).foregroundStyle(palette.secondary)
                Picker("When a tag already has data", selection: $nfcOverwritePolicyRaw) {
                    ForEach(NFCOverwritePolicy.allCases) { policy in Text(policy.title).tag(policy.rawValue) }
                }
                .pickerStyle(.menu)
                Text("Raw-page storage, NTAG password protection and permanent sealing are experimental and unvalidated. They stay Off here and can be turned on later only under Settings → Advanced, after a separate risk warning.")
                    .font(.footnote).foregroundStyle(palette.secondary)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        default:
            VStack(alignment: .leading, spacing: 14) {
                Text(Self.safetyNoticeText)
                    .font(.subheadline)
                    .foregroundStyle(palette.secondary)
                    .lineSpacing(5)
                    .fixedSize(horizontal: false, vertical: true)
                Text("This acknowledgement is stored locally. It is not an account-linked receipt, a warranty, or a guarantee of recovery.")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(palette.secondary)
                Button {
                    onboardingProgress.setFinalAcknowledged(!onboardingProgress.finalAcknowledged)
                } label: {
                    Label("I have read and understand these limitations",
                          systemImage: onboardingProgress.finalAcknowledged ? "checkmark.square.fill" : "square")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(onboardingProgress.finalAcknowledged ? palette.accentText : palette.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("onboarding-final-acknowledgement")
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
        }
    }

    private var onboardingCanContinue: Bool {
        !onboardingProgress.isFinalPage || onboardingProgress.finalAcknowledged
    }

    private func onboardingInfoCard(_ text: String) -> some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(palette.secondary)
            .lineSpacing(4)
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 20))
    }

    private func continueOnboarding() {
        if onboardingProgress.isFinalPage {
            guard let version = onboardingProgress.finish() else { return }
            onboardingAcknowledgedVersion = version
            noticeAcknowledgedAt = ISO8601DateFormatter().string(from: Date())
            showFirstUseNotice = false
            setHealthReminder(healthReminderEnabled)
        } else {
            onboardingProgress.advance()
        }
    }

    private var aboutVersionLabel: String {
        TagcryptAppMetadata.displayVersion(
            marketingVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—",
            buildNumber: Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
        )
    }

    private var aboutView: some View {
        List {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "wave.3.right")
                        .font(.system(size: 38))
                        .foregroundStyle(palette.accentText)
                    Text("Tagcrypt")
                        .font(.largeTitle.weight(.semibold))
                    Text("Version \(aboutVersionLabel)")
                        .foregroundStyle(.secondary)
                    Text(TagcryptAppMetadata.publisherName)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .listRowBackground(Color.clear)
            }
            Section("What Tagcrypt does") {
                Text("Tagcrypt encrypts short text on your device and can save the encrypted record to a compatible NFC tag or QR image. Passphrase records work on supported devices; FIDO PRF workflows require a compatible key and operating-system version.")
            }
            Section("Privacy and storage") {
                Text("Tagcrypt has no user account or automatic Vault sync. Secrets are encrypted on-device; saved recovery data remains local unless you export an encrypted backup. First-run acknowledgement is stored on this device.")
                if let privacyURL = URL(string: "https://tagcrypt.com/privacy/") {
                    Link("Privacy policy", destination: privacyURL)
                }
            }
            Section("Links") {
                if let url = URL(string: "https://tagcrypt.com/") {
                    Link(destination: url) { Label("Tagcrypt website", systemImage: "globe") }
                }
                if let url = URL(string: "https://tagcrypt.com/format/") {
                    Link(destination: url) { Label("Record format & offline recovery", systemImage: "doc.text") }
                }
                if let url = URL(string: "https://github.com/fishandmedia/tagcrypt-ios") {
                    Link(destination: url) { Label("Source code on GitHub", systemImage: "chevron.left.forwardslash.chevron.right") }
                }
                if let url = URL(string: "https://fishandmedia.com/") {
                    Link(destination: url) { Label("Fish and Media", systemImage: "building.2") }
                }
                if let url = URL(string: "mailto:support@fishandmedia.com") {
                    Link(destination: url) { Label("Contact support", systemImage: "envelope") }
                }
            }
            Section("Guide for AI assistants") {
                Text("A plain-text guide to Tagcrypt written for AI assistants. Give it to ChatGPT, Claude, Gemini or another assistant, then ask your questions. Never paste your secret, passphrase or shares into any chat.")
                    .font(.footnote)
                if let guideURL = Bundle.main.url(forResource: "LLM", withExtension: "md") {
                    ShareLink(item: guideURL) { Label("Share or save the guide (LLM.md)", systemImage: "square.and.arrow.up") }
                    Button {
                        if let text = try? String(contentsOf: guideURL, encoding: .utf8) { UIPasteboard.general.string = text }
                        nfc.setStatus("AI guide copied.")
                    } label: { Label("Copy guide text", systemImage: "doc.on.doc") }
                }
                if let url = URL(string: "https://tagcrypt.com/llm.md") {
                    Link(destination: url) { Label("Guide online", systemImage: "globe") }
                }
            }
            Section("Credits") {
                Text("Published by \(TagcryptAppMetadata.publisherName). Tagcrypt is a trademark of \(TagcryptAppMetadata.publisherName). Open source under the Apache License 2.0; uses swift-sodium and libsodium (ISC).")
            }
        }
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var tagcryptGearView: some View {
        List {
            Section("Tags and security keys") {
                Text("Product suggestions will appear here once specific tags and keys pass our physical tests. No shop or affiliate links are active yet. Until then: choose NDEF-formatted NTAG213/215/216 tags from a seller you trust, and see Help & FAQ for what to look for.")
                    .font(.body)
            }
        }
        .navigationTitle("Shop for tags")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var helpFAQView: some View {
        List {
            Section("Getting started") {
                DisclosureGroup("What does Tagcrypt do?") {
                    Text("It encrypts a short secret, such as a recovery code or a PIN, on your iPhone and stores only the encrypted record on an NFC tag or in a QR image. To read it back you scan the tag or QR and enter the passphrase or tap your security key.")
                }
                DisclosureGroup("How do I write my first tag?") {
                    Text("1. Type the secret. 2. Generate a passphrase (recommended) or choose your own. 3. Tap Encrypt & prepare tag. 4. Tap Write prepared record and hold the top of your iPhone to the tag. Tagcrypt reads the tag back to check the write. 5. Read it once more and decrypt it before you rely on it.")
                }
                DisclosureGroup("How do I check a tag before writing?") {
                    Text("Open Identify my tag at the top of the Encrypt page and scan the tag. Tagcrypt reports the chip, free space, whether it is locked or password-protected, and what is already on it, and selects the matching tag size. It only reads; nothing is written.")
                }
                DisclosureGroup("What are the 3 share tags?") {
                    Text("Encrypt → Split into 3 tags writes the encrypted record as three shares on three tags. Any two rebuild it (Decrypt → Restore from 2 of 3 share tags); one alone reveals nothing. You still need the passphrase or key. Use it so that losing one tag does not lose the record.")
                }
                DisclosureGroup("Can I ask an AI assistant about Tagcrypt?") {
                    Text("Yes. Settings → About → Guide for AI assistants shares a text file (LLM.md) written for AI tools. Give it to your assistant and ask away. Never paste your secret, passphrase or shares into a chat.")
                }
                DisclosureGroup("Can I read a tag without Tagcrypt?") {
                    Text("Yes, for passphrase records. The record format and an offline Python recovery script are published on tagcrypt.com. A record protected only by a security key needs the app and that key.")
                }
            }
            Section("Passphrases") {
                DisclosureGroup("What makes a good passphrase?") {
                    Text("Use the generated passphrase or the 12-word phrase. Both are random, which is what makes them strong. If you choose your own, make it long and unique: never reuse a password from another account, and avoid names, dates, song lyrics or keyboard patterns. Tagcrypt refuses phrases it estimates below about 80 bits.")
                }
                DisclosureGroup("Why does the passphrase matter so much?") {
                    Text("Anyone who copies the tag can try to guess the passphrase on their own computer, as many times as they like. Strong encryption cannot protect a guessable passphrase. The tag protects the secret only as well as the passphrase does.")
                }
                DisclosureGroup("Where are my passphrases kept?") {
                    Text("Generated passphrases stay in this iPhone's Keychain. Any passphrase you write a tag with, generated or your own, is saved in the encrypted Recovery Vault on this iPhone after a verified write or when you tap Save. Nothing is uploaded or synced.")
                }
                DisclosureGroup("I forgot my passphrase. Can you recover it?") {
                    Text("No. Tagcrypt has no account and no server copy, so nobody can reset it. Check the Recovery Vault and your backups. Without the passphrase (or the security key for a key-only record) the secret cannot be decrypted.")
                }
            }
            Section("Backups and changing phone") {
                DisclosureGroup("What happens if I delete the app?") {
                    Text("The Recovery Vault file is deleted with the app. iOS sometimes keeps Keychain items (such as generated passphrases) after an app is removed, and Tagcrypt finds them again if you reinstall, but iOS does not promise this, so never rely on it. The only dependable copy is an encrypted backup you exported, plus your own written records.")
                }
                DisclosureGroup("How do I move to a new iPhone?") {
                    Text("Before you switch: Settings → Backup, set a passphrase to lock backups, then Back up Recovery Vault and save the file to Files or a computer. On the new iPhone, install Tagcrypt and use Import encrypted backup with the same passphrase. Vault data and generated passphrases do not move by themselves, not even with an iCloud device backup.")
                }
                DisclosureGroup("Does an iPhone or iCloud backup include my Vault?") {
                    Text("A device backup may contain the encrypted Vault file, but its key is kept on this iPhone only, so a backup restored to a new phone cannot open it. Use Tagcrypt's own encrypted backup instead.")
                }
                DisclosureGroup("What is the passphrase to lock backups?") {
                    Text("A separate passphrase that encrypts the backup files and key bundles you export. Use a different one from your tags, store it apart from the file, and do not lose it: Tagcrypt cannot open a backup without it.")
                }
            }
            Section("Choosing tags") {
                DisclosureGroup("Which tag should I use?") {
                    Text("Choose a genuine, rewritable NFC Forum Type 2 tag from a source you trust. NTAG213 is suitable for short records, NTAG215 offers more room, and NTAG216 has the most capacity. Sticker tags and clones can report less NDEF space than their label suggests; Tagcrypt checks the live capacity when you scan. Use QR for larger records.")
                    ForEach(TagcryptSupportedTag.allCases) { tag in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(tag.rawValue).font(.subheadline.weight(.semibold))
                            Text(tag.summary).font(.footnote).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 3)
                    }
                }
                DisclosureGroup("Which size do I need?") {
                    Text("NTAG213 (144 bytes) fits a short secret. NTAG215 (504 bytes) and NTAG216 (888 bytes) leave room for longer secrets, several named secrets, or security-key records. If a record does not fit, Tagcrypt tells you and can re-encrypt it for the tag's real capacity.")
                }
                DisclosureGroup("Sticker, card or key fob?") {
                    Text("All work if they contain an NTAG21x chip. Stickers are cheap but easy to damage and are often clones. Cards and fobs last longer. Avoid metal surfaces unless the tag is labelled on-metal, and keep tags away from heat and bending.")
                }
                DisclosureGroup("Why does my tag say it is not formatted?") {
                    Text("Buy NDEF-formatted tags. iPhone cannot format a blank, unformatted tag, so Tagcrypt refuses tags that report “not formatted for NDEF”.")
                }
                DisclosureGroup("My tag is a clone. Does that matter?") {
                    Text("For ordinary encrypted records, no: any writable NDEF tag works. Advanced features (tag password, raw pages, clearing unused pages, permanent seal) talk to the chip directly. On clones they may fail or behave differently. Turn on Compatible tags in Advanced only to experiment with disposable tags.")
                }
            }
            Section("Safety and limits") {
                DisclosureGroup("Is the secret stored on the tag?") {
                    Text("Only in encrypted form. The tag holds ciphertext, not the secret or the passphrase. It is still wise to keep the tag somewhere private, because a copy lets someone attempt offline guesses.")
                }
                DisclosureGroup("Should a tag be my only copy?") {
                    Text("No. Tags can be lost, broken or wiped. Keep an independent copy of the secret and its passphrase, test-read the tag after writing, and use the 3-month reminder to check copies still work.")
                }
                DisclosureGroup("What do security keys add?") {
                    Text("A FIDO2 key with PRF support can unlock a record by touch, so a copied tag is useless without the physical key. Joint records need both the passphrase and the key, and keep a passphrase-only emergency route. Key-only records are lost for good if every registered key is lost.")
                }
                DisclosureGroup("What does the tag password do?") {
                    Text("It is a 32-bit password inside the chip that stops casual overwrites by other NFC apps. It is not encryption and adds no secrecy. Your record is already encrypted either way. TagCrypt can still rewrite the tag with the key it was set with, and Settings → Tag details → Remove tag password makes it writable by any app again. Keep the Vault backup: it contains the Auto key.")
                }
                DisclosureGroup("What does the permanent seal do?") {
                    Text("It locks an NTAG213, 215 or 216 for good so the record can never be changed or deleted. It cannot be undone, even by Tagcrypt. It is experimental and meant for a disposable test tag first.")
                }
                DisclosureGroup("Why does a skipped tag show a tick?") {
                    Text("iOS ends every NFC scan with either a tick or a red X; there is no neutral option. When “Skip tags with data” leaves a tag unchanged, iOS shows the tick with “Tag not changed.” Tagcrypt then shows a minus sign in its own status card to confirm nothing was written.")
                }
                DisclosureGroup("Security and limitations") {
                    Text("NFC tags and QR images can be copied or replayed. Passphrase records can be guessed offline if the phrase is weak. Losing the only passphrase, key, or backup can make a record unrecoverable. A tag-password is only a casual write deterrent, not encryption. Permanent sealing cannot be undone. Tagcrypt does not promise tamper-proof tags, guaranteed recovery, or audited security.")
                }
            }
            Section("Help") {
                if let url = URL(string: "mailto:support@fishandmedia.com") {
                    Link(destination: url) { Label("Email support", systemImage: "envelope") }
                }
            }
        }
        .navigationTitle("Help & FAQ")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var settingsRiskTitle: String {
        switch pendingSettingsRiskAction {
        case .compatibleTags: "Allow compatible (non-NXP) tags?"
        case .enableAdvanced: "Advanced settings can affect tags"
        case .rawPages: "Use raw NTAG pages?"
        case .randomizeUnusedPages: "Randomize unused tag pages?"
        case .tagPasswordMode: "Enable NTAG password protection?"
        case .deleteOrganisationKey(_, let label): "Delete Organisation key “\(label)”?"
        case .rotateAutoKey: "Replace the Auto tag key?"
        case nil: "Advanced settings"
        }
    }

    private var settingsRiskMessage: String {
        switch pendingSettingsRiskAction {
        case .compatibleTags:
            "Tagcrypt will identify tags that do not answer like genuine NTAG213/215/216 from their Capability Container. A clone may map its memory differently, so password setup, raw pages or sealing could damage it. Use disposable tags only."
        case .enableAdvanced:
            "Advanced options can overwrite records or permanently lock a disposable tag. Switching modes alone does not write to a tag. Keep a separate recovery copy."
        case .rawPages:
            "Raw-page writes replace the tag's user memory and are not standard NDEF. A clone may behave differently. Continue only with a disposable tag and a separate recovery copy."
        case .randomizeUnusedPages:
            "This overwrites unused pages after writing. A protocol or clone mismatch may damage other data. Use only a disposable tag with a separate recovery copy."
        case .tagPasswordMode:
            "The 32-bit tag password is not encryption. A clone can fail partway through setup and become difficult to rewrite. Continue only after backing up the key and using a disposable tag."
        case .deleteOrganisationKey:
            "This device will no longer be able to rewrite tags protected with this key. Records on those tags stay readable. Export the encrypted key bundle first if anyone may still need it."
        case .rotateAutoKey:
            "A new random Auto key replaces the current one. This device will no longer be able to rewrite tags protected with the old key unless you restore an encrypted Vault backup that contains it. Records on those tags stay readable. Back up the Vault first."
        case nil:
            "These settings can affect tags."
        }
    }

    private func applyPendingSettingsRiskAction() {
        switch pendingSettingsRiskAction {
        case .compatibleTags:
            allowCompatibleTags = true
            nfc.allowCompatibleTags = true
        case .enableAdvanced:
            advancedSettingsEnabled = true
        case .rawPages(let enabled):
            rawPageModeEnabled = enabled
            if enabled { paddedRecordsEnabled = true }
        case .randomizeUnusedPages(let enabled):
            wipeUnusedTagPages = enabled
        case .tagPasswordMode(let mode):
            tagLockModeRaw = mode
        case .deleteOrganisationKey(let id, let label):
            do {
                try TagLockKeyStore.deleteOrganisationKey(id: id)
                organisationKeyListRevision += 1
                banner = "Organisation key “\(label)” deleted from this device."
            } catch {
                banner = "Could not delete the Organisation key. Nothing was changed."
            }
        case .rotateAutoKey:
            do {
                _ = try TagLockKeyStore.rotateAutoKey()
                banner = "New Auto tag key created. Back up the encrypted Recovery Vault now."
            } catch {
                banner = "Could not replace the Auto tag key. The current key is unchanged."
            }
        case nil:
            break
        }
        pendingSettingsRiskAction = nil
    }

    private var settingsSheet: some View {
        NavigationStack {
            Form {
                Section {
                    SettingRow(title: "Theme", caption: "Light, dark or auto") {
                        Picker("Theme", selection: $theme.appearance) {
                            ForEach(TagcryptAppearance.allCases) { appearance in
                                Text(appearance.title).tag(appearance)
                            }
                        }
                        .labelsHidden().pickerStyle(.menu).fixedSize()
                    }
                    SettingRow(title: "Passphrase", caption: passphraseMode == "perTag" ? "New one per tag" : "Reuse one phrase",
                               detail: "Per tag: enter and confirm a passphrase for each record; safer when tags have different owners or uses. Reusable: reuse the current generated passphrase, stored in this iPhone's device-only Keychain until replaced or cleared.") {
                        Picker("Passphrase", selection: $passphraseMode) {
                            Text("Per tag").tag("perTag")
                            Text("Reusable").tag("reusable")
                        }
                        .labelsHidden().pickerStyle(.menu).fixedSize()
                    }
                    SettingRow(title: "Face ID for Vault", caption: "Ask before showing Vault",
                               detail: "Face ID or device passcode. An in-app check, not a separate lock on the Vault file.") {
                        Toggle("Face ID for Vault", isOn: $vaultRequiresFaceID).labelsHidden()
                    }
                    .onChange(of: vaultRequiresFaceID) { enabled in
                        if enabled {
                            isRecoveryVaultUnlocked = false
                            if selectedTab == .vault { selectedTab = .encrypt }
                        } else {
                            isRecoveryVaultUnlocked = true
                        }
                    }
                    SettingRow(title: "Tags with data", caption: (NFCOverwritePolicy(rawValue: nfcOverwritePolicyRaw) ?? .warn).title,
                               detail: nfcOverwritePolicyDescription) {
                        Picker("Tags with data", selection: $nfcOverwritePolicyRaw) {
                            ForEach(NFCOverwritePolicy.allCases) { policy in Text(policy.title).tag(policy.rawValue) }
                        }
                        .labelsHidden().pickerStyle(.menu).fixedSize()
                    }
                    SettingRow(title: "Check-a-copy reminder", caption: "Every 3 months",
                               detail: healthReminderStatus.isEmpty
                                ? "A local notification asks you to read and verify a saved tag or QR copy. It does not create a backup or sync your data."
                                : healthReminderStatus) {
                        Toggle("Check-a-copy reminder", isOn: $healthReminderEnabled).labelsHidden()
                    }
                    .onChange(of: healthReminderEnabled) { enabled in setHealthReminder(enabled) }
                }

                Section("Backup") {
                    SettingRow(title: "Passphrase to lock backups", caption: "Locks every backup file",
                               detail: "Encrypts the Vault backups and Organisation key bundles you export, and opens them again on import. Use a different passphrase from your tags. Tagcrypt cannot recover it; keep it apart from the backup file.")
                    SecureField("Passphrase to lock backups", text: $vaultExportPassphrase)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
                    if !vaultExportPassphrase.isEmpty { vaultExportPassphraseStrength }
                    Button {
                        Task {
                            guard await authenticateForProtectedVaultAction() else { return }
                            vaultExportSelection = nil
                            deferredSettingsAction = .exportVault
                            showSettings = false
                        }
                    } label: { Label("Back up Recovery Vault…", systemImage: "square.and.arrow.up") }
                    .disabled(vaultEntries.isEmpty && archivedPassphrases.isEmpty)
                    Button {
                        Task {
                            guard await authenticateForProtectedVaultAction() else { return }
                            showVaultImportPicker = true
                        }
                    } label: { Label("Import encrypted backup…", systemImage: "square.and.arrow.down") }
                    NavigationLink { recoveryPhrasesView } label: {
                        SettingRow(title: "Saved recovery phrases", caption: archivedPassphrases.isEmpty && !generatedPassphraseIsSaved ? "None yet" : "On this iPhone only")
                    }
                }

                Section {
                    SettingRow(title: "Advanced", caption: advancedSettingsEnabled ? "Tag tools shown" : "Tag tools hidden",
                               detail: "Advanced write options can overwrite tag data or make a tag permanently read-only. Use them only with a separate recovery copy and a tag you can afford to lose.",
                               tint: advancedSettingsEnabled ? .orange : nil) {
                        Toggle("Advanced", isOn: Binding(
                            get: { advancedSettingsEnabled },
                            set: { enabled in
                                if enabled {
                                    pendingSettingsRiskAction = .enableAdvanced
                                    showAdvancedSettingsWarning = true
                                } else {
                                    advancedSettingsEnabled = false
                                }
                            }
                        )).labelsHidden()
                    }
                    if advancedSettingsEnabled {
                        SettingRow(title: "Key verification", caption: "Ask key for PIN",
                                   detail: requireFIDOKeyPIN
                                    ? "Requests user verification from the security key. Depending on its model, this may ask for the key PIN or another step. The passphrase remains a separate recovery route."
                                    : "The key may unlock with a touch alone. The passphrase remains a separate recovery route.") {
                            Toggle("Key verification", isOn: $requireFIDOKeyPIN).labelsHidden()
                        }
                        NavigationLink { securityKeysView } label: {
                            SettingRow(title: "Security keys", caption: fido.registeredKeys.isEmpty ? "None registered" : "\(fido.registeredKeys.count) registered")
                        }
                        SettingRow(title: "Pad NFC records", caption: "Hide record length",
                                   detail: "NFC padding targets a conservative \(selectedSize.safeNDEFPayloadBytes)-byte payload for the selected \(selectedSize.rawValue), leaving a safety margin for tags with less usable NDEF space. QR records use fixed size buckets below 1,200 bytes. Turning padding off reduces tag size but reveals a closer estimate of the record's length. The tag's reported capacity is checked again before writing.") {
                            Toggle("Pad NFC records", isOn: $paddedRecordsEnabled).labelsHidden()
                                .disabled(rawPageModeEnabled)
                        }
                        SettingRow(title: "Compatible tags", caption: "Allow non-NXP tags",
                                   detail: "Experimental. When a tag does not answer GET_VERSION like a genuine NTAG213/215/216, Tagcrypt identifies the model from its Capability Container instead, so password mode, raw pages, unused-page clearing and sealing can be tried on clone stickers. A clone may map memory differently; use disposable tags only.",
                                   tint: allowCompatibleTags ? .orange : nil) {
                            Toggle("Compatible tags", isOn: Binding(
                                get: { allowCompatibleTags },
                                set: { enabled in
                                    if enabled {
                                        pendingSettingsRiskAction = .compatibleTags
                                        showAdvancedSettingsWarning = true
                                    } else {
                                        allowCompatibleTags = false
                                        nfc.allowCompatibleTags = false
                                    }
                                }
                            )).labelsHidden()
                        }
                        SettingRow(title: "Raw-page storage", caption: "Skip NDEF, use all memory",
                                   detail: "Experimental, unvalidated. A binary v7 record fills every user-memory byte of an identified NTAG213/215/216. Other NFC apps and iOS background reading cannot see it; Tagcrypt reads it only when this mode is on. Padding is required so the full-memory length is known.",
                                   tint: rawPageModeEnabled ? .orange : nil) {
                            Toggle("Raw-page storage", isOn: Binding(
                                get: { rawPageModeEnabled },
                                set: { enabled in
                                    if enabled {
                                        pendingSettingsRiskAction = .rawPages(true)
                                        showAdvancedSettingsWarning = true
                                    } else {
                                        rawPageModeEnabled = false
                                    }
                                }
                            )).labelsHidden()
                        }
                        .onChange(of: rawPageModeEnabled) { enabled in if enabled { paddedRecordsEnabled = true } }
                        SettingRow(title: "Clear unused pages", caption: "Scrub old tag data",
                                   detail: "Experimental, unvalidated. On identified NTAG213/215/216 tags, Tagcrypt verifies the NDEF record, then randomises the bytes after it and reads back the full user memory. Unknown, protected, unreadable or locked tags are left as they are.",
                                   tint: wipeUnusedTagPages ? .orange : nil) {
                            Toggle("Clear unused pages", isOn: Binding(
                                get: { wipeUnusedTagPages },
                                set: { enabled in
                                    if enabled {
                                        pendingSettingsRiskAction = .randomizeUnusedPages(true)
                                        showAdvancedSettingsWarning = true
                                    } else {
                                        wipeUnusedTagPages = false
                                    }
                                }
                            )).labelsHidden()
                            .disabled(rawPageModeEnabled)
                        }
                        SettingRow(title: "Tag password", caption: "Deter casual overwrites",
                                   detail: "Experimental. Off by default. Auto uses one random device-only master key, included in full encrypted Vault backups. Organisation keys are shared only as a passphrase-encrypted bundle. The 32-bit NTAG password is sent unencrypted and only deters casual overwrites; it adds no secrecy. Some tags may fail partway through setup.",
                                   tint: tagLockModeRaw == "Off" ? nil : .orange) {
                            Picker("Tag password", selection: Binding(
                                get: { tagLockModeRaw },
                                set: { nextMode in
                                    if nextMode == "Off" {
                                        tagLockModeRaw = nextMode
                                    } else {
                                        pendingSettingsRiskAction = .tagPasswordMode(nextMode)
                                        showAdvancedSettingsWarning = true
                                    }
                                }
                            )) {
                                Text("Off").tag("Off")
                                Text("Auto").tag("Auto")
                                Text("Organisation").tag("Organisation")
                            }
                            .labelsHidden().pickerStyle(.menu).fixedSize()
                        }
                        .onChange(of: tagLockModeRaw) { mode in
                            guard mode == "Auto" else { return }
                            do {
                                _ = try TagLockKeyStore.createAutoKey()
                                banner = "Device-only NTAG key ready. Back up the encrypted Recovery Vault before using tag protection."
                            } catch {
                                tagLockModeRaw = "Off"
                                banner = "Could not create the device-only NTAG key. Password mode remains Off."
                            }
                        }
                        NavigationLink { tagKeysView } label: {
                            SettingRow(title: "Tag keys", caption: tagLockOrganisationKeyCount == 0 ? "Auto key, Organisation keys" : "\(tagLockOrganisationKeyCount) Organisation key\(tagLockOrganisationKeyCount == 1 ? "" : "s")")
                        }
                        NavigationLink { tagDiagnosticsView } label: {
                            SettingRow(title: "Tag details", caption: "Last scan and CRC test")
                        }
                        NavigationLink { permanentSealView } label: {
                            SettingRow(title: "Permanent seal", caption: "Experimental · NTAG21x", tint: .orange)
                        }
                    }
                }

                Section {
                    NavigationLink("About Tagcrypt") { aboutView }
                    NavigationLink("Shop for tags") { tagcryptGearView }
                    NavigationLink("Help & FAQ") { helpFAQView }
                    NavigationLink("Security, privacy & storage") { securityAndPrivacyView }
                }
            }
            .alert(settingsRiskTitle, isPresented: $showAdvancedSettingsWarning) {
                Button("Continue", role: .destructive) { applyPendingSettingsRiskAction() }
                Button("Cancel", role: .cancel) { pendingSettingsRiskAction = nil }
            } message: {
                Text(settingsRiskMessage)
            }
            .tint(palette.accentText)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
                    .onAppear {
                        refreshArchivedPassphrases()
                        refreshVaultEntries()
                    }
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showSettings = false } } }
        }
        .presentationDetents([.medium, .large])
    }

    private var recoveryPhrasesView: some View {
        Form {
            Section {
                    if generatedPassphraseIsSaved {
                        Button("Forget saved generated passphrase", role: .destructive) {
                            do {
                                let currentInputIsGenerated = passphrase == generatedPassphraseValue
                                try VaultPassphraseStore.clear()
                                if currentInputIsGenerated {
                                    passphrase = ""
                                    passphraseConfirmation = ""
                                    showPassphrase = false
                                }
                                generatedPassphraseValue = ""
                                generatedPassphraseIsSaved = false
                            } catch {
                                banner = error.localizedDescription
                            }
                        }
                    }
                    if !archivedPassphrases.isEmpty {
                        Text("Recovery phrase archive · stored only in this iPhone’s Keychain")
                            .font(.footnote.weight(.semibold))
                        HStack {
                            Button(vaultSelectionMode ? "Done selecting" : "Select archived") {
                                vaultSelectionMode.toggle()
                                selectedVaultEntryIDs.removeAll()
                                if !vaultSelectionMode { selectedArchivedPhraseIDs.removeAll() }
                            }
                            if vaultSelectionMode {
                                Button("Select all") { selectedArchivedPhraseIDs = Set(archivedPassphrases.map(\.id)) }
                                Button("Clear") { selectedArchivedPhraseIDs.removeAll() }
                            }
                            Spacer()
                            if vaultSelectionMode { Text("\(selectedArchivedPhraseIDs.count) selected").font(.caption).foregroundStyle(.secondary) }
                        }
                        if vaultSelectionMode {
                            HStack {
                                Button("Delete selected", role: .destructive) {
                                    bulkDeleteSelectionCount = selectedArchivedPhraseIDs.count
                                    guard bulkDeleteSelectionCount > 0 else { return }
                                    showSettings = false
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { showBulkDeleteConfirmation = true }
                                }.disabled(selectedArchivedPhraseIDs.isEmpty)
                                Spacer()
                                Button("Export selected…") {
                                    vaultExportSelection = archivedPassphrases.filter { selectedArchivedPhraseIDs.contains($0.id) }.map {
                                        TagcryptVaultEntry(passphrase: $0.passphrase,
                                                           nickname: $0.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Current Passphrase",
                                                           destination: "Recovery phrase archive", fidoKeyNames: [],
                                                           createdAt: $0.createdAt, updatedAt: $0.createdAt)
                                    }
                                    deferredSettingsAction = .exportVault
                                    showSettings = false
                                }.disabled(selectedArchivedPhraseIDs.isEmpty)
                            }
                        }
                        ForEach(archivedPassphrases) { entry in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    if vaultSelectionMode {
                                        Button {
                                            if selectedArchivedPhraseIDs.contains(entry.id) { selectedArchivedPhraseIDs.remove(entry.id) }
                                            else { selectedArchivedPhraseIDs.insert(entry.id) }
                                        } label: {
                                            Image(systemName: selectedArchivedPhraseIDs.contains(entry.id) ? "checkmark.circle.fill" : "circle")
                                        }.buttonStyle(.plain)
                                    }
                                    Text(entry.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Current Passphrase")
                                        .font(.subheadline.weight(.medium))
                                }
                                Text("Saved \(recoveryTimestamp(entry.createdAt))")
                                    .font(.caption).foregroundStyle(.secondary)
                                HStack {
                                    Text(revealedArchivedPassphraseIDs.contains(entry.id)
                                         ? entry.passphrase
                                         : String(repeating: "•", count: min(entry.passphrase.count, 32)))
                                        .font(.system(.footnote, design: .monospaced))
                                        .textSelection(.enabled)
                                        .privacySensitive()
                                    Spacer(minLength: 4)
                                    Menu {
                                        Button(revealedArchivedPassphraseIDs.contains(entry.id) ? "Hide passphrase" : "Reveal passphrase") {
                                            if revealedArchivedPassphraseIDs.contains(entry.id) { revealedArchivedPassphraseIDs.remove(entry.id) }
                                            else { revealedArchivedPassphraseIDs.insert(entry.id) }
                                        }
                                        Button("Copy passphrase") { copySecret(entry.passphrase) }
                                        Button("Delete archived phrase", role: .destructive) {
                                            do { archivedPassphrases = try VaultPassphraseArchive.delete(entry) }
                                            catch { banner = "Could not delete the archived phrase. \(error.localizedDescription)" }
                                        }
                                    } label: { Image(systemName: "ellipsis.circle").foregroundStyle(palette.accentText) }
                                        .accessibilityLabel("Archived phrase actions")
                                }
                            }
                            .padding(.vertical, 4)
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    do { archivedPassphrases = try VaultPassphraseArchive.delete(entry) }
                                    catch { banner = "Could not delete the archived phrase. \(error.localizedDescription)" }
                                } label: { Label("Delete", systemImage: "trash") }
                            }
                        }
                    }
                if !generatedPassphraseIsSaved && archivedPassphrases.isEmpty {
                    Text("No generated or archived passphrases are stored on this iPhone.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            } footer: {
                Text("Generated passphrases contain 144 random bits and stay in this iPhone's device-only Keychain. They do not sync to Apple Passwords or move to a new phone.")
            }
        }
        .navigationTitle("Recovery phrases")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var securityKeysView: some View {
        Form {
            Section {
                    if #available(iOS 26.4, *) {
                        Text("Register each physical key once and give it a name. The system identifies credentials, not key serial numbers, so Tagcrypt cannot prove that two registrations are separate devices.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        ForEach(fido.registeredKeys, id: \.credentialID) { key in
                            VStack(alignment: .leading, spacing: 8) {
                                Label(key.displayName, systemImage: "key.fill")
                                HStack {
                                    Button("Rename") {
                                        keyBeingRenamed = key
                                        fidoNameDraft = key.displayName
                                        renameFIDOKeyError = nil
                                        deferredSettingsAction = .renameFIDOKey
                                        showSettings = false
                                    }
                                    .buttonStyle(.borderless)
                                    Spacer()
                                    Button("Forget", role: .destructive) {
                                        keyPendingForget = key
                                        showForgetFIDOKeyConfirmation = true
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                        }
                        Button("Add a FIDO2 security key") {
                            fidoNameDraft = fido.registeredKeys.isEmpty ? "Security key" : ""
                            confirmedDifferentPhysicalFIDOKey = false
                            deferredSettingsAction = .registerFIDOKey
                            showSettings = false
                        }
                        Text("Records can use a passphrase, a FIDO key, or both. Joint-factor records retain passphrase-only emergency recovery. QR records can be scanned by Tagcrypt on iPad; external USB-C/NFC support depends on OS version and key model and must be verified on those devices.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Text("Requires iOS or iPadOS 26.4 or later, a matching app/domain association, and a key that supports PRF. Ordinary FIDO2 sign-in support alone is not enough. Different credential registrations may still reside on one physical key; Tagcrypt cannot detect a key’s serial number.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("External security-key PRF requires iOS or iPadOS 26.4 or later. This device's current OS does not meet that requirement.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
            }
        }
        .navigationTitle("Security keys")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Forget this security key?", isPresented: $showForgetFIDOKeyConfirmation, titleVisibility: .visible) {
                Button("Forget security key", role: .destructive) {
                    guard let key = keyPendingForget else { return }
                    do {
                        try fido.removeRegisteredKey(key)
                        selectedFIDOKeyIDs.remove(key.credentialID)
                        if keyBeingRenamed?.credentialID == key.credentialID {
                            keyBeingRenamed = nil
                            showRenameFIDOKeySheet = false
                        }
                        if fido.registeredKeys.isEmpty { recordUnlockChoiceRaw = RecordUnlockChoice.passphrase.rawValue }
                        keyPendingForget = nil
                        nfc.setStatus("Security key forgotten on this iPhone. Existing records may still require this key or their recovery passphrase.")
                    } catch {
                        keyPendingForget = nil
                        banner = "Could not forget the security key. It remains registered. \(error.localizedDescription)"
                    }
                }
                Button("Cancel", role: .cancel) { keyPendingForget = nil }
            } message: {
                Text("This removes the saved profile from this iPhone. Records already encrypted with this key will need another registered key or their passphrase recovery route.")
            }
    }

    private var tagKeysView: some View {
        Form {
            Section {
                if (try? TagLockKeyStore.loadAutoKey()) != nil {
                    SettingRow(title: "Auto key", caption: "On this iPhone",
                               detail: "One random device-only master key. Full encrypted Vault backups include it. Replacing it means this iPhone can no longer rewrite tags protected with the old key.")
                    Button("Back up in encrypted Vault export…") {
                        vaultExportSelection = nil
                        showSettings = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { showVaultExportWarning = true }
                    }
                    Button("Replace Auto key…", role: .destructive) {
                        pendingSettingsRiskAction = .rotateAutoKey
                        showTagKeyRiskAlert = true
                    }
                } else {
                    SettingRow(title: "Auto key", caption: "Created when Auto is chosen")
                }
            }
            Section("Organisation keys") {
                ForEach(organisationKeysCache) { key in
                    HStack {
                        Text(key.label)
                        Spacer()
                        Button("Delete", role: .destructive) {
                            pendingSettingsRiskAction = .deleteOrganisationKey(key.id, key.label)
                            showTagKeyRiskAlert = true
                        }
                        .font(.footnote)
                        .buttonStyle(.borderless)
                    }
                }
                .id(organisationKeyListRevision)
                .onAppear { organisationKeysCache = (try? TagLockKeyStore.loadOrganisationKeys()) ?? [] }
                .onChange(of: organisationKeyListRevision) { _ in
                    organisationKeysCache = (try? TagLockKeyStore.loadOrganisationKeys()) ?? []
                }
                HStack {
                    TextField("New key label", text: $tagLockOrganisationLabel)
                        .textInputAutocapitalization(.words)
                    Button("Create") {
                        do {
                            _ = try TagLockKeyStore.createOrganisationKey(label: tagLockOrganisationLabel)
                            tagLockOrganisationLabel = ""
                            organisationKeyListRevision += 1
                            banner = "Organisation key created. Export its encrypted bundle and share the file and passphrase through separate channels."
                        } catch {
                            banner = "Could not create Organisation key. Enter a label and try again."
                        }
                    }
                    .buttonStyle(.borderless)
                    .disabled(tagLockOrganisationLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                SettingRow(title: "Export key bundle", caption: "Locked with backup passphrase",
                           detail: "Locked with the passphrase from Settings → Backup. Never send the passphrase through the same channel as the bundle.") {
                    Button("Export…") { prepareTagLockKeyExport() }
                        .buttonStyle(.borderless)
                        .disabled(!vaultExportPassphraseIsLongEnough)
                }
                SettingRow(title: "Import key bundle", caption: "From a .tagcryptlock file",
                           detail: "Adds the Organisation keys from a bundle someone shared with you. Enter the bundle's passphrase in Settings → Backup first. Keys with the same ID are not added twice, and your Auto key is never replaced by an import.") {
                    Button("Import…") {
                        Task {
                            guard await authenticateForProtectedVaultAction() else { return }
                            showSettings = false
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { showVaultImportPicker = true }
                        }
                    }
                    .buttonStyle(.borderless)
                    .disabled(vaultExportPassphrase.isEmpty)
                }
            }
        }
        .navigationTitle("Tag keys")
        .navigationBarTitleDisplayMode(.inline)
        .alert(settingsRiskTitle, isPresented: $showTagKeyRiskAlert) {
            Button("Continue", role: .destructive) { applyPendingSettingsRiskAction() }
            Button("Cancel", role: .cancel) { pendingSettingsRiskAction = nil }
        } message: {
            Text(settingsRiskMessage)
        }
    }

    private var tagDiagnosticsView: some View {
        Form {
            Section("Last scanned tag") {
                Text(nfc.scannedTagSummary)
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Last result") {
                Text(nfc.status).font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let crc = nfc.lastCRCDiagnostic {
                Section("Last CRC test") {
                    Text(crc)
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Section {
                SettingRow(title: "Identify a tag", caption: "Chip, space, contents") {
                    Button("Scan") { nfc.identifyTag() }
                        .buttonStyle(.borderless)
                        .disabled(nfc.isScanning)
                }
                if let result = nfc.identifyResult {
                    Text(result).font(.footnote).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                SettingRow(title: "Remove tag password", caption: "Make a tag writable again",
                           detail: "Unlocks the tag with your Auto or Organisation key, clears its password and resets the stored password to the factory value, so any app can write it again. The record on the tag is not changed. Not possible on a sealed tag.") {
                    Button("Scan") { nfc.removeTagPassword(candidates: allKnownTagLockCandidates) }
                        .buttonStyle(.borderless)
                        .disabled(nfc.isScanning)
                }
                SettingRow(title: "CRC test", caption: "Read-only, writes nothing",
                           detail: "Sends GET_VERSION twice, with and without a CRC, and shows both replies above. Run it once per batch of disposable tags. Normal scans already try both and keep the one that works.") {
                    Button("Run") { nfc.runCRCDiagnostic() }
                        .buttonStyle(.borderless)
                        .disabled(nfc.isScanning)
                }
            }
        }
        .navigationTitle("Tag details")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var permanentSealView: some View {
        Form {
            Section {
                SettingRow(title: "Seal this record", caption: "Irreversible · NTAG213/215/216",
                           detail: "Freezes all user-memory pages of an NTAG213, 215 or 216, the Capability Container and the configuration pages; the record stays readable but can never be changed. Verified on one NTAG216-compatible tag (2026-10-11); not yet on genuine NXP chips. Tagcrypt checks the exact prepared record and the lock bytes, asks you to confirm, then needs the same tag rescanned. Tag password must be Off and raw-page storage off. A model reply is not proof of genuine NXP silicon.",
                           tint: .orange)
                Button(role: .destructive) {
                    guard let preparedRecord else {
                        banner = "Prepare and verify an encrypted record in this session before sealing a tag."
                        return
                    }
                    // The irreversible confirmation is shown on the main screen, so
                    // close Settings first; otherwise it appears hidden behind it.
                    showSettings = false
                    let lockMode = TagLockMode(rawValue: tagLockModeRaw) ?? .off
                    let rawMode = rawPageModeEnabled
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
                        nfc.prepareWholeMemorySeal(for: preparedRecord, tagLockMode: lockMode, rawPageMode: rawMode)
                    }
                } label: {
                    Label("Inspect and seal this tag…", systemImage: "lock.fill")
                }
                .disabled(preparedRecord == nil || nfc.isScanning || rawPageModeEnabled || tagLockModeRaw != "Off")
                if preparedRecord == nil {
                    Text("Prepare an encrypted record first.").font(.footnote).foregroundStyle(.secondary)
                } else if rawPageModeEnabled || tagLockModeRaw != "Off" {
                    Text("Turn off Tag password and Raw-page storage first.").font(.footnote).foregroundStyle(.orange)
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if !nfc.status.isEmpty {
                Text(nfc.status)
                    .font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                    .padding(.horizontal, 16).padding(.bottom, 8)
            }
        }
        .navigationTitle("Permanent seal")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var securityAndPrivacyView: some View {
        List {
            Section("Encryption") {
                Text("New passphrase records use Argon2id (libsodium) and ChaCha20-Poly1305 with a fresh random salt. Older v2–v6 records are still read with PBKDF2-HMAC-SHA256 (600,000 rounds). FIDO-only records wrap a random data key using the selected key's WebAuthn PRF output. Joint-factor records normally require both factors and retain a passphrase-only emergency route.")
            }
            Section("Limits") {
                Text("A tag is copyable. Anyone with a copy of a passphrase-based record can make offline guesses; use a generated or unique, strong passphrase. FIDO-only records have no passphrase recovery; losing every selected key makes the secret unrecoverable. A copied valid record can also be replayed.")
                Text("Tagcrypt does not make NFC tags tamper-proof and has not had an independent security audit. FIDO2 PRF key wrapping requires a supported iOS version and compatible physical key; it is not a general FIDO2 login or hardware-wallet feature. First-use acknowledgement is stored on this device and is not a legal warranty or account-linked consent receipt.")
            }
            Section("Privacy and storage") {
                Text("Tagcrypt processes secrets on this device and does not upload them. The Recovery Vault encrypts saved passphrases, labels, and optional encrypted NFC/QR payloads at rest; its key does not sync or transfer to a replacement device. Slot titles and secrets are encrypted together in records. Saved tag labels and FIDO key names are stored with Vault entries.")
                Text("The Vault asks for Face ID or device passcode before showing saved entries by default. Saving or reusing an encrypted payload also asks for device authentication. The Vault is local and does not sync.")
                Text("Generated passphrases contain 144 random bits and are stored in this device's Keychain. They do not sync to Apple Passwords or transfer to a replacement device. Custom passphrases are saved to the Vault only after a verified NFC write or when you tap Save. Keep a separate recovery copy before writing.")
                Text("Generated phrases survive app closure and a normal restart. iOS often retains Keychain items after an app is removed, but Tagcrypt cannot guarantee recovery after uninstall, reinstall, device erase, or an app identity change. The Recovery Vault data file is inside the app's local container and is removed when the app is deleted. Export an encrypted Vault backup to Files before deleting the app; keep its backup passphrase separately.")
            }
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .navigationTitle("Security & privacy")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var renameFIDOKeySheet: some View {
        NavigationStack {
            Form {
                Section("Key name") {
                    TextField("Name this security key", text: $fidoNameDraft)
                        .textInputAutocapitalization(.words)
                        .autocorrectionDisabled()
                }
                if let renameFIDOKeyError {
                    Section {
                        Label(renameFIDOKeyError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
                Section {
                    Text("Renaming changes only the label stored on this iPhone. It does not change the physical key or records already written.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Rename security key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        showRenameFIDOKeySheet = false
                        keyBeingRenamed = nil
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: saveFIDOKeyName)
                        .disabled(fidoNameDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .tint(palette.accentText)
        }
        .presentationDetents([.medium])
    }

    private func saveFIDOKeyName() {
        let name = fidoNameDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            renameFIDOKeyError = "Enter a name for this security key."
            return
        }
        guard let keyBeingRenamed else {
            renameFIDOKeyError = "The selected key is no longer in the registered list. It has not been removed."
            return
        }
        do {
            try fido.rename(keyBeingRenamed, to: name)
            selectedFIDOKeyIDs.insert(keyBeingRenamed.credentialID)
            nfc.setStatus("Security key renamed to \(name).")
            renameFIDOKeyError = nil
            self.keyBeingRenamed = nil
            showRenameFIDOKeySheet = false
        } catch {
            // Leave the registered key visible and keep the rename editor open.
            renameFIDOKeyError = "Could not save the new name. The key profile is unchanged. \(error.localizedDescription)"
        }
    }

    private var recoveryPhrasePickerSheet: some View {
        NavigationStack {
            List {
                if vaultEntries.isEmpty && archivedPassphrases.isEmpty {
                    Text("No archived recovery phrases are stored on this iPhone yet.")
                        .foregroundStyle(.secondary)
                }
                if !vaultEntries.isEmpty {
                    Section("Recovery Vault") {
                        ForEach(vaultEntries.filter { !$0.passphrase.isEmpty }) { entry in
                            Button {
                                passphrase = entry.passphrase
                                passphraseConfirmation = entry.passphrase
                                showRecoveryPhrasePicker = false
                                Task { await decryptScannedRecord(using: entry.passphrase) }
                            } label: {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(entry.nickname).font(.headline)
                                    Text("\(entry.destination) · \(entry.updatedAt.formatted(date: .abbreviated, time: .shortened))")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }.privacySensitive()
                        }
                    }
                }
                if !archivedPassphrases.isEmpty {
                    Section("Saved recovery phrases") {
                    ForEach(archivedPassphrases) { entry in
                        Button {
                            passphrase = entry.passphrase
                            passphraseConfirmation = entry.passphrase
                            showRecoveryPhrasePicker = false
                            Task { await decryptScannedRecord(using: entry.passphrase) }
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Saved recovery phrase")
                                    .font(.headline)
                                Text(entry.createdAt.formatted(date: .abbreviated, time: .shortened))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .privacySensitive()
                    }
                    }
                }
            }
            .navigationTitle("Tagcrypt Recovery Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { showRecoveryPhrasePicker = false }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var qrPreviewSheet: some View {
        NavigationStack {
            VStack(spacing: 14) {
                Text("Encrypted QR record")
                    .font(.title2.weight(.semibold))
                if let qrPreviewImage {
                    Image(uiImage: qrPreviewImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 280, height: 280)
                        .padding(12)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 14))
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.black.opacity(0.12), lineWidth: 1))
                        .accessibilityLabel("QR code containing encrypted Tagcrypt data")
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "qrcode").font(.largeTitle)
                        Text("QR unavailable").font(.headline)
                        Text("Create the encrypted record again to generate a QR image.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(height: 280)
                }
                VStack(spacing: 10) {
                  Button {
                      saveCurrentPassphraseToVault(destinationName: "QR code")
                  } label: {
                      Label("Save passphrase and nickname to Vault", systemImage: "lock.doc")
                          .frame(maxWidth: .infinity).padding(.vertical, 11)
                          .background(palette.selectedTab, in: RoundedRectangle(cornerRadius: 13))
                          .foregroundStyle(palette.accentText)
                  }
                  HStack(spacing: 10) {
                    Button {
                        guard let qrPreviewImage else { return }
                        qrExportDocument = TagcryptQRDocument(image: qrPreviewImage)
                        qrPreviewActionAfterDismissal = .export
                        showQRPreview = false
                    } label: {
                        Label("Save to Files", systemImage: "folder")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(palette.accent, in: RoundedRectangle(cornerRadius: 13))
                            .foregroundStyle(palette.onAccent)
                    }
                    Button {
                        guard let qrPreviewImage else { return }
                        printQR(qrPreviewImage)
                    } label: {
                        Image(systemName: "printer")
                            .frame(width: 48, height: 48)
                            .background(palette.input, in: RoundedRectangle(cornerRadius: 13))
                            .foregroundStyle(palette.primary)
                    }
                    .accessibilityLabel("Print QR")
                  }
                  HStack(spacing: 10) {
                    Button {
                        guard let qrPreviewImage else { return }
                        Task { await saveQRToPhotos(qrPreviewImage) }
                    } label: {
                        Label("Save to Photos", systemImage: "photo")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(palette.accent, in: RoundedRectangle(cornerRadius: 13))
                            .foregroundStyle(palette.onAccent)
                    }
                    Button {
                        guard let qrPreviewImage else { return }
                        qrShareImage = qrPreviewImage
                        qrPreviewActionAfterDismissal = .share
                        showQRPreview = false
                    } label: {
                        Label("Share QR…", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(palette.input, in: RoundedRectangle(cornerRadius: 13))
                            .foregroundStyle(palette.primary)
                    }
                  }
                }
                .disabled(qrPreviewImage == nil)
                Text("The QR contains encrypted data only. Treat saved or shared copies like the tag.")
                    .font(.caption)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                Text("QR records are limited to about 1,200 bytes and should be printed at 60 mm or larger for reliable scanning.")
                    .font(.caption2)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(22)
            .background(palette.background.ignoresSafeArea())
            .navigationTitle("QR backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showQRPreview = false } } }
        }
        .presentationDetents([.large])
    }

    @ViewBuilder
    private var statusCard: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: statusCardSymbol)
                .foregroundStyle(nfc.lastOutcome == .failed ? Color.red : palette.accentText)
                .accessibilityLabel(statusCardAccessibilityLabel)
            Text(nfc.status)
                .font(.subheadline)
                .foregroundStyle(palette.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            if nfc.isScanning { ProgressView().tint(palette.accent) }
        }
        .padding(15)
        .background(palette.accent.opacity(0.11), in: RoundedRectangle(cornerRadius: 15))
        if let warning = nfc.tagPasswordSetupWarning {
            VStack(alignment: .leading, spacing: 8) {
                Label("Tag password setup incomplete", systemImage: "exclamationmark.triangle.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.orange)
                Text(warning)
                    .font(.footnote)
                    .foregroundStyle(palette.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Dismiss") { nfc.dismissTagPasswordSetupWarning() }
                    .font(.footnote.weight(.semibold))
            }
            .padding(15)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 15))
        }
    }

    private var statusCardSymbol: String {
        if nfc.isScanning { return "dot.radiowaves.left.and.right" }
        switch nfc.lastOutcome {
        case .skipped: return "minus.circle"
        case .written, .read: return "checkmark.circle"
        case .failed: return "exclamationmark.triangle"
        case .cancelled: return "xmark.circle"
        case nil: return "info.circle"
        }
    }

    private var statusCardAccessibilityLabel: String {
        switch nfc.lastOutcome {
        case .skipped: return "Skipped, tag not changed"
        case .written: return "Written and verified"
        case .read: return "Read"
        case .failed: return "Failed"
        case .cancelled: return "Cancelled"
        case nil: return "Status"
        }
    }

    private var nfcOverwritePolicyDescription: String {
        switch NFCOverwritePolicy(rawValue: nfcOverwritePolicyRaw) ?? .warn {
        case .warn: "Ask before replacing data on a tag."
        case .never: "Stop the write when a tag already has data."
        case .skip: "Leave this tag unchanged if it already contains data."
        case .always: "Replace existing tag data without asking."
        }
    }

    private func sectionTitle(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption2.weight(.bold)).tracking(1.5).foregroundStyle(palette.accentText)
            Text(detail).font(.caption).foregroundStyle(palette.secondary)
        }
    }

    private func invalidateCryptoOperation() {
        guard isCryptoWorking else { return }
        cryptoOperation = UUID()
        isCryptoWorking = false
    }

    private func restoreGeneratedPassphrase() {
        do {
            guard let savedPassphrase = try VaultPassphraseStore.load() else {
                generatedPassphraseIsSaved = false
                return
            }
            generatedPassphraseIsSaved = true
            guard passphrase.isEmpty || passphrase == generatedPassphraseValue else { return }
            passphrase = savedPassphrase
            passphraseConfirmation = savedPassphrase
            generatedPassphraseValue = savedPassphrase
        } catch {
            generatedPassphraseIsSaved = false
            banner = error.localizedDescription
        }
    }

    private func copySecret(_ value: String) {
        UIPasteboard.general.setItems(
            [["public.utf8-plain-text": value]],
            options: [.expirationDate: Date().addingTimeInterval(60), .localOnly: true]
        )
        nfc.setStatus("Copied. The clipboard entry expires after one minute where supported.")
    }

    private func combineRecoveryShares() {
        do {
            let record = try TagcryptRecoveryShares.combine([recoveryShareOne, recoveryShareTwo])
            guard VaultCrypto.isTagcryptRecord(record) else { throw VaultError.malformedRecord }
            pendingEncryptedRecord = record
            pendingRecordSource = "recovery shares"
            passphrase = ""
            selectedTab = .decrypt
            recoveryShareOne = ""
            recoveryShareTwo = ""
            showRecoveryShareImport = false
            nfc.setStatus("Encrypted record reconstructed. Enter its passphrase or use its registered security key to decrypt it.")
        } catch {
            banner = "Could not reconstruct the encrypted record. Check that the two shares are distinct, complete, and from the same set. \(error.localizedDescription)"
        }
    }

    private func recoveryShareNDEFSize(index: Int) -> Int {
        guard recoveryShareExports.indices.contains(index),
              let share = try? TagcryptRecoveryShares.binaryData(from: recoveryShareExports[index]) else { return Int.max }
        return VaultNDEFTextCodec.binaryShareMessageLength(byteCount: share.count)
    }

    private func recoveryShareFitsSelectedNFC(index: Int) -> Bool {
        guard recoveryShareExports.indices.contains(index),
              let share = try? TagcryptRecoveryShares.binaryData(from: recoveryShareExports[index]) else { return false }
        return rawPageModeEnabled ? share.count <= selectedSize.bytes : recoveryShareNDEFSize(index: index) <= estimatedNDEFCapacity
    }

    private func prepareRecoveryShareForNFC(index: Int) {
        guard recoveryShareFitsSelectedNFC(index: index), recoveryShareExports.indices.contains(index) else {
            banner = "This recovery share does not fit the selected NFC storage capacity. Choose a larger NTAG21x size."
            return
        }
        do {
            let share = try TagcryptRecoveryShares.binaryData(from: recoveryShareExports[index])
            preparedRecord = share
            preparedRecoveryShareIndex = index
            destination = .nfc
            writingRecoveryShare = true
            showRecoveryShares = false
            selectedTab = .encrypt
            nfc.setStatus("Recovery share \(index + 1) is ready. Write it to a separate tag, then repeat for the other shares.")
        } catch {
            banner = "Could not prepare this recovery share. \(error.localizedDescription)"
        }
    }

    private func recoveryTimestamp(_ date: Date) -> String {
        date.formatted(.dateTime.day().month(.abbreviated).year().hour().minute().second())
    }

    private func refreshArchivedPassphrases() {
        do { archivedPassphrases = try VaultPassphraseArchive.load() }
        catch { banner = "Recovery phrases could not be loaded. No saved data was changed. \(error.localizedDescription)" }
    }

    private func refreshVaultEntries() {
        do { vaultEntries = try TagcryptVaultStore.load() }
        catch { banner = "The encrypted Vault could not be opened. Existing data was not changed. \(error.localizedDescription)" }
    }

    private func saveCurrentPassphraseToVault(destinationName: String? = nil) {
        guard !passphrase.isEmpty else { banner = "Enter a passphrase before saving it to the Vault."; return }
        do {
            vaultEntries = try TagcryptVaultStore.upsert(
                passphrase: passphrase,
                nickname: destinationName == "QR code" && !tagNickname.isEmpty ? tagNickname : "Recovery phrase",
                destination: destinationName ?? "Recovery phrase",
                fidoKeyNames: useSecurityKeyUnlock ? selectedFIDOKeys.map(\.displayName) : []
            )
            nfc.setStatus("Passphrase saved to the encrypted on-device Vault.")
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) { showPassphraseSavedToast = true }
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(1.6))
                withAnimation(.easeOut(duration: 0.2)) { showPassphraseSavedToast = false }
            }
        } catch { banner = "Could not save the passphrase to the Vault. \(error.localizedDescription)" }
    }

    @MainActor
    private func authenticateForProtectedVaultAction() async -> Bool {
        let context = LAContext()
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            banner = "This action requires device authentication. Set a device passcode in iPhone Settings to save or retrieve encrypted payloads."
            return false
        }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication,
                                                   localizedReason: "Protect your saved encrypted Tagcrypt record")
        } catch {
            banner = "Biometric authentication was not confirmed. No payload was saved or opened. \(error.localizedDescription)"
            return false
        }
    }

    @MainActor
    private func savePreparedPayloadToVault() async {
        guard let payload = preparedRecord else { return }
        guard await authenticateForProtectedVaultAction() else { return }
        do {
            let nickname = tagNickname.trimmingCharacters(in: .whitespacesAndNewlines)
            vaultEntries = try TagcryptVaultStore.upsert(
                passphrase: passphrase,
                nickname: nickname.isEmpty ? "Encrypted \(destination.rawValue) copy" : nickname,
                destination: destination.rawValue,
                fidoKeyNames: useSecurityKeyUnlock ? selectedFIDOKeys.map(\.displayName) : [],
                encryptedPayload: payload
            )
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            nfc.setStatus("Encrypted payload saved to the on-device Recovery Vault.")
            withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) { showPassphraseSavedToast = true }
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(1.6))
                withAnimation(.easeOut(duration: 0.2)) { showPassphraseSavedToast = false }
            }
        } catch { banner = "Could not save the encrypted payload. \(error.localizedDescription)" }
    }

    @MainActor
    private func prepareSavedPayload(_ entry: TagcryptVaultEntry, as destination: RecordDestination) async {
        preparedRecoveryShareIndex = nil
        writingRecoveryShare = false
        guard await authenticateForProtectedVaultAction() else { return }
        guard let payload = entry.encryptedPayload else {
            banner = "This Vault entry has no saved encrypted payload."
            return
        }
        passphrase = entry.passphrase
        passphraseConfirmation = entry.passphrase
        tagNickname = entry.nickname
        self.destination = destination
        selectedTab = .encrypt
        DispatchQueue.main.async {
            preparedRecord = payload
            if destination == .qr { presentQR(for: payload) }
            else { nfc.setStatus("Saved encrypted payload ready. Tap Write prepared record to write it to an NFC tag.") }
        }
    }

    private func selectTab(_ tab: MainTab) {
        guard tab == .vault, vaultRequiresFaceID else {
            selectedTab = tab
            return
        }
        selectedTab = .vault
        guard !isRecoveryVaultUnlocked, !isRecoveryVaultAuthenticating else { return }
        Task { await authenticateRecoveryVault() }
    }

    @MainActor
    private func authenticateRecoveryVault() async {
        guard vaultRequiresFaceID else { isRecoveryVaultUnlocked = true; return }
        guard !isRecoveryVaultAuthenticating else { return }
        isRecoveryVaultAuthenticating = true
        defer { isRecoveryVaultAuthenticating = false }
        let context = LAContext()
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            selectedTab = .encrypt
            banner = "Device authentication is unavailable. Set a device passcode, or turn off the Vault viewing prompt in Tagcrypt Settings."
            return
        }
        do {
            isRecoveryVaultUnlocked = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Unlock your Tagcrypt Recovery Vault"
            )
            if !isRecoveryVaultUnlocked { selectedTab = .encrypt }
        } catch {
            selectedTab = .encrypt
            banner = "The Recovery Vault stayed locked. \(error.localizedDescription)"
        }
    }

    private func requestRecoveryPhrasePicker() {
        guard vaultRequiresFaceID else { showRecoveryPhrasePicker = true; return }
        Task { @MainActor in
            await authenticateRecoveryVault()
            if isRecoveryVaultUnlocked { showRecoveryPhrasePicker = true }
        }
    }

    private func associateCurrentPassphraseWithWrittenTag() {
        guard !passphrase.isEmpty || recordUnlockChoice == .fido else { return }
        do {
            vaultEntries = try TagcryptVaultStore.upsert(passphrase: passphrase, nickname: tagNickname,
                destination: "NFC tag", fidoKeyNames: useSecurityKeyUnlock ? selectedFIDOKeys.map(\.displayName) : [])
            nfc.setStatus("NFC write verified. The passphrase and tag label were saved in this iPhone’s encrypted Vault.")
        } catch { banner = "The tag was written, but its Vault label could not be updated: \(error.localizedDescription)" }
    }

    private func vaultCSV() throws -> String {
        let header = ["id", "tag_nickname", "destination", "passphrase", "fido_key_names", "encrypted_payload_base64", "created_at", "updated_at"]
        let entries = try vaultExportSelection ?? vaultExportEntries()
        let formatter = ISO8601DateFormatter()
        let rows = entries.map { entry in
            [entry.id.uuidString, entry.nickname, entry.destination, entry.passphrase, entry.fidoKeyNames.joined(separator: "; "),
             entry.encryptedPayload?.base64EncodedString() ?? "",
             formatter.string(from: entry.createdAt), formatter.string(from: entry.updatedAt)]
        }
        return ([header] + rows).map { row in
            row.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: ",")
        }.joined(separator: "\r\n")
    }

    private func prepareCSVExport() {
        guard vaultExportPassphraseIsLongEnough else { return }
        do {
            let csv = try vaultCSV()
            let backup = PasswordVault(secret: csv)
            let payload = try VaultCrypto.seal(backup, passphrase: vaultExportPassphrase)
            vaultExportDocument = TagcryptVaultExport(data: Data(("TAGCRYPTCSV1:" + payload.base64EncodedString()).utf8))
            showCSVExportWarning = false
            showCSVExportFilePicker = true
        } catch {
            showCSVExportWarning = false
            banner = "Could not prepare the encrypted CSV backup. \(error.localizedDescription)"
        }
    }

    private func decodeVaultCSV(_ csv: String) throws -> [TagcryptVaultEntry] {
        let characters = Array(csv)
        var rows = [[String]]()
        var row = [String]()
        var field = ""
        var quoted = false
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if quoted {
                if character == "\"" {
                    if index + 1 < characters.count && characters[index + 1] == "\"" {
                        field.append("\""); index += 1
                    } else { quoted = false }
                } else { field.append(character) }
            } else {
                switch character {
                case "\"" where field.isEmpty: quoted = true
                case ",": row.append(field); field = ""
                case "\n": row.append(field); rows.append(row); row = []; field = ""
                case "\r": break
                default: field.append(character)
                }
            }
            index += 1
        }
        guard !quoted else { throw VaultError.malformedRecord }
        if !field.isEmpty || !row.isEmpty { row.append(field); rows.append(row) }
        guard let header = rows.first,
              header == ["id", "tag_nickname", "destination", "passphrase", "fido_key_names", "encrypted_payload_base64", "created_at", "updated_at"] else {
            throw VaultError.malformedRecord
        }
        let formatter = ISO8601DateFormatter()
        return try rows.dropFirst().map { values in
            guard values.count == header.count,
                  let id = UUID(uuidString: values[0]),
                  (!values[3].isEmpty || !values[4].isEmpty || !values[5].isEmpty),
                  let created = formatter.date(from: values[6]),
                  let updated = formatter.date(from: values[7]) else { throw VaultError.malformedRecord }
            let payload: Data?
            if values[5].isEmpty { payload = nil }
            else if let decoded = Data(base64Encoded: values[5]) { payload = decoded }
            else { throw VaultError.malformedRecord }
            let keyNames = values[4].isEmpty ? [] : values[4].components(separatedBy: "; ")
            return TagcryptVaultEntry(id: id, passphrase: values[3], nickname: values[1], destination: values[2],
                                      fidoKeyNames: keyNames, encryptedPayload: payload,
                                      createdAt: created, updatedAt: updated)
        }
    }

    private func vaultExportEntries() throws -> [TagcryptVaultEntry] {
        let entries = try TagcryptVaultStore.load()
        let archivedRows = try VaultPassphraseArchive.load()
            .filter { archived in !entries.contains(where: { $0.passphrase == archived.passphrase }) }
            .map { archived in
                TagcryptVaultEntry(passphrase: archived.passphrase,
                                   nickname: archived.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Current Passphrase",
                                   destination: "Recovery phrase archive", fidoKeyNames: [],
                                   createdAt: archived.createdAt, updatedAt: archived.createdAt)
            }
        return entries + archivedRows
    }

    @MainActor
    private func deleteSelectedRecoveryEntries() async {
        let vaultIDs = selectedVaultEntryIDs
        let archiveIDs = selectedArchivedPhraseIDs
        guard !vaultIDs.isEmpty || !archiveIDs.isEmpty else { return }
        if vaultRequiresFaceID, !(await authenticateForProtectedVaultAction()) { return }
        do {
            vaultEntries = try TagcryptVaultStore.delete(ids: vaultIDs)
            archivedPassphrases = try VaultPassphraseArchive.delete(ids: archiveIDs)
            selectedVaultEntryIDs.removeAll()
            selectedArchivedPhraseIDs.removeAll()
            vaultSelectionMode = false
            banner = "Deleted \(vaultIDs.count + archiveIDs.count) selected recovery entries. Existing tags and QR codes are unchanged."
        } catch {
            banner = "Could not delete the selected recovery entries. \(error.localizedDescription)"
        }
    }

    private func requestGeneratedPassphrase() {
        do {
            let generated = try VaultCrypto.generatePassphrase()
            requestPassphraseRotation(generated)
        } catch { banner = error.localizedDescription }
    }

    private func requestMemorablePassphrase() {
        do {
            let generated = try TagcryptPassphraseAssessment.generateMemorablePhrase()
            requestPassphraseRotation(generated)
        } catch { banner = error.localizedDescription }
    }

    private func requestPassphraseRotation(_ generated: String) {
            if !passphrase.isEmpty {
                generatedPassphraseToInstall = generated
                let currentTime = Date().formatted(.dateTime.day().month(.abbreviated).hour().minute())
                rotationVaultLabel = "Current Passphrase · \(currentTime)"
                showPassphraseRotationPrompt = true
            } else {
                installGeneratedPassphrase(generated)
            }
    }

    private func setHealthReminder(_ enabled: Bool) {
        guard enabled else {
            TagcryptHealthReminder.disable()
            healthReminderStatus = "Reminder disabled. Existing tags and saved copies are unchanged."
            return
        }
        Task { @MainActor in
            let scheduled = await TagcryptHealthReminder.enable()
            if scheduled {
                healthReminderStatus = "Reminder scheduled locally. You can change it in iOS notification settings."
            } else {
                healthReminderEnabled = false
                healthReminderStatus = "Notifications were not allowed, so no reminder was scheduled. Enable notifications in iOS Settings and try again."
            }
        }
    }

    private func confirmPassphraseRotation() {
        let label = rotationVaultLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let next = generatedPassphraseToInstall, !passphrase.isEmpty, !label.isEmpty else { return }
        do {
            // Preserve the old phrase first; on any error it remains active.
            archivedPassphrases = try VaultPassphraseArchive.archive(passphrase, label: label)
            vaultEntries = try TagcryptVaultStore.upsert(passphrase: passphrase,
                nickname: label,
                destination: "Recovery phrase", fidoKeyNames: [])
            try VaultPassphraseStore.save(next)
            installGeneratedPassphrase(next, persist: false)
            generatedPassphraseToInstall = nil
            rotationVaultLabel = ""
                showPassphraseRotationPrompt = false
                showPassphraseSavedToast = false
        } catch {
            generatedPassphraseToInstall = nil
            rotationVaultLabel = ""
            showPassphraseRotationPrompt = false
            banner = "The new phrase was not installed. Your current phrase remains active. \(error.localizedDescription)"
        }
    }

    private func discardCurrentPassphraseAndRotate() {
        guard let next = generatedPassphraseToInstall, !passphrase.isEmpty else { return }
        do {
            // Replace the active Keychain item without archiving or creating a Vault entry.
            try VaultPassphraseStore.save(next)
            installGeneratedPassphrase(next, persist: false)
            generatedPassphraseToInstall = nil
            rotationVaultLabel = ""
            showPassphraseRotationPrompt = false
            nfc.setStatus("A new passphrase is active. The previous phrase was not archived.")
        } catch {
            generatedPassphraseToInstall = nil
            rotationVaultLabel = ""
            showPassphraseRotationPrompt = false
            banner = "The new phrase was not installed. Your current phrase remains active. \(error.localizedDescription)"
        }
    }

    private func installGeneratedPassphrase(_ value: String, persist: Bool = true) {
        do {
            if persist { try VaultPassphraseStore.save(value) }
            passphrase = value
            generatedPassphraseValue = value
            passphraseConfirmation = value
            generatedPassphraseIsSaved = true
            showPassphrase = true
        } catch {
            banner = "The passphrase was not changed because Keychain could not save it. \(error.localizedDescription)"
        }
    }

    private func encrypt() async {
        preparedRecoveryShareIndex = nil
        writingRecoveryShare = false
        guard hasEncryptableContent else {
            banner = "Enter a secret or fill at least one slot before encrypting."
            return
        }
        guard !passphraseIsRequiredForRecord || passphraseMode != "perTag" || passphrase == passphraseConfirmation else {
            banner = "The passphrases do not match. Confirm the passphrase you will need to decrypt this record."
            return
        }
        guard !passphraseIsRequiredForRecord || TagcryptPassphraseAssessment.evaluate(passphrase).meetsMinimum else {
            banner = "Use a passphrase that meets the minimum strength shown below the field."
            return
        }
        guard destination == .qr || approximateRecordSize <= selectedNFCCapacity else {
            let storage = rawPageModeEnabled ? "raw user memory" : "usable NDEF capacity"
            banner = "This record is estimated at about \(approximateRecordSize) bytes, above the selected \(selectedSize.rawValue) \(storage) capacity (\(selectedNFCCapacity) bytes). Select a larger tag or use a shorter secret."
            return
        }
        let operation = UUID()
        cryptoOperation = operation
        let vaultToEncrypt = vaultDraft
        let passphraseToUse = passphrase
            let shouldPadRecord = destination == .qr || paddedRecordsEnabled || (destination == .nfc && rawPageModeEnabled)
            let targetNFCRecordLength = destination == .nfc && paddedRecordsEnabled ? nfcTargetRecordLength : nil
        let envelopeMode = recordUnlockChoice.envelopeMode
        isCryptoWorking = true
        do {
            let record: Data
            if useSecurityKeyUnlock {
                let keyProfiles = selectedFIDOKeys
                guard !keyProfiles.isEmpty, keyProfiles.count <= 3 else { throw FIDOKeyError.noRegisteredKey }
                let prfInput = try FIDOEnvelopeCrypto.makePRFInput()
                var credentials = [(credentialID: Data, prfOutput: Data)]()
                for profile in keyProfiles {
                    let output = try await fido.prfOutput(credentialID: profile.credentialID, input: prfInput)
                    credentials.append((profile.credentialID, output))
                }
                record = try await Task.detached(priority: .userInitiated) {
                    try FIDOEnvelopeCrypto.seal(vaultToEncrypt, passphrase: passphraseToUse,
                                                credentials: credentials, prfInput: prfInput,
                                                mode: envelopeMode, padRecord: shouldPadRecord,
                                                targetRecordLength: targetNFCRecordLength)
                }.value
            } else {
                record = try await Task.detached(priority: .userInitiated) {
                    try VaultCrypto.seal(vaultToEncrypt, passphrase: passphraseToUse, padRecord: shouldPadRecord,
                                         targetRecordLength: targetNFCRecordLength)
                }.value
            }
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            preparedRecord = record
            pendingEncryptedRecord = nil
            showSecret = false
            nfc.setStatus(destination == .nfc ? "Encrypted record ready to write." : "Encrypted QR created.")
            if destination == .qr { presentQR(for: record) }
        } catch {
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            banner = error.localizedDescription
        }
    }

    private func write() {
        guard let preparedRecord else { return }
        let policy = NFCOverwritePolicy(rawValue: nfcOverwritePolicyRaw) ?? .warn
        let mode = TagLockMode(rawValue: tagLockModeRaw) ?? .off
        var candidates: [TagLockCredentialCandidate] = mode == .off ? allKnownTagLockCandidates : []
        if mode != .off {
            do {
                let autoKey = mode == .auto ? try TagLockKeyStore.createAutoKey() : try TagLockKeyStore.loadAutoKey()
                let organisationKeys = try TagLockKeyStore.loadOrganisationKeys()
                if mode == .organisation && organisationKeys.isEmpty {
                    banner = "Organisation mode needs an imported Organisation key before it can protect a new tag. No NFC session was started."
                    return
                }
                candidates = TagLockCredentialResolver.candidates(mode: mode, autoKey: autoKey,
                                                                  organisationKeys: organisationKeys)
                if candidates.isEmpty {
                    banner = mode == .organisation
                        ? "No Auto or Organisation tag-lock key is available. Import/create a key or turn password mode Off."
                        : "The device-only tag-lock key is unavailable. Turn password mode Off, then try again."
                    return
                }
            } catch {
                banner = "Could not load the configured tag-password key. No NFC session was started."
                return
            }
        }
        nfc.write(preparedRecord, overwritePolicy: policy, wipeOldTagData: wipeUnusedTagPages,
                  rawPageMode: rawPageModeEnabled, tagLockMode: mode, tagLockCandidates: candidates)
    }

    /// All tag-lock keys on this device (Auto first). Only used to unlock tags
    /// that already have a password; never to set a new one.
    private var allKnownTagLockCandidates: [TagLockCredentialCandidate] {
        TagLockCredentialResolver.allKnownCandidates(
            autoKey: try? TagLockKeyStore.loadAutoKey(),
            organisationKeys: (try? TagLockKeyStore.loadOrganisationKeys()) ?? [])
    }

    private func prepareQR() {
        guard let preparedRecord else { return }
        presentQR(for: preparedRecord)
    }

    private func presentQR(for preparedRecord: Data) {
        let value = TagcryptQRCodec.encode(preparedRecord)
        guard let image = TagcryptQRCodec.image(for: value) else {
            banner = "Could not create the QR image. The prepared encrypted record is still available."
            return
        }
        qrPreviewImage = image
        showQRPreview = true
    }

    private func printQR(_ image: UIImage) {
        let info = UIPrintInfo(dictionary: nil)
        info.outputType = .photo
        info.jobName = "Tagcrypt encrypted QR"
        let controller = UIPrintInteractionController.shared
        controller.printInfo = info
        controller.printingItem = image
        controller.present(animated: true) { _, completed, error in
            if let error { banner = "Could not open print options: \(error.localizedDescription)" }
        }
    }

    private func acceptScannedQR(_ value: String) {
        do {
            let record = try TagcryptQRCodec.decode(value)
            pendingEncryptedRecord = record
            pendingRecordSource = "QR image"
            preparedRecord = nil
            decryptedVault = nil
            showSecret = false
            passphraseConfirmation = ""
            selectedTab = .decrypt
            nfc.setStatus("Encrypted record read from QR. Enter its passphrase and decrypt on this iPhone.")
        } catch {
            banner = "This QR is not a valid Tagcrypt encrypted record. No data was imported."
        }
    }

    private func decryptScannedRecord(using passphraseOverride: String? = nil) async {
        guard let pendingEncryptedRecord else { return }
        let operation = UUID()
        cryptoOperation = operation
        let passphraseToUse = passphraseOverride ?? passphrase
        isCryptoWorking = true
        do {
            let record = pendingEncryptedRecord
            let unlockedVault = try await Task.detached(priority: .userInitiated) {
                if VaultCrypto.requiresFIDOKey(for: record) {
                    return try FIDOEnvelopeCrypto.openWithPassphrase(record, passphrase: passphraseToUse)
                }
                return try VaultCrypto.open(record, passphrase: passphraseToUse)
            }.value
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            decryptedVault = unlockedVault
            self.pendingEncryptedRecord = nil
            preparedRecord = nil
            if passphraseMode == "perTag" && passphrase != generatedPassphraseValue {
                passphrase = ""
                passphraseConfirmation = ""
            } else {
                passphraseConfirmation = passphrase
            }
            showSecret = false
            nfc.setStatus("Decrypted. Tap the eye beside a secret to reveal it; secrets hide automatically after 60 seconds.")
        } catch {
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            banner = error.localizedDescription
            nfc.setStatus("Decryption failed. The scanned record is retained so you can try again.")
        }
    }

    private func decryptScannedRecordWithBoth() async {
        guard let record = pendingEncryptedRecord, !passphrase.isEmpty else { return }
        let operation = UUID()
        cryptoOperation = operation
        isCryptoWorking = true
        do {
            let parameters = try FIDOEnvelopeCrypto.fidoParameters(in: record)
            guard let commonPRFInput = parameters.first?.prfInput,
                  parameters.allSatisfy({ $0.prfInput == commonPRFInput }) else { throw FIDOKeyError.noRegisteredKey }
            let assertion = try await fido.prfOutput(credentialIDs: parameters.map(\.credentialID), input: commonPRFInput,
                                                     requireUserVerification: requireFIDOKeyPIN)
            let phrase = passphrase
            let unlockedVault = try await Task.detached(priority: .userInitiated) {
                try FIDOEnvelopeCrypto.openWithPassphraseAndFIDO(record, passphrase: phrase,
                    credentialID: assertion.credentialID, prfOutput: assertion.output)
            }.value
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            decryptedVault = unlockedVault
            pendingEncryptedRecord = nil
            preparedRecord = nil
            passphraseConfirmation = passphrase
            showSecret = false
            nfc.setStatus("Unlocked with the passphrase and security key. The passphrase remains available as emergency recovery.")
        } catch {
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            banner = error.localizedDescription
            nfc.setStatus("Two-factor unlock failed. The scanned record is retained so you can retry or use passphrase-only emergency recovery.")
        }
    }

    private func decryptScannedRecordWithFIDO(key: RegisteredFIDOKey) async {
        await decryptScannedRecordWithFIDO(credentialID: key.credentialID, displayName: key.displayName)
    }

    private func decryptScannedRecordWithFIDO(credentialID: Data, displayName: String) async {
        guard let record = pendingEncryptedRecord else { return }
        let operation = UUID()
        cryptoOperation = operation
        isCryptoWorking = true
        do {
            let parameters = try FIDOEnvelopeCrypto.fidoParameters(in: record)
            guard parameters.contains(where: { $0.credentialID == credentialID }),
                  let commonPRFInput = parameters.first?.prfInput,
                  parameters.allSatisfy({ $0.prfInput == commonPRFInput }) else { throw FIDOKeyError.noRegisteredKey }
            let assertion = try await fido.prfOutput(credentialIDs: parameters.map(\.credentialID), input: commonPRFInput,
                                                     requireUserVerification: requireFIDOKeyPIN)
            let unlockedVault = try await Task.detached(priority: .userInitiated) {
                try FIDOEnvelopeCrypto.openWithFIDO(record, credentialID: assertion.credentialID, prfOutput: assertion.output)
            }.value
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            decryptedVault = unlockedVault
            pendingEncryptedRecord = nil
            preparedRecord = nil
            passphrase = ""
            passphraseConfirmation = ""
            showSecret = false
            let unlockedCredentialID = assertion.credentialID
            if !fido.registeredKeys.contains(where: { $0.credentialID == unlockedCredentialID }) {
                do {
                    try fido.rememberExistingCredential(credentialID: unlockedCredentialID, displayName: displayName)
                    selectedFIDOKeyIDs.insert(unlockedCredentialID)
                    nfc.setStatus("Unlocked and restored this security key to Settings. You can rename it there.")
                } catch {
                    banner = "Secret unlocked, but Tagcrypt could not save this key profile: \(error.localizedDescription)"
                    nfc.setStatus("Decrypted with the original security key. Keep the passphrase recovery copy available.")
                }
            } else {
                nfc.setStatus("Decrypted with the registered security key. Reveal a secret when ready; clear when finished.")
            }
        } catch {
            guard cryptoOperation == operation, scenePhase != .background else { return }
            isCryptoWorking = false
            banner = error.localizedDescription
            nfc.setStatus("Security-key unlock failed. The encrypted record is retained so you can retry with the key or passphrase.")
        }
    }

    private func registerFIDOKey(named name: String) async {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else { banner = "Enter a name for this security key."; return }
        do {
            try await fido.register(displayName: cleanName)
            if let registered = fido.registeredKeys.last { selectedFIDOKeyIDs.insert(registered.credentialID) }
            nfc.setStatus("\(cleanName) registered with PRF support. Keep an independent passphrase recovery copy.")
        } catch { banner = error.localizedDescription }
        confirmedDifferentPhysicalFIDOKey = false
    }

    @MainActor
    private func saveQRToPhotos(_ image: UIImage) async {
        let current = PHPhotoLibrary.authorizationStatus(for: .addOnly)
        let status: PHAuthorizationStatus
        if current == .notDetermined {
            status = await withCheckedContinuation { continuation in
                PHPhotoLibrary.requestAuthorization(for: .addOnly) { continuation.resume(returning: $0) }
            }
        } else { status = current }
        guard status == .authorized || status == .limited else {
            banner = "Allow Tagcrypt to add photos in iPhone Settings to save this encrypted QR image."
            return
        }
        await withCheckedContinuation { continuation in
            PHPhotoLibrary.shared().performChanges({
                PHAssetChangeRequest.creationRequestForAsset(from: image)
            }) { success, error in
                DispatchQueue.main.async {
                    if success {
                        self.banner = "Encrypted QR saved to Photos."
                    } else {
                        self.banner = "Could not save QR to Photos: \(error?.localizedDescription ?? "Unknown error")"
                    }
                    continuation.resume()
                }
            }
        }
    }

    #if DEBUG
    private var screenshotPreviewMode: String? {
        if let mode = ProcessInfo.processInfo.environment["TAGCRYPT_PREVIEW"] { return mode }
        return ProcessInfo.processInfo.arguments.first(where: { $0.hasPrefix("--tagcrypt-preview=") })
            .map { String($0.dropFirst("--tagcrypt-preview=".count)) }
    }

    private func configureScreenshotPreview() {
        guard let mode = screenshotPreviewMode else { return }
        // Screenshot previews use fake values and must not inherit simulator Keychain alerts.
        banner = nil
        theme.appearance = mode.contains("light") ? .light : .dark
        onboardingAcknowledgedVersion = TagcryptOnboarding.version
        showFirstUseNotice = false
        passphraseMode = "reusable"
        passphrase = "demo-Q7v!Lm2#Zt8w-Rk4p-Xn9s"
        passphraseConfirmation = passphrase
        generatedPassphraseValue = passphrase
        generatedPassphraseIsSaved = false
        customPassphraseAcknowledged = true
        selectedSize = .ntag216
        recordUnlockChoiceRaw = RecordUnlockChoice.passphrase.rawValue
        showPassphrase = false
        showSecret = false
        if mode.contains("multi") {
            secretEntryMode = .slots
            secret = ""
            secretSlots = [
                SecretSlotDraft(title: "Email · sample", secret: "SAMPLE_ONLY_user@example.invalid"),
                SecretSlotDraft(title: "Wi-Fi · sample", secret: "SAMPLE_ONLY_example_network_key"),
            ]
        } else {
            secretEntryMode = .single
            secret = "SAMPLE_ONLY_NOT_A_REAL_CREDENTIAL"
            secretSlots = [SecretSlotDraft(title: "Password 1")]
        }
        if mode.hasPrefix("decrypt") {
            selectedTab = .decrypt
            Task { @MainActor in
                let draft = mode.contains("multi")
                    ? PasswordVault(secret: "", slots: [
                        VaultSecretSlot(title: "Email · sample", secret: "SAMPLE_ONLY_user@example.invalid"),
                        VaultSecretSlot(title: "Wi-Fi · sample", secret: "SAMPLE_ONLY_example_network_key"),
                    ])
                    : PasswordVault(secret: "SAMPLE_ONLY_NOT_A_REAL_CREDENTIAL")
                if let record = try? await Task.detached(priority: .userInitiated, operation: {
                    try VaultCrypto.seal(draft, passphrase: "demo-Q7v!Lm2#Zt8w-Rk4p-Xn9s")
                }).value {
                    pendingEncryptedRecord = record
                    pendingRecordSource = "Sample QR"
                    decryptedVault = draft
                    showSecret = true
                    nfc.setStatus("Demo preview only. No actual credential is present.")
                }
            }
        } else if mode.hasPrefix("settings") {
            showSettings = true
        } else if mode.hasPrefix("qr") {
            selectedTab = .encrypt
            Task { @MainActor in
                if let record = try? await Task.detached(priority: .userInitiated, operation: {
                    try VaultCrypto.seal("SAMPLE_ONLY_NOT_A_REAL_CREDENTIAL", passphrase: "demo-Q7v!Lm2#Zt8w-Rk4p-Xn9s")
                }).value,
                   let image = TagcryptQRCodec.image(for: TagcryptQRCodec.encode(record)) {
                    preparedRecord = record
                    qrPreviewImage = image
                    showQRPreview = true
                }
            }
        } else {
            selectedTab = .encrypt
        }
    }
    #endif
}


private struct MainScrollOffsetKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

/// Plain reference type so per-frame scroll updates do not re-render the view.
private final class ScrollDirectionTracker {
    private var lastOffset: CGFloat?
    private(set) var upwardTravel: CGFloat = 0

    /// Returns the change since the last offset (positive = scrolling up).
    func update(_ offset: CGFloat) -> CGFloat {
        defer { lastOffset = offset }
        guard let lastOffset else { return 0 }
        let delta = offset - lastOffset
        if delta > 0 { upwardTravel += delta } else if delta < 0 { upwardTravel = 0 }
        return delta
    }

    func reset() { lastOffset = nil; upwardTravel = 0 }
}


/// Reads the main scroll offset (0 at top, negative when scrolled down).
/// iOS 18+ uses onScrollGeometryChange; older systems fall back to a preference key.
private struct MainScrollOffsetReader: ViewModifier {
    let onChange: (CGFloat) -> Void
    func body(content: Content) -> some View {
        if #available(iOS 18.0, *) {
            content.onScrollGeometryChange(for: CGFloat.self) { geometry in
                -(geometry.contentOffset.y + geometry.contentInsets.top)
            } action: { _, newValue in
                onChange(newValue)
            }
        } else {
            content.onPreferenceChange(MainScrollOffsetKey.self) { onChange($0) }
        }
    }
}
