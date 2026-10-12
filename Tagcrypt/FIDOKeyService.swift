import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

struct RegisteredFIDOKey: Codable, Equatable {
    var credentialID: Data
    var displayName: String
    var relyingPartyID: String
}

enum FIDOKeyError: LocalizedError {
    case unavailable
    case prfUnsupported
    case missingPRFOutput
    case noRegisteredKey
    case alreadyRegistered
    case duplicateName
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "Security-key PRF requires iOS 26.4 or later and a supported FIDO2 security key."
        case .prfUnsupported:
            return "This security key did not confirm PRF support. It was not registered for Tagcrypt encryption."
        case .missingPRFOutput:
            return "The security key did not return the requested PRF output. No record was unlocked or written."
        case .noRegisteredKey:
            return "Register a supported security key in Settings before enabling security-key unlock."
        case .alreadyRegistered:
            return "That security key is already registered on this device."
        case .duplicateName:
            return "A security key with that name is already registered. Use a different name only for a genuinely separate physical key."
        case .keychain(let status):
            return "The registered security-key profile could not be saved or loaded (Keychain status \(status))."
        }
    }
}

/// Uses Apple's roaming WebAuthn security-key API only for its WebAuthn PRF
/// output. A successful WebAuthn assertion is not treated as a login or as a
/// substitute for validating the PRF result. The record keeps its own credential ID.
@MainActor
final class FIDOKeyManager: NSObject, ObservableObject {
    /// Security-key credentials are bound to this relying-party ID: changing it
    /// after release makes every registered key and FIDO record unusable.
    /// Chosen before the first public release (2026-10-11): tagcrypt.com must
    /// serve /.well-known/apple-app-site-association (webcredentials) directly.
    static let relyingPartyID = "tagcrypt.com"
    @Published private(set) var registeredKeys: [RegisteredFIDOKey] = []

    private static let service = "com.fishandmedia.tagcrypt.fido"
    private static let account = "registered-roaming-keys-v2"
    private static let legacyAccount = "registered-roaming-key-v1"
    private var controller: ASAuthorizationController?
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    func restore() throws {
        // Keep the current in-memory profiles if Keychain access or decoding
        // fails. Treating an error as an empty list can make a key look deleted.
        let restoredProfiles = try Self.loadProfiles()
        // Keys registered for an earlier relying-party ID (pre-release builds)
        // cannot unlock anything under the current one, so they are hidden.
        registeredKeys = restoredProfiles.filter { $0.relyingPartyID == Self.relyingPartyID }
    }

    func register(displayName: String) async throws {
        guard #available(iOS 26.4, *) else { throw FIDOKeyError.unavailable }
        let normalizedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
        guard !registeredKeys.contains(where: {
            $0.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
                .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current) == normalizedName
        }) else { throw FIDOKeyError.duplicateName }
        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: Self.relyingPartyID)
        let challenge = try Self.randomData(count: 32)
        let userID = try Self.randomData(count: 32)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: displayName,
            name: displayName,
            userID: userID
        )
        // External security-key registration requires an explicit public-key
        // algorithm list. ES256 (COSE -7) is the interoperable P-256 choice.
        request.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)
        ]
        let supportCheck = ASAuthorizationPublicKeyCredentialPRFRegistrationInput.InputValues(
            saltInput1: try Self.randomData(count: 32)
        )
        request.prf = .inputValues(supportCheck)
        request.userVerificationPreference = .preferred
        // Tagcrypt keeps the credential ID itself; a discoverable (resident)
        // credential would store the display name and user handle on the key
        // and use one of its limited slots for no benefit.
        request.residentKeyPreference = .discouraged
        let authorization = try await perform(request)
        guard let registration = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration,
              registration.prf?.isSupported == true else { throw FIDOKeyError.prfUnsupported }
        let profile = RegisteredFIDOKey(
            credentialID: registration.credentialID,
            displayName: displayName,
            relyingPartyID: Self.relyingPartyID
        )
        guard !registeredKeys.contains(where: { $0.credentialID == profile.credentialID }) else {
            throw FIDOKeyError.alreadyRegistered
        }
        try Self.saveProfiles(registeredKeys + [profile])
        registeredKeys.append(profile)
    }

    func rename(_ key: RegisteredFIDOKey, to name: String) throws {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else { return }
        // Reload from Keychain before editing. The Settings row can outlive a
        // stale/incomplete in-memory manager snapshot; do not turn that into a
        // false "not registered" error or overwrite other saved profiles.
        var updated = try Self.loadProfiles()
        if let index = updated.firstIndex(where: { $0.credentialID == key.credentialID }) {
            updated[index].displayName = cleanName
        } else {
            var restoredProfile = key
            restoredProfile.displayName = cleanName
            updated.append(restoredProfile)
        }
        try Self.saveProfiles(updated)
        registeredKeys = updated
    }

    /// Rebuilds the local display profile from a credential ID embedded in a
    /// record only after an assertion has proved possession of that credential.
    func rememberExistingCredential(credentialID: Data, displayName: String) throws {
        guard !credentialID.isEmpty, credentialID.count <= 255,
              !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw FIDOKeyError.noRegisteredKey
        }
        if registeredKeys.contains(where: { $0.credentialID == credentialID }) { return }
        let profile = RegisteredFIDOKey(
            credentialID: credentialID,
            displayName: displayName.trimmingCharacters(in: .whitespacesAndNewlines),
            relyingPartyID: Self.relyingPartyID
        )
        let updated = registeredKeys + [profile]
        try Self.saveProfiles(updated)
        registeredKeys = updated
    }

    func removeRegisteredKey(_ key: RegisteredFIDOKey) throws {
        let updated = registeredKeys.filter { $0.credentialID != key.credentialID }
        guard updated.count != registeredKeys.count else { throw FIDOKeyError.noRegisteredKey }
        try Self.saveProfiles(updated)
        registeredKeys = updated
    }

    func prfOutput(credentialID: Data? = nil, input: Data, requireUserVerification: Bool = false) async throws -> Data {
        let keyID = try credentialID ?? registeredKeys.first?.credentialID ?? { throw FIDOKeyError.noRegisteredKey }()
        let result = try await prfOutput(credentialIDs: [keyID], input: input, requireUserVerification: requireUserVerification)
        return result.output
    }

    func prfOutput(credentialIDs: [Data], input: Data, requireUserVerification: Bool = false) async throws -> (credentialID: Data, output: Data) {
        guard #available(iOS 26.4, *) else { throw FIDOKeyError.unavailable }
        guard !credentialIDs.isEmpty, credentialIDs.count <= 3,
              credentialIDs.allSatisfy({ !$0.isEmpty && $0.count <= 255 }) else { throw FIDOKeyError.noRegisteredKey }
        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: Self.relyingPartyID)
        let challenge = try Self.randomData(count: 32)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        request.allowedCredentials = credentialIDs.map {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: [.nfc, .usb])
        }
        request.prf = .inputValues(.init(saltInput1: input))
        request.userVerificationPreference = requireUserVerification ? .required : .preferred
        let authorization = try await perform(request)
        guard let assertion = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion,
              credentialIDs.contains(assertion.credentialID), let prfKey = assertion.prf?.first else {
            throw FIDOKeyError.missingPRFOutput
        }
        return (assertion.credentialID, prfKey.withUnsafeBytes { Data($0) })
    }

    private func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    private static func loadProfiles() throws -> [RegisteredFIDOKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            // Migrate the earlier single-key Keychain item without losing its credential.
            guard let legacy = try loadLegacyProfile() else { return [] }
            try saveProfiles([legacy])
            return [legacy]
        }
        guard status == errSecSuccess, let data = result as? Data,
              let profiles = try? JSONDecoder().decode([RegisteredFIDOKey].self, from: data) else {
            throw FIDOKeyError.keychain(status)
        }
        return profiles
    }

    private static func loadLegacyProfile() throws -> RegisteredFIDOKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: legacyAccount,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let profile = try? JSONDecoder().decode(RegisteredFIDOKey.self, from: data) else {
            throw FIDOKeyError.keychain(status)
        }
        return profile
    }

    private static func saveProfiles(_ profiles: [RegisteredFIDOKey]) throws {
        let data = try JSONEncoder().encode(profiles)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let updates: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw FIDOKeyError.keychain(addStatus) }
        } else if status != errSecSuccess {
            throw FIDOKeyError.keychain(status)
        }
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw VaultError.randomGenerationFailed(status) }
        return data
    }
}

extension FIDOKeyManager: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization)
        continuation = nil
        self.controller = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
        self.controller = nil
    }
}

/// Requests a password through Apple's system Password AutoFill picker.
/// iOS does not let an app launch the Passwords app and search arbitrary items;
/// this returns a credential the user selects from the system's available list.
@MainActor
final class ApplePasswordsPicker: NSObject, ObservableObject,
    ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var controller: ASAuthorizationController?
    private var continuation: CheckedContinuation<String, Error>?

    func choosePassword() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let request = ASAuthorizationPasswordProvider().createRequest()
            let controller = ASAuthorizationController(authorizationRequests: [request])
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASPasswordCredential else {
            continuation?.resume(throwing: FIDOKeyError.noRegisteredKey)
            continuation = nil
            self.controller = nil
            return
        }
        continuation?.resume(returning: credential.password)
        continuation = nil
        self.controller = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
        self.controller = nil
    }
}
