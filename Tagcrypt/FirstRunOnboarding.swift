import Foundation

enum AdaptiveNDEFCapacityPolicy {
    /// Finds the largest encrypted binary record that can be wrapped in an
    /// NDEF message within the capacity reported by the scanned tag.
    static func maximumPayloadBytes(fitting capacity: Int,
                                    messageLength: (Int) -> Int) -> Int {
        guard capacity > 0, messageLength(0) <= capacity else { return 0 }
        var low = 0
        var high = capacity
        while low < high {
            let middle = low + (high - low + 1) / 2
            if messageLength(middle) <= capacity {
                low = middle
            } else {
                high = middle - 1
            }
        }
        return low
    }
}

enum TagcryptOnboarding {
    static let version = "onboarding-2026-10-11-v4"
    static let pageCount = 5

    static func isComplete(acknowledgedVersion: String?) -> Bool {
        acknowledgedVersion == version
    }
}

enum TagcryptConfigurationDefaults {
    static let requireFIDOKeyPIN = false
    static let nfcOverwritePolicyRaw = "warn"
    static let paddedRecordsEnabled = true
    static let wipeUnusedTagPages = false
    static let rawPageModeEnabled = false
    static let tagLockModeRaw = "Off"
    static let advancedSettingsEnabled = false
}

enum TagcryptAppMetadata {
    static let publisherName = "Fish and Media Ltd."

    static func displayVersion(marketingVersion: String, buildNumber: String) -> String {
        "\(marketingVersion).\(buildNumber)"
    }
}

struct TagcryptOnboardingProgress {
    private(set) var currentPageIndex = 0
    private(set) var finalAcknowledged = false

    var isFinalPage: Bool { currentPageIndex == TagcryptOnboarding.pageCount - 1 }
    var canFinish: Bool { isFinalPage && finalAcknowledged }

    @discardableResult
    mutating func advance() -> Bool {
        guard currentPageIndex < TagcryptOnboarding.pageCount - 1 else { return false }
        currentPageIndex += 1
        return true
    }

    mutating func goBack() {
        guard currentPageIndex > 0 else { return }
        currentPageIndex -= 1
    }

    mutating func setFinalAcknowledged(_ acknowledged: Bool) {
        guard isFinalPage else { return }
        finalAcknowledged = acknowledged
    }

    mutating func finish() -> String? {
        guard canFinish else { return nil }
        return TagcryptOnboarding.version
    }
}
