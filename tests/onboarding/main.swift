import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

expect(!TagcryptOnboarding.isComplete(acknowledgedVersion: nil), "a fresh install must show onboarding")
expect(!TagcryptOnboarding.isComplete(acknowledgedVersion: "older-version"), "an older acknowledgement must show updated onboarding")
expect(TagcryptOnboarding.isComplete(acknowledgedVersion: TagcryptOnboarding.version), "the current acknowledgement must suppress repeat onboarding")
expect(TagcryptOnboarding.pageCount == 5, "onboarding must omit the per-job record destination page")
expect(TagcryptConfigurationDefaults.wipeUnusedTagPages == false, "unused-page randomization must be off by default")
expect(TagcryptConfigurationDefaults.rawPageModeEnabled == false, "raw-page writing must be off by default")
expect(TagcryptConfigurationDefaults.advancedSettingsEnabled == false, "Basic settings mode must be the default")
expect(TagcryptConfigurationDefaults.requireFIDOKeyPIN == false, "security-key verification must be optional by default")
expect(TagcryptConfigurationDefaults.nfcOverwritePolicyRaw == "warn", "replacing a populated tag must warn by default")
expect(TagcryptAppMetadata.displayVersion(marketingVersion: "1.1", buildNumber: "22") == "1.1.22", "About must use dotted marketing/build version format")
expect(TagcryptAppMetadata.publisherName == "Fish and Media Ltd.", "About must use the official publisher branding")

expect(AdaptiveNDEFCapacityPolicy.maximumPayloadBytes(fitting: 868, messageLength: { $0 + 33 }) == 835,
       "adaptive NDEF preflight must calculate the largest binary payload that fits the tag's live capacity")
expect(AdaptiveNDEFCapacityPolicy.maximumPayloadBytes(fitting: 32, messageLength: { $0 + 33 }) == 0,
       "adaptive NDEF preflight must return zero when even the empty record overhead cannot fit")

var progress = TagcryptOnboardingProgress()
expect(!progress.canFinish, "onboarding cannot finish before the final card")
for _ in 0..<(TagcryptOnboarding.pageCount - 1) {
    expect(progress.advance(), "each Continue action before the final card must advance one page")
}
expect(progress.currentPageIndex == TagcryptOnboarding.pageCount - 1, "Continue actions must reach the final card")
expect(!progress.advance(), "Continue must not move past the final card")
expect(progress.finish() == nil, "reaching the final card without acknowledgement must not complete onboarding")

progress.setFinalAcknowledged(true)
expect(progress.canFinish, "final acknowledgement must enable completion")
expect(progress.finish() == TagcryptOnboarding.version, "completion must return the current version for local persistence")

progress.goBack()
expect(progress.currentPageIndex == TagcryptOnboarding.pageCount - 2, "Back must return to the preceding card")
expect(!progress.canFinish, "moving away from the final card must disable completion")

print("PASS: mandatory onboarding progression and versioned acknowledgement")
