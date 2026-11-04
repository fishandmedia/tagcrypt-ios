import Foundation
import Security
import UserNotifications

enum TagcryptPassphraseAssessment {
    enum Level: Int {
        case weak = 0
        case fair = 1
        case strong = 2
        case veryStrong = 3

        var title: String {
            switch self {
            case .weak: "Weak"
            case .fair: "Fair"
            case .strong: "Strong"
            case .veryStrong: "Very strong"
            }
        }
    }

    struct Result {
        let level: Level
        let meetsMinimum: Bool
        let guidance: String
    }

    // A compact, unambiguous word list. Twelve independent uniform choices
    // provide 84 bits before any user-added changes to the generated phrase.
    private static let memorableWords = [
        "acorn", "amber", "anchor", "apricot", "arch", "artist", "aspen", "atlas",
        "badger", "bamboo", "beacon", "birch", "bison", "blossom", "boulder", "breeze",
        "cabin", "cactus", "canoe", "canvas", "cedar", "cello", "cherry", "cinder",
        "clover", "cobalt", "comet", "coral", "copper", "cricket", "cypress", "daisy",
        "delta", "desert", "dolphin", "drizzle", "eagle", "earth", "ember", "falcon",
        "fern", "fjord", "flannel", "forest", "fossil", "foxglove", "gadget", "galaxy",
        "garden", "ginger", "glacier", "goblet", "granite", "harbor", "hazel", "heron",
        "honey", "hyacinth", "island", "ivory", "jasmine", "juniper", "kettle", "kiwi",
        "lagoon", "lantern", "laurel", "lemon", "linen", "lotus", "maple", "marble",
        "meadow", "mercury", "meteor", "minnow", "mitten", "monarch", "moss", "mountain",
        "nectar", "newt", "nickel", "oasis", "ocean", "olive", "onyx", "orange",
        "otter", "paddle", "panda", "papaya", "pebble", "pepper", "petal", "phoenix",
        "piano", "pine", "planet", "plum", "pocket", "poppy", "quartz", "rabbit",
        "radar", "rainbow", "raven", "reed", "ribbon", "river", "robin", "saffron",
        "sailor", "saturn", "scarlet", "shadow", "silver", "sparrow", "spruce", "starling",
        "sunrise", "teapot", "thistle", "thunder", "timber", "tulip", "valley", "velvet"
    ]

    private static let obviousFragments = [
        "password", "passphrase", "letmein", "qwerty", "asdf", "123456", "12345678",
        "welcome", "tagcrypt", "changeme", "iloveyou", "admin"
    ]

    static func generateMemorablePhrase() throws -> String {
        var words = [String]()
        words.reserveCapacity(12)
        while words.count < 12 {
            var byte: UInt8 = 0
            let status = SecRandomCopyBytes(kSecRandomDefault, 1, &byte)
            guard status == errSecSuccess else { throw VaultError.randomGenerationFailed(status) }
            // 128 divides 256 evenly, so this mapping has no modulo bias.
            words.append(memorableWords[Int(byte & 0x7f)])
        }
        return words.joined(separator: "-")
    }

    static func evaluate(_ input: String) -> Result {
        let phrase = input.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCanonicalMapping
        let folded = phrase.lowercased()
        let words = folded.split(whereSeparator: { $0 == "-" || $0 == " " }).map(String.init)

        if phrase.utf8.count < 16 {
            return Result(level: .weak, meetsMinimum: false, guidance: "Use at least 16 UTF-8 bytes.")
        }
        if obviousFragments.contains(where: folded.contains) || hasObviousSequence(folded) {
            return Result(level: .weak, meetsMinimum: false, guidance: "Avoid common words, repeated characters, and keyboard or number sequences.")
        }

        if words.count == 12, words.allSatisfy({ memorableWords.contains($0) }) {
            return Result(level: .strong, meetsMinimum: true, guidance: "Twelve uniformly random choices from this 128-word list provide 84 bits; hand-picked words may be much less predictable. Keep generated words in order.")
        }

        let alphabetSize = estimatedAlphabetSize(phrase)
        let estimatedBits = Double(phrase.count) * log2(Double(alphabetSize))
        let level: Level
        switch estimatedBits {
        case ..<80: level = .fair
        case 80..<112: level = .strong
        default: level = .veryStrong
        }
        return Result(
            level: level,
            meetsMinimum: estimatedBits >= 80,
            guidance: "Rough estimate based on length and character variety; it cannot measure how predictable a phrase is."
        )
    }

    private static func estimatedAlphabetSize(_ value: String) -> Int {
        var size = 0
        if value.contains(where: { $0.isLowercase }) { size += 26 }
        if value.contains(where: { $0.isUppercase }) { size += 26 }
        if value.contains(where: { $0.isNumber }) { size += 10 }
        if value.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { size += 32 }
        return max(size, 1)
    }

    private static func hasObviousSequence(_ value: String) -> Bool {
        let scalars = Array(value.unicodeScalars.map(\.value))
        guard scalars.count >= 4 else { return false }
        var run = 1
        for index in 1..<scalars.count {
            let previous = scalars[index - 1]
            let current = scalars[index]
            if current == previous || current == previous + 1 || current + 1 == previous {
                run += 1
                if run >= 4 { return true }
            } else {
                run = 1
            }
        }
        return false
    }
}

enum TagcryptHealthReminder {
    static let notificationID = "tagcrypt.tag-health-check"
    static let interval: TimeInterval = 90 * 24 * 60 * 60

    static func enable() async -> Bool {
        let center = UNUserNotificationCenter.current()
        do {
            let allowed = try await center.requestAuthorization(options: [.alert, .sound])
            guard allowed else { return false }
            let content = UNMutableNotificationContent()
            content.title = "Check your Tagcrypt backup"
            content.body = "Read and verify a saved tag or QR copy. Keep a second recovery copy somewhere separate."
            content.sound = .default
            let trigger = UNTimeIntervalNotificationTrigger(timeInterval: interval, repeats: true)
            let request = UNNotificationRequest(identifier: notificationID, content: content, trigger: trigger)
            try await center.add(request)
            return true
        } catch {
            return false
        }
    }

    static func disable() {
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [notificationID])
    }
}

enum TagcryptSupportedTag: String, CaseIterable, Identifiable {
    case ntag213 = "NTAG213"
    case ntag215 = "NTAG215"
    case ntag216 = "NTAG216"

    var id: String { rawValue }
    var userBytes: Int {
        switch self {
        case .ntag213: 144
        case .ntag215: 504
        case .ntag216: 888
        }
    }

    var summary: String { "\(userBytes) bytes user memory · NFC Forum Type 2 · unprotected by default" }
}
