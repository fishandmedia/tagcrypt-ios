import SwiftUI
import UIKit

final class TagcryptAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}

@main
struct TagcryptApp: App {
    @UIApplicationDelegateAdaptor(TagcryptAppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
