import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let state = AppState()

    private static var isRunningTests: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
            || NSClassFromString("XCTestCase") != nil
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard !Self.isRunningTests else { return }
        state.start()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        state.open(urls)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // The shares sheet guards Escape and its own Close button, but ⌘Q
        // used to walk straight past both and take the only copy of a split
        // key with it.
        if let blocker = state.quitBlocker, !Self.confirmQuit(blocker) {
            return .terminateCancel
        }
        let core = state.core
        // The Volumes screen's last poll: what the helper has to unmount, and
        // so how long its answer may take. Stale on the high side is fine.
        let mounted = state.volumes.mounted.count
        Task {
            // The helper cancels work and unmounts every volume before it
            // answers; its answer names any mount point it could not release.
            let outcome = await core.shutdown(mountedVolumes: mounted)
            if !outcome.unmountFailed.isEmpty {
                Self.showUnmountFailures(outcome.unmountFailed)
            }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// Modal because quitting is about to destroy something the user cannot
    /// get back. Returns true when they chose to go ahead anyway.
    private static func confirmQuit(_ blocker: AppState.QuitBlocker) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = blocker.messageText
        alert.informativeText = blocker.informativeText
        alert.addButton(withTitle: "Keep working")
        alert.addButton(withTitle: blocker.quitTitle)
        // Escape and ⌘. land on "Keep working"; the destructive choice needs
        // a deliberate click.
        alert.buttons.last?.hasDestructiveAction = true
        return alert.runModal() == .alertSecondButtonReturn
    }

    /// Modal because the app is about to exit: this is the user's only
    /// chance to learn that a volume is still mounted.
    private static func showUnmountFailures(_ mountPoints: [String]) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = mountPoints.count == 1
            ? "A volume could not be unmounted"
            : "Some volumes could not be unmounted"
        let list = mountPoints.map { "• " + (($0 as NSString).abbreviatingWithTildeInPath) }.joined(separator: "\n")
        alert.informativeText = "Something is still using:\n\(list)\n\nClose the files or Finder windows using them, then eject the volume in Finder. Unsaved changes there may be lost."
        alert.addButton(withTitle: "Quit")
        alert.runModal()
    }
}
