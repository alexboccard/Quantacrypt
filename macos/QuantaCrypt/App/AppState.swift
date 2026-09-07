import AppKit
import os
import Observation

enum AppSection: String, CaseIterable, Identifiable, Hashable {
    case encrypt, decrypt, volumes

    var id: String { rawValue }

    var title: String {
        switch self {
        case .encrypt: return "Encrypt"
        case .decrypt: return "Decrypt"
        case .volumes: return "Volumes"
        }
    }

    var systemImage: String {
        switch self {
        case .encrypt: return "lock"
        case .decrypt: return "lock.open"
        case .volumes: return "externaldrive"
        }
    }
}

enum HelperStatus: Equatable {
    case starting
    case ready(VersionInfo)
    case failed(CoreError)
}

/// Everything the window, the menu bar and the delegate share.
@MainActor
@Observable
final class AppState {
    let core: CoreClient
    let recents: RecentStore
    let encrypt: EncryptModel
    let decrypt: DecryptModel
    let volumes: VolumesModel

    var section: AppSection? = .encrypt
    var helperStatus: HelperStatus = .starting
    /// Set when the app bundle — helper included — no longer verifies
    /// against its own signature. Shown, never enforced: see
    /// `HelperLocator.bundleIntegrityWarning`.
    var integrityWarning: String?

    static let readmeURL = URL(string: "https://github.com/alexboccard/QuantaCrypt#readme")!

    init(core: CoreClient = .live(), recents: RecentStore = RecentStore()) {
        self.core = core
        self.recents = recents
        self.encrypt = EncryptModel(core: core)
        self.decrypt = DecryptModel(core: core, recents: recents)
        self.volumes = VolumesModel(core: core, recents: recents)
        // "Check it opens" ends in Decrypt; the shares it proves are still
        // sitting in Encrypt.
        decrypt.onVerified = { [weak self] path in self?.encrypt.forgetShares(for: path) }
    }

    /// Launch the helper and read its version for the status item.
    func start() {
        checkBundleIntegrity()
        Task {
            // Without this the status item keeps showing "ready" after the
            // helper has died — the one condition it exists to report.
            await core.onUnexpectedExit { [weak self] in
                Task { @MainActor in self?.helperStatus = .failed(.helperExited) }
            }
            await refreshHelperStatus()
        }
    }

    /// Validate the whole bundle off the main thread — it hashes the app
    /// and the helper's payload — and surface a failure without blocking
    /// anything.
    func checkBundleIntegrity() {
        Task {
            let warning = await Task.detached(priority: .utility) {
                HelperLocator.bundleIntegrityWarning()
            }.value
            if let warning {
                Logger.client.error("bundle integrity check failed: \(warning, privacy: .public)")
            }
            integrityWarning = warning
        }
    }

    static let versionTimeout: Duration = .seconds(20)
    static let versionTimedOut = CoreError(
        code: .helperUnavailable,
        message: "The encryption helper didn't answer. Try again. If it keeps happening, set its location in Settings or reinstall QuantaCrypt.",
        detail: "version handshake timed out after 20s")

    func refreshHelperStatus() async {
        helperStatus = .starting
        let core = self.core
        do {
            // This is the first thing the app does, and the status item only
            // offers "Try again" once the status is `.failed` — so a helper
            // that launches and never answers used to leave the window on
            // "Starting…" forever, with no way out.
            let info: VersionInfo = try await withTimeout(Self.versionTimeout) {
                try await core.perform(.version)
            }
            helperStatus = .ready(info)
            Logger.client.info("helper ready: qc-core \(info.version, privacy: .public)")
        } catch let error as CoreError {
            helperStatus = .failed(error)
        } catch is TimeoutError {
            helperStatus = .failed(Self.versionTimedOut)
        } catch {
            helperStatus = .failed(CoreError(code: .helperUnavailable, message: error.localizedDescription, detail: ""))
        }
    }

    func restartHelper() {
        Task {
            await core.restart(mountedVolumes: volumes.mounted.count)
            await refreshHelperStatus()
        }
    }

    // MARK: Routing

    func open(_ urls: [URL]) {
        for url in urls { open(url) }
    }

    /// Route a document to its section. The sidebar only switches when the
    /// model actually took the file; a model busy with a job keeps the
    /// current section and explains inline (in its own section, where the
    /// running job and its Cancel button are) — see `openNote` for the
    /// copy shown wherever the user currently is.
    func open(_ url: URL) {
        let target: AppSection
        let accepted: Bool
        switch url.pathExtension.lowercased() {
        case "qcx":
            target = .decrypt
            accepted = decrypt.load(path: url.path)
        case "qcv":
            target = .volumes
            accepted = volumes.prepareMount(path: url.path)
        default:
            target = .encrypt
            accepted = encrypt.setSource(url.path)
        }
        if accepted {
            section = target
            openNote = nil
        } else {
            openNote = OpenNote(text: EncryptModel.busyMessage(for: url.path), section: target, url: url)
        }
    }

    /// Shown in the window's status bar when an open was refused, so the
    /// message is visible even when the busy section is not the current one.
    /// The URL is kept so the document is offered again once the job that
    /// blocked it finishes, instead of being silently dropped.
    struct OpenNote: Equatable {
        let text: String
        let section: AppSection
        let url: URL
    }
    var openNote: OpenNote?

    /// Whether the section that refused a document is still working. Drives
    /// the note's two shapes: "wait" while busy, "open it now" once idle.
    func isBusy(_ section: AppSection) -> Bool {
        switch section {
        case .encrypt: return encrypt.isRunning
        case .decrypt: return decrypt.isRunning
        case .volumes: return volumes.createRunning || volumes.mountRunning
        }
    }

    // MARK: Quitting

    /// Something that must be settled before the app may exit. Discovered in
    /// `applicationShouldTerminate`, which otherwise takes the shares — the
    /// only copy of a split key — down with the process.
    enum QuitBlocker: Equatable {
        case unsavedShares(String)
        case runningJob

        var messageText: String {
            switch self {
            case .unsavedShares: return "Save the shares first"
            case .runningJob: return "A job is still running"
            }
        }

        var informativeText: String {
            switch self {
            case .unsavedShares(let name):
                return "Without them, \(name) can never be opened again. Quitting now discards them."
            case .runningJob:
                return "Quitting cancels it. Nothing partial is left behind, but the work is lost."
            }
        }

        var quitTitle: String {
            switch self {
            case .unsavedShares: return "Quit and discard shares"
            case .runningJob: return "Quit and cancel"
            }
        }
    }

    var quitBlocker: QuitBlocker? {
        if encrypt.sharesToShow != nil, !encrypt.sharesSaved {
            return .unsavedShares(encrypt.sharesToShow?.context.protectedName ?? "the file")
        }
        if volumes.sharesToShow != nil, !volumes.sharesSaved {
            return .unsavedShares(volumes.sharesToShow?.context.protectedName ?? "the volume")
        }
        if AppSection.allCases.contains(where: isBusy) { return .runningJob }
        return nil
    }

    // MARK: Menu commands

    func openDocument() {
        guard let url = Panels.chooseFile(types: [.qcx, .qcv], message: "Choose an encrypted file or volume.") else { return }
        open(url)
    }

    func encryptFile() {
        section = .encrypt
        encrypt.chooseSource()
    }

    func decryptFile() {
        section = .decrypt
        decrypt.chooseFile()
    }

    func mountVolume() {
        section = .volumes
        volumes.chooseVolumeToMount()
    }

    /// "Check it opens" on the encrypt result: load the new `.qcx` into
    /// Decrypt, where Verify only proves the credential without writing
    /// anything. Closing the loop on the encrypt journey while the password
    /// is still in the user's head.
    func verifyEncrypted(_ path: String) {
        guard decrypt.load(path: path) else {
            openNote = OpenNote(text: EncryptModel.busyMessage(for: path),
                                section: .decrypt, url: URL(fileURLWithPath: path))
            return
        }
        section = .decrypt
        decrypt.verifyPrompt = true
    }
}
