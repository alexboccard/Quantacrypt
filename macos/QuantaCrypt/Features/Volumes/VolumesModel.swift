import Foundation
import os
import Observation

@MainActor
@Observable
final class VolumesModel {
    enum MountCredential: String, CaseIterable, Identifiable {
        case password = "Password"
        case shares = "Split key"
        var id: String { rawValue }
    }

    static let brewCommand = "brew install --cask fuse-t"
    static let brewAlternative = "brew install --cask macfuse"
    static let mountRoot = (Paths.homeDirectory as NSString).appendingPathComponent("QuantaCrypt Volumes")

    /// The protocol says these ops are short and never cancel, so a client
    /// must fail them locally after a grace period
    /// (docs/design/core-service-protocol.md). Without a bound, a helper that
    /// launches and never answers leaves a spinner up with nothing to click.
    static let inspectTimeout: Duration = .seconds(20)
    static let checkTimeout: Duration = .seconds(10)

    static func timedOut(_ what: String, after seconds: Int) -> CoreError {
        CoreError(code: .helperUnavailable,
                  message: "The encryption helper didn't answer. Try again. If it keeps happening, restart the helper in Settings.",
                  detail: "\(what) timed out after \(seconds)s")
    }

    private let core: CoreClient
    private let recents: RecentStore

    // FUSE gate
    var fuse: FuseCheck?
    var fuseChecking = false
    var fuseCheckNote: String?
    var fuseError: CoreError?

    // Create
    var createName = ""
    var createDirectory = (Paths.homeDirectory as NSString).appendingPathComponent("Documents")
    var createMode: ProtectionMode = .password
    var createPassword = ""
    var createConfirmation = ""
    var createThreshold = 2
    var createTotal = 3
    var createProgress: CoreProgress?
    var createRunning = false
    var createCancelling = false
    var createError: CoreError?
    var createStatus: String?
    var createResult: VolumeCreateResult?
    var sharesToShow: SharesPresentation? {
        didSet { if sharesToShow != nil { sharesSaved = false } }
    }
    /// Whether the shares on screen have been written somewhere durable.
    /// Read by the quit guard — the sheet's own state dies with the sheet.
    var sharesSaved = false
    var offerMountAfterCreate = false

    // Mount
    var mountPath: String?
    var mountInfo: VolumeInspectInfo?
    var mountInspecting = false
    /// Why the auth block could not be read; the credential picker then
    /// stands in for it.
    var mountInspectError: CoreError?
    var mountPoint = ""
    /// The volume `mountPoint` was chosen for. The choice used to be a flag
    /// that stuck to every later volume, so opening B after choosing a
    /// folder for A landed on A's folder — "already mounted" while A was
    /// up, "not empty" once Finder had written to it.
    private var mountPointChosenFor: String?
    var mountCredential: MountCredential = .password
    var mountPassword = ""
    var mountShares: [ShareEntry] = [ShareEntry(), ShareEntry()]
    var mountProgress: CoreProgress?
    var mountRunning = false
    var mountCancelling = false
    var mountError: CoreError?
    var mountStatus: String?
    var mountedNote: String?
    /// Whether the volume `mountedNote` names came up read-only. The note's
    /// "drag files in" hint is wrong for a drive that refuses every write.
    var mountedReadOnly = false
    /// A mount whose journal tail failed to verify, and the sidecar the
    /// helper saved that tail to (nil from an older helper).
    struct SuspiciousMount: Equatable {
        let volume: MountedVolume
        let suspectSidecar: String?
    }
    var suspiciousMount: SuspiciousMount?

    // Mounted list
    var mounted: [MountedVolume] = []
    var listLoaded = false
    /// Consecutive `volume_list` failures. The list is a poll, so one miss is
    /// noise; a run of them means what is on screen is fiction.
    private var listFailures = 0
    var listIsStale: Bool { listFailures >= 2 }
    /// Mount points this app opened read-only, from the `volume_mount`
    /// results it saw. Only a fallback: an entry that `volume_list` reports
    /// `read_only` for takes the helper's word, and that word replaces what
    /// the set said for the point. Without that, a mount whose result never
    /// reached `finishMount` (cancelled while the helper finished anyway,
    /// or given up on locally) left the set wrong for as long as the next
    /// drive at that point stayed mounted. It is what the row shows only
    /// when a helper older than the key lists the drive, since every poll
    /// replaces `mounted` wholesale. Never pruned by a poll: a list snapshot
    /// taken mid-mount would drop the point the result is about to add.
    private var readOnlyMountPoints: Set<String> = []
    var unmountCandidate: MountedVolume?
    var unmounting: Set<String> = []
    var unmountError: CoreError?

    private var createTask: Task<Void, Never>?
    private var mountTask: Task<Void, Never>?

    init(core: CoreClient, recents: RecentStore) {
        self.core = core
        self.recents = recents
    }

    // MARK: FUSE

    enum MountSupport: Equatable { case unknown, missing, ready }

    /// `fuse == nil` is "not checked yet", not "not installed" — sending the
    /// user to Homebrew because a check is still in flight, or because the
    /// helper is down, wastes their time on the wrong problem.
    var mountSupport: MountSupport {
        guard let fuse else { return .unknown }
        return fuse.ok ? .ready : .missing
    }

    var mountingAvailable: Bool { mountSupport == .ready }

    func checkFuse(userInitiated: Bool = false) async {
        fuseChecking = true
        let before = fuse
        let core = self.core
        do {
            let check: FuseCheck = try await withTimeout(Self.checkTimeout) {
                try await core.perform(.fuseCheck)
            }
            fuse = check
            fuseError = nil
            if userInitiated {
                fuseCheckNote = check.ok
                    ? "Disk mounting is ready."
                    : (before == check ? "Checked just now. Still missing: \(check.missingSummary)."
                                       : "Still missing: \(check.missingSummary).")
            }
        } catch let error as CoreError {
            fuseError = error
        } catch is TimeoutError {
            fuseError = Self.timedOut("fuse_check", after: 10)
        } catch {
            fuseError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
        }
        fuseChecking = false
    }

    // MARK: Create

    var createPath: String {
        let name = createName.trimmingCharacters(in: .whitespacesAndNewlines)
        let file = name.lowercased().hasSuffix(".qcv") ? name : name + ".qcv"
        return (createDirectory as NSString).appendingPathComponent(file)
    }

    func chooseCreateLocation() {
        let name = createName.isEmpty ? "Vault" : createName
        guard let url = Panels.save(suggestedName: name.lowercased().hasSuffix(".qcv") ? name : name + ".qcv",
                                    type: .qcv, message: "Choose a name and location for the new volume.",
                                    directory: URL(fileURLWithPath: createDirectory)) else { return }
        createName = url.deletingPathExtension().lastPathComponent
        createDirectory = url.deletingLastPathComponent().path
    }

    var createValidationMessage: String? {
        if mountRunning { return "Wait for the volume that is opening to finish." }
        let name = createName.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { return "Give the volume a name." }
        if name.contains("/") { return "The name can't contain a slash." }
        if Paths.exists(createPath) { return "\(Format.fileName(createPath)) already exists. Choose another name or location." }
        switch createMode {
        case .password:
            if createPassword.isEmpty { return "Enter a password." }
            if createPassword.count < PasswordStrength.minimumLength {
                return "Use at least \(PasswordStrength.minimumLength) characters."
            }
            if createPassword != createConfirmation { return "The two passwords don't match." }
        case .splitKey:
            if !(2...20).contains(createThreshold) || !(2...20).contains(createTotal) || createThreshold > createTotal {
                return "Enter numbers between 2 and 20, with Required to unlock no larger than Total people."
            }
        }
        return nil
    }

    var canCreate: Bool { !createRunning && createValidationMessage == nil }

    func createVolume() {
        guard canCreate else { return }
        let path = createPath
        let credential: CoreRequest.Credential = createMode == .password
            ? .password(createPassword)
            : .splitKey(k: createThreshold, n: createTotal)
        createRunning = true
        createCancelling = false
        createProgress = nil
        createError = nil
        createStatus = nil
        createResult = nil
        createTask = Task { [core] in
            do {
                let result: VolumeCreateResult = try await core.perform(
                    .volumeCreate(path: path, credential: credential)
                ) { p in
                    Task { @MainActor [weak self] in self?.createProgress = p }
                }
                finishCreate(result)
            } catch let error as CoreError {
                createRunning = false
                createCancelling = false
                createProgress = nil
                if error.isCancellation { createStatus = error.message } else { createError = error }
            } catch {
                createRunning = false
                createCancelling = false
                createProgress = nil
                createError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    private func finishCreate(_ result: VolumeCreateResult) {
        createRunning = false
        createCancelling = false
        createProgress = nil
        createResult = result
        createPassword = ""
        createConfirmation = ""
        if !result.shares.isEmpty, let k = result.threshold, let n = result.total {
            sharesToShow = SharesPresentation(
                shares: result.shares,
                context: ShareFiles.Context(stem: Format.stem(result.path),
                                            protectedName: Format.fileName(result.path), k: k, n: n, kind: .qcvVolume))
        } else {
            offerMountAfterCreate = true
        }
    }

    func sharesSheetDismissed() {
        if createResult != nil { offerMountAfterCreate = true }
    }

    func cancelCreate() {
        guard createRunning else { return }
        createCancelling = true
        createTask?.cancel()
    }

    /// Second chance at the shares of a volume that has already been created
    /// — without it, one click on "Discard shares" seals the volume forever.
    func showSharesAgain() {
        guard let result = createResult, !result.shares.isEmpty,
              let k = result.threshold, let n = result.total else { return }
        sharesToShow = SharesPresentation(
            shares: result.shares,
            context: ShareFiles.Context(stem: Format.stem(result.path),
                                        protectedName: Format.fileName(result.path),
                                        k: k, n: n, kind: .qcvVolume))
    }

    var canShowSharesAgain: Bool {
        guard let result = createResult else { return false }
        return !result.shares.isEmpty && result.threshold != nil && result.total != nil
    }

    func mountCreatedVolume() {
        guard let result = createResult else { return }
        prepareMount(path: result.path)
        mountCredential = result.mode == "shamir" ? .shares : .password
    }

    // MARK: Mount

    static func defaultMountPoint(for volumePath: String) -> String {
        (mountRoot as NSString).appendingPathComponent(Format.stem(volumePath))
    }

    func chooseVolumeToMount() {
        guard let url = Panels.chooseFile(types: [.qcv], message: "Choose a volume to mount.") else { return }
        prepareMount(path: url.path)
    }

    static func accepts(_ url: URL) -> Bool {
        url.pathExtension.lowercased() == "qcv"
    }

    /// Select `path` for mounting. Returns false — with the reason in
    /// `mountStatus` — while a mount is running.
    @discardableResult
    func prepareMount(path: String) -> Bool {
        guard !mountRunning else {
            mountStatus = EncryptModel.busyMessage(for: path)
            return false
        }
        mountPath = path
        mountError = nil
        mountStatus = nil
        mountedNote = nil
        mountedReadOnly = false
        if mountPointChosenFor != path {
            mountPointChosenFor = nil
            mountPoint = Self.defaultMountPoint(for: path)
        }
        mountInfo = nil
        mountInspectError = nil
        mountInspecting = true
        // Read the auth block so the right credential entry appears without
        // asking the user how the volume is protected. When that fails the
        // reason is shown and the "Unlock with" picker takes over.
        Task { [core] in
            defer { if mountPath == path { mountInspecting = false } }
            do {
                let info: VolumeInspectInfo = try await withTimeout(Self.inspectTimeout) {
                    try await core.perform(.volumeInspect(path: path))
                }
                guard mountPath == path else { return }
                mountInfo = info
                mountCredential = info.isSplitKey ? .shares : .password
                let needed = info.threshold ?? 2
                if info.isSplitKey, mountShares.count < needed {
                    mountShares = (0..<needed).map { _ in ShareEntry() }
                }
            } catch let error as CoreError {
                guard mountPath == path else { return }
                mountInspectError = Self.inspectFailure(error)
            } catch is TimeoutError {
                guard mountPath == path else { return }
                mountInspectError = Self.timedOut("volume_inspect", after: 20)
            } catch {
                guard mountPath == path else { return }
                mountInspectError = Self.inspectFailure(
                    CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)"))
            }
        }
        return true
    }

    /// Re-run the inspection for the volume already on screen. A failed
    /// inspect otherwise stands until the user picks the file again.
    func retryInspect() {
        guard let path = mountPath else { return }
        // prepareMount keeps the mount point the user chose; re-selecting the
        // same path is the whole retry.
        prepareMount(path: path)
    }

    static func inspectFailure(_ error: CoreError) -> CoreError {
        CoreError(code: error.code, message: "Couldn't read this volume: \(error.message)", detail: error.detail)
    }

    func chooseMountPoint() {
        guard let url = Panels.chooseFolder(message: "Choose an empty folder to mount the volume at.",
                                            prompt: "Mount Here",
                                            directory: URL(fileURLWithPath: Self.mountRoot)) else { return }
        useMountPoint(url.path)
    }

    /// Record `path` as the mount point for the volume on screen; the next
    /// volume gets the default again.
    func useMountPoint(_ path: String) {
        mountPoint = path
        mountPointChosenFor = mountPath
    }

    func loadMountSharesFromFiles() {
        let urls = Panels.chooseFiles(types: ShareFiles.fileTypes, message: "Choose one or more share files.")
        guard !urls.isEmpty else { return }
        let (loaded, problems) = ShareFiles.load(urls)
        guard !loaded.isEmpty else {
            mountStatus = problems.first ?? "No shares were found in \(urls.count == 1 ? "that file" : "those files")."
            return
        }
        mountShares = ShareValidation.merge(loaded, into: mountShares,
                                            threshold: mountInfo?.threshold ?? 2, total: mountInfo?.total)
        mountStatus = problems.first
    }

    var mountValidationMessage: String? {
        if createRunning { return "Wait for the volume being created to finish." }
        guard mountPath != nil else { return "Choose a volume file." }
        if mountPoint.trimmingCharacters(in: .whitespaces).isEmpty { return "Choose where to mount it." }
        switch mountCredential {
        case .password:
            if mountPassword.isEmpty { return "Enter the password." }
        case .shares:
            // The inspected threshold when the auth block was readable;
            // otherwise any two or more and the helper says how many it needs.
            return ShareValidation.message(entries: mountShares, threshold: mountInfo?.threshold)
        }
        return nil
    }

    var canMount: Bool { !mountRunning && mountValidationMessage == nil }

    /// The form is complete *and* this Mac can mount: the toolbar button,
    /// its ⌘↩ shortcut and the inline button all key off this one gate.
    var canMountNow: Bool { canMount && mountingAvailable }

    /// Why the mount action is unavailable, for the buttons' help text.
    var mountBlockedMessage: String? {
        if let message = mountValidationMessage { return message }
        switch mountSupport {
        case .ready: return nil
        case .unknown:
            return fuseError == nil
                ? "Checking whether this Mac can open volumes as drives…"
                : "Couldn't check whether this Mac can mount volumes: the helper isn't responding."
        case .missing: return "Install disk mounting support first."
        }
    }

    func mount() {
        guard canMountNow, let path = mountPath else { return }
        let credential: CoreRequest.Credential = mountCredential == .password
            ? .password(mountPassword)
            : .shares(ShareValidation.prepared(mountShares))
        let target = (mountPoint as NSString).expandingTildeInPath
        mountRunning = true
        mountCancelling = false
        mountProgress = nil
        mountError = nil
        mountStatus = nil
        mountedNote = nil
        mountedReadOnly = false
        mountTask = Task { [core] in
            do {
                let result: VolumeMountResult = try await core.perform(
                    .volumeMount(path: path, mountPoint: target, credential: credential)
                ) { p in
                    Task { @MainActor [weak self] in self?.mountProgress = p }
                }
                finishMount(result, path: path)
            } catch let error as CoreError {
                mountRunning = false
                mountCancelling = false
                mountProgress = nil
                if error.isCancellation {
                    mountStatus = error.message
                } else {
                    mountError = Self.friendlyMountError(error, credential: mountCredential, path: path)
                }
            } catch {
                mountRunning = false
                mountCancelling = false
                mountProgress = nil
                mountError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    /// Only `wrong_credentials`, `permission_denied` and a FUSE startup
    /// failure are reworded; a `format` (damaged payload) or `invalid_input`
    /// (unreadable share) error keeps the helper's message.
    static func friendlyMountError(_ error: CoreError, credential: MountCredential, path: String) -> CoreError {
        switch error.code {
        case .wrongCredentials where credential == .password:
            return CoreError(code: error.code, message: "The password is incorrect. Check Caps Lock and try again.",
                             detail: error.detail)
        case .wrongCredentials:
            return CoreError(code: error.code,
                             message: "These shares don't unlock this volume. Try swapping in a different share. QuantaCrypt can't tell which one is wrong.",
                             detail: error.detail)
        case .permissionDenied:
            return CoreError(code: error.code,
                             message: "QuantaCrypt can't create the mount point. Choose a folder inside your home folder, such as ~/QuantaCrypt Volumes/\(Format.stem(path)).",
                             detail: error.detail)
        case .io where error.message.contains("FUSE mount failed"):
            // The helper interpolates the raw OSError here, so the two most
            // common real failures arrive as "[Errno 1] Operation not
            // permitted" with no cause and nowhere to go.
            return CoreError(
                code: error.code,
                message: "Couldn't open the volume as a drive. Check that the folder it mounts at is empty and not already in use, and that macFUSE or FUSE-T is allowed in System Settings ▸ Privacy & Security.",
                detail: error.detail.isEmpty ? error.message : "\(error.message)\n\(error.detail)")
        default:
            return error
        }
    }

    private func finishMount(_ result: VolumeMountResult, path: String) {
        mountRunning = false
        mountCancelling = false
        mountProgress = nil
        mountPassword = ""
        // Shares are key material — k points on the polynomial that rebuilds
        // the master key. Leaving them live in an @Observable model, rendered
        // in plain TextFields, outlasts the operation they were typed for.
        mountShares = mountShares.map { _ in ShareEntry() }
        // The create result was kept for "Show shares again"; a volume that
        // has now been unlocked with those shares has proven them, and the
        // result row would otherwise carry the master key for the rest of
        // the session. (`createVolume` clears it at the start of a new one.)
        if createResult?.path == path { createResult = nil }
        recents.add(path, kind: .mounted)
        let volume = MountedVolume(mountPoint: result.mountPoint, volumePath: result.volumePath ?? path, stats: nil,
                                   readOnly: result.readOnly)
        if result.readOnly {
            readOnlyMountPoints.insert(result.mountPoint)
        } else {
            readOnlyMountPoints.remove(result.mountPoint)
        }
        // A poll from an older helper may already have listed the new drive
        // unflagged.
        mounted = stampReadOnly(mounted)
        if result.journalSuspicious {
            suspiciousMount = SuspiciousMount(volume: volume, suspectSidecar: result.suspectSidecar)
        } else {
            mountedNote = "Mounted \(volume.name) at \(Format.tildePath(result.mountPoint))."
            mountedReadOnly = result.readOnly
        }
        Task { await refreshMounted() }
    }

    static let readOnlyMountMessage =
        "Mounted read-only: the .qcv file or its folder can't be written. You can open and copy files out, but nothing can be saved onto the drive."

    private func stampReadOnly(_ volumes: [MountedVolume]) -> [MountedVolume] {
        volumes.map { volume in
            var stamped = volume
            stamped.readOnly = volume.reportedReadOnly ?? readOnlyMountPoints.contains(volume.mountPoint)
            return stamped
        }
    }

    /// Fold what a fresh `volume_list` reports into the fallback set, so a
    /// later list from a helper that omits the key (or the stamp in
    /// `finishMount`) cannot revive a flag the helper has already retracted.
    private func reconcileReadOnly(with volumes: [MountedVolume]) {
        for volume in volumes {
            guard let reported = volume.reportedReadOnly else { continue }
            if reported {
                readOnlyMountPoints.insert(volume.mountPoint)
            } else {
                readOnlyMountPoints.remove(volume.mountPoint)
            }
        }
    }

    /// Body of the "may have been altered" alert.
    ///
    /// "Unmounting now keeps it untouched" was an unconditional promise
    /// about a conditional guarantee: the container is safe only until
    /// something writes, and macOS puts .DS_Store and Spotlight metadata on
    /// a fresh mount within seconds — the first save then truncates the
    /// suspicious tail for good. This matches the Tk wording, which tells
    /// the user to keep a copy first. The sidecar is the one artefact an
    /// investigation could use; left unnamed it is litter beside the volume.
    static func suspiciousMountMessage(_ mount: SuspiciousMount) -> String {
        var text = "\(mount.volume.name)'s records don't match what QuantaCrypt last wrote. It may have been altered or swapped for an older copy. It was mounted using the last state that checks out.\n\nIf you didn't expect this, unmount now and keep a copy of the .qcv file before writing anything: macOS writes to a new drive within seconds, and the first write destroys the records that raised this."
        if let sidecar = mount.suspectSidecar {
            text += "\n\nThe unreadable records were saved to \(Format.fileName(sidecar)) beside the volume. Keep it with your backup if you need to investigate."
        }
        return text
    }

    func cancelMount() {
        guard mountRunning else { return }
        mountCancelling = true
        mountTask?.cancel()
        // The FUSE startup wait has no cancel check inside it, so a cancelled
        // mount often succeeds anyway. Refresh straight away rather than
        // leaving "Cancelled" standing next to a volume that did mount.
        Task { await refreshMounted() }
    }

    // MARK: Mounted list

    func refreshMounted() async {
        let core = self.core
        do {
            let list: VolumeListResult = try await withTimeout(Self.checkTimeout) {
                try await core.perform(.volumeList)
            }
            reconcileReadOnly(with: list.volumes)
            mounted = stampReadOnly(list.volumes).sorted { $0.mountPoint < $1.mountPoint }
            listFailures = 0
            listLoaded = true
        } catch {
            // Polling: one transient failure just keeps the last list, but a
            // run of them means the rows on screen no longer describe reality.
            // The error itself is the only trace of why — `listIsStale` says
            // that the list is wrong, never what went wrong.
            listFailures += 1
            listLoaded = true
            // The code is enough to tell a dead helper from a slow one; the
            // description can quote the helper's message, which names mount
            // points, so it is redacted unless the log is read with privacy.
            let code = (error as? CoreError)?.code.rawValue ?? (error is TimeoutError ? "timeout" : "internal")
            Logger.client.error("volume_list failed (\(self.listFailures, privacy: .public) in a row): \(code, privacy: .public) \(String(describing: error), privacy: .private)")
        }
    }

    /// Poll while the Volumes screen is on screen; cancelled with the view.
    func pollMounted() async {
        if fuse == nil { await checkFuse() }
        while !Task.isCancelled {
            await refreshMounted()
            try? await Task.sleep(for: .seconds(3))
        }
    }

    func requestUnmount(_ volume: MountedVolume) {
        unmountCandidate = volume
    }

    func unmount(_ volume: MountedVolume) {
        guard !unmounting.contains(volume.mountPoint) else { return }
        unmounting.insert(volume.mountPoint)
        unmountError = nil
        Task { [core] in
            do {
                _ = try await core.perform(.volumeUnmount(mountPoint: volume.mountPoint))
                mountedNote = "Unmounted \(volume.name)."
                mountedReadOnly = false
            } catch let error as CoreError {
                if error.code == .invalidInput {
                    // Already ejected between the poll and the click: the
                    // refresh below drops the row; no error banner.
                    mountedNote = "\(volume.name) was already unmounted."
                } else {
                    unmountError = error.code == .busy || error.code == .io
                        ? CoreError(code: error.code,
                                    message: "Something is still using \(volume.name). Close Finder windows or apps opened from it, then try again.",
                                    detail: error.detail)
                        : error
                }
            } catch {
                unmountError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
            unmounting.remove(volume.mountPoint)
            await refreshMounted()
        }
    }
}
