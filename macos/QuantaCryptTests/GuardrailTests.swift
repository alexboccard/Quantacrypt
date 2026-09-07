import XCTest
@testable import QuantaCrypt

/// The guards added by the 2026-09 UI audit: the ones whose absence lost data
/// or sent the user somewhere useless. See docs/design/ui-audit-native-2026-09.md.
@MainActor
final class GuardrailTests: XCTestCase {

    // MARK: Already-encrypted sources (N-07)

    func testQuantaCryptContainersAreNotEncryptionSources() {
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/notes.txt.qcx"), .decrypt)
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/Vault.qcv"), .volumes)
        // Case is the file system's business, not the user's.
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/Notes.QCX"), .decrypt)
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/notes.txt"))
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/archive.qcxx"))
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/folder"))
    }

    func testSettingAnEncryptedSourceIsRefusedAndExplained() {
        let model = EncryptModel(core: CoreClient(transportFactory: { FakeTransport() }))
        XCTAssertFalse(model.setSource("/tmp/notes.txt.qcx"))
        XCTAssertNil(model.sourcePath, "a refused source must not become the file to encrypt")
        XCTAssertEqual(model.wrongSection?.section, .decrypt)
        XCTAssertEqual(model.wrongSection?.path, "/tmp/notes.txt.qcx")
    }

    func testAPlainSourceClearsTheRefusal() {
        let model = EncryptModel(core: CoreClient(transportFactory: { FakeTransport() }))
        XCTAssertFalse(model.setSource("/tmp/notes.txt.qcx"))
        XCTAssertTrue(model.setSource("/tmp/notes.txt"))
        XCTAssertNil(model.wrongSection)
        XCTAssertEqual(model.sourcePath, "/tmp/notes.txt")
    }

    // MARK: Quit guard (N-01)

    func testQuitIsBlockedWhileSharesAreUnsaved() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertNil(state.quitBlocker, "an idle app must quit without ceremony")

        state.encrypt.sharesToShow = Self.presentation(named: "secrets.qcx")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("secrets.qcx"))

        // Writing them somewhere durable is what lifts the guard — the sheet
        // being open is not, and neither is copying to the clipboard.
        state.encrypt.sharesSaved = true
        XCTAssertNil(state.quitBlocker)
    }

    func testShowingANewShareSetReArmsTheGuard() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        state.encrypt.sharesToShow = Self.presentation(named: "first.qcx")
        state.encrypt.sharesSaved = true
        state.encrypt.sharesToShow = Self.presentation(named: "second.qcx")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("second.qcx"),
                       "a second share set must not inherit the first one's saved flag")
    }

    func testVolumeSharesBlockQuitToo() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        state.volumes.sharesToShow = Self.presentation(named: "Vault.qcv")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("Vault.qcv"))
    }

    func testQuitBlockerCopyNamesWhatIsLost() {
        let blocker = AppState.QuitBlocker.unsavedShares("Vault.qcv")
        XCTAssertTrue(blocker.informativeText.contains("Vault.qcv"))
        XCTAssertTrue(blocker.informativeText.contains("never be opened again"))
        XCTAssertEqual(blocker.quitTitle, "Quit and discard shares")
    }

    // MARK: Decrypt input hygiene (E-10)

    func testLoadingAnotherFileClearsTheSharesTypedForTheLastOne() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        let decrypt = state.decrypt
        decrypt.shares = [ShareEntry(text: "QCSHARE-one"), ShareEntry(text: "QCSHARE-two")]
        decrypt.password = "hunter2"
        XCTAssertTrue(decrypt.load(path: "/tmp/other.qcx"))
        XCTAssertEqual(decrypt.shares, [], "one file's shares must not stand in for another's")
        XCTAssertEqual(decrypt.password, "")
    }

    // MARK: Mount support tri-state (E-05)

    func testUncheckedMountSupportIsNotReportedAsMissing() {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertEqual(model.mountSupport, .unknown)
        model.mountPath = "/tmp/Vault.qcv"
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2hunter2"
        // "Install disk mounting support" is the wrong advice for a check
        // that has not finished; so is it for a helper that is down.
        XCTAssertEqual(model.mountBlockedMessage,
                       "Checking whether this Mac can open volumes as drives…")
        model.fuseError = CoreError(code: .helperUnavailable, message: "no helper", detail: "")
        XCTAssertEqual(model.mountBlockedMessage,
                       "Couldn't check whether this Mac can mount volumes: the helper isn't responding.")
    }

    // MARK: One job at a time (A-02)

    func testCreateAndMountBlockEachOther() {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        model.mountRunning = true
        XCTAssertEqual(model.createValidationMessage, "Wait for the volume that is opening to finish.")
        XCTAssertFalse(model.canCreate)
        model.mountRunning = false
        model.createRunning = true
        XCTAssertEqual(model.mountValidationMessage, "Wait for the volume being created to finish.")
        XCTAssertFalse(model.canMount)
    }

    // MARK: Mount failure copy (E-04)

    func testFuseStartupFailureGetsACauseAndANextStep() {
        let raw = CoreError(code: .io, message: "FUSE mount failed: [Errno 1] Operation not permitted",
                            detail: "")
        let shown = VolumesModel.friendlyMountError(raw, credential: .password, path: "/tmp/Vault.qcv")
        XCTAssertFalse(shown.message.contains("Errno"), "the raw interpolation is not a user message")
        XCTAssertTrue(shown.message.contains("Privacy & Security"))
        XCTAssertTrue(shown.detail.contains("Errno 1"), "the raw text belongs in the details")
    }

    func testUnrelatedIOErrorsKeepTheHelperMessage() {
        let raw = CoreError(code: .io, message: "The volume file is unreadable.", detail: "")
        let shown = VolumesModel.friendlyMountError(raw, credential: .password, path: "/tmp/Vault.qcv")
        XCTAssertEqual(shown.message, "The volume file is unreadable.")
    }

    // MARK: Wire errors (E-11)

    func testAMessagelessHelperErrorStillSaysWhatToDo() {
        let error = CoreError.fromWire(code: "internal", message: nil, detail: nil)
        XCTAssertTrue(error.message.contains("didn't say what"), "the fallback names the cause")
        XCTAssertTrue(error.message.contains("Try again"))
    }

    // MARK: Stale mounted list (E-06)

    func testMountedListIsOnlyStaleAfterARunOfFailures() async {
        let model = VolumesModel(core: CoreClient(transportFactory: { FailingTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertFalse(model.listIsStale)
        await model.refreshMounted()
        XCTAssertFalse(model.listIsStale, "one missed poll is noise, not a stale list")
        await model.refreshMounted()
        XCTAssertTrue(model.listIsStale)
    }

    // MARK: Encrypt drop zone (S-09)

    func testTheEncryptDropZoneTakesOnlyExistingFiles() throws {
        XCTAssertFalse(EncryptModel.acceptsDrop(URL(string: "https://example.com/report.pdf")!),
                       "a link dragged from a browser is not a file")
        XCTAssertFalse(EncryptModel.acceptsDrop(URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString)")))
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appending(path: "notes.txt")
        try Data("hi".utf8).write(to: file)
        XCTAssertTrue(EncryptModel.acceptsDrop(file))
        XCTAssertTrue(EncryptModel.acceptsDrop(dir), "folders are zipped and encrypted too")
    }

    // MARK: Share files name the .qcx (F-032 / S-05)

    func testSplitKeySharesNameTheEncryptedFileAndItsFingerprint() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let output = dir.appending(path: "report.pdf.qcx")
        try Data("abc".utf8).write(to: output)

        let result = EncryptResult(output: output.path, size: 3, filename: "report.pdf", mode: "shamir",
                                   threshold: 2, total: 3,
                                   shares: [Share(index: 1, code: "QCSHARE-A", mnemonic: nil)])
        let presentation = try XCTUnwrap(result.makeSharesPresentation())
        XCTAssertEqual(presentation.context.protectedName, "report.pdf.qcx",
                       "the recipient is told to pick the encrypted file, so name that one")
        XCTAssertEqual(presentation.context.stem, "report.pdf")
        XCTAssertEqual(presentation.context.fingerprint, "ba7816bf8f01")
        XCTAssertEqual(presentation.context.kind, .qcxFile)
        XCTAssertEqual(presentation.shares.count, 1)

        let password = EncryptResult(output: output.path, size: 3, filename: "report.pdf", mode: "single",
                                     threshold: nil, total: nil, shares: [])
        XCTAssertNil(password.makeSharesPresentation())
    }

    // MARK: Key material is dropped once proven (S-06)

    func testAVerifiedEncryptDropsItsShares() async throws {
        let transport = FakeTransport()
        let state = AppState(core: CoreClient(transportFactory: { transport }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/report.pdf.qcx"
        state.encrypt.result = EncryptResult(output: path, size: 3, filename: "report.pdf", mode: "shamir",
                                             threshold: 2, total: 3,
                                             shares: [Share(index: 1, code: "QCSHARE-A", mnemonic: nil)])

        state.verifyEncrypted(path)
        XCTAssertEqual(state.section, .decrypt)
        await transport.waitForRequests(1)
        let inspect = await transport.request(0)
        XCTAssertEqual(inspect.op, "inspect")
        await transport.emit(["id": inspect.id!, "event": "done",
                              "result": ["path": path, "size": 3, "version": 2, "mode": "password",
                                         "threshold": NSNull(), "total": NSNull(), "embedded": false]])
        try await waitUntil("the inspect result to land") { state.decrypt.info != nil }
        XCTAssertNotNil(state.encrypt.result?.shares, "inspecting proves nothing yet")

        state.decrypt.password = "hunter2"
        state.decrypt.verify()
        await transport.waitForRequests(2)
        let verify = await transport.request(1)
        XCTAssertEqual(verify.op, "decrypt")
        XCTAssertEqual(verify.params?["verify_only"], .bool(true))
        await transport.emit(["id": verify.id!, "event": "done", "result": ["verified": true, "mode": "password"]])
        try await waitUntil("the verify to finish") { state.decrypt.verifiedNote != nil }

        XCTAssertNil(state.encrypt.result?.shares, "shares proven to work no longer belong in the model")
        XCTAssertEqual(state.encrypt.result?.output, path, "the result card itself stays")
    }

    func testAVerifiedEncryptOfAnotherFileKeepsTheShares() {
        let model = EncryptModel(core: CoreClient(transportFactory: { FakeTransport() }))
        model.result = EncryptResult(output: "/tmp/a.qcx", size: 1, filename: "a", mode: "shamir",
                                     threshold: 2, total: 3, shares: [Share(index: 1, code: "QCSHARE-A", mnemonic: nil)])
        model.forgetShares(for: "/tmp/b.qcx")
        XCTAssertNotNil(model.result?.shares)
        model.forgetShares(for: "/tmp/a.qcx")
        XCTAssertNil(model.result?.shares)
    }

    func testMountingTheCreatedVolumeDropsTheCreateResult() async throws {
        let transport = FakeTransport()
        let model = VolumesModel(core: CoreClient(transportFactory: { transport }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/Vault.qcv"
        model.createResult = VolumeCreateResult(path: path, mode: "shamir", threshold: 2, total: 3,
                                                shares: [Share(index: 1, code: "QCSHARE-A", mnemonic: nil)])
        XCTAssertTrue(model.canShowSharesAgain)
        model.fuse = FuseCheck(fuseBackend: .init(ok: true, detail: ""), fusepy: .init(ok: true, detail: ""), ok: true)
        model.mountPath = path
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2"
        XCTAssertTrue(model.canMountNow)

        model.mount()
        await transport.waitForRequests(1)
        let mount = await transport.request(0)
        XCTAssertEqual(mount.op, "volume_mount")
        await transport.emit(["id": mount.id!, "event": "done",
                              "result": ["mount_point": "/tmp/mnt", "volume_path": path, "journal_suspicious": false]])
        try await waitUntil("the mount to finish") { model.mountedNote != nil }

        XCTAssertNil(model.createResult, "a mounted volume has proven its shares; the row would otherwise hold the key all session")
        XCTAssertFalse(model.canShowSharesAgain)
        // The list refresh the mount kicked off; answer it so nothing lingers.
        await transport.waitForRequests(2)
        let list = await transport.request(1)
        await transport.emit(["id": list.id!, "event": "done", "result": ["volumes": []]])
    }

    func testStartingANewCreateDropsThePreviousResult() throws {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        model.createResult = VolumeCreateResult(path: "/tmp/Old.qcv", mode: "shamir", threshold: 2, total: 3,
                                                shares: [Share(index: 1, code: "QCSHARE-A", mnemonic: nil)])
        model.createDirectory = FileManager.default.temporaryDirectory.path
        model.createName = "Vault-\(UUID().uuidString)"
        model.createPassword = "hunter2hunter2"
        model.createConfirmation = "hunter2hunter2"
        XCTAssertTrue(model.canCreate)
        model.createVolume()
        XCTAssertNil(model.createResult)
        model.cancelCreate()
    }

    // MARK: A chosen mount point belongs to one volume (F-028)

    func testAChosenMountPointDoesNotStickToTheNextVolume() {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertTrue(model.prepareMount(path: "/tmp/A.qcv"))
        model.useMountPoint("/tmp/somewhere-else")
        XCTAssertEqual(model.mountPoint, "/tmp/somewhere-else")
        // Retrying the same volume is not a new volume.
        XCTAssertTrue(model.prepareMount(path: "/tmp/A.qcv"))
        XCTAssertEqual(model.mountPoint, "/tmp/somewhere-else")

        XCTAssertTrue(model.prepareMount(path: "/tmp/B.qcv"))
        XCTAssertEqual(model.mountPoint, VolumesModel.defaultMountPoint(for: "/tmp/B.qcv"),
                       "A's folder would fail as already mounted, or as not empty")
    }

    // MARK: A read-only mount is shown as one

    func testAReadOnlyMountFlagsTheMountedRow() async throws {
        let transport = FakeTransport()
        let model = VolumesModel(core: CoreClient(transportFactory: { transport }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/Vault.qcv"
        model.fuse = FuseCheck(fuseBackend: .init(ok: true, detail: ""), fusepy: .init(ok: true, detail: ""), ok: true)
        model.mountPath = path
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2"
        XCTAssertTrue(model.canMountNow)

        model.mount()
        await transport.waitForRequests(1)
        let mount = await transport.request(0)
        XCTAssertEqual(mount.op, "volume_mount")
        await transport.emit(["id": mount.id!, "event": "done",
                              "result": ["mount_point": "/tmp/mnt", "volume_path": path,
                                         "journal_suspicious": false, "suspect_sidecar": NSNull(),
                                         "read_only": true]])
        try await waitUntil("the mount to finish") { model.mountedNote != nil }
        XCTAssertTrue(model.mountedReadOnly, "the post-mount note must say the drive refuses writes")

        // An older helper's `volume_list` does not carry the flag; the row
        // must still show it after the poll that follows every mount
        // replaces the list.
        await transport.waitForRequests(2)
        let list = await transport.request(1)
        XCTAssertEqual(list.op, "volume_list")
        await transport.emit(["id": list.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": path,
                                                      "stats": NSNull()]]]])
        try await waitUntil("the list to refresh") { !model.mounted.isEmpty }
        XCTAssertEqual(model.mounted.map(\.readOnly), [true])

        // Unmounting clears the note's flag with the note.
        model.unmount(model.mounted[0])
        await transport.waitForRequests(3)
        let unmount = await transport.request(2)
        XCTAssertEqual(unmount.op, "volume_unmount")
        await transport.emit(["id": unmount.id!, "event": "done", "result": ["mount_point": "/tmp/mnt"]])
        try await waitUntil("the unmount to finish") { model.mountedNote == "Unmounted Vault." }
        XCTAssertFalse(model.mountedReadOnly)
        await transport.waitForRequests(4)
        let relist = await transport.request(3)
        await transport.emit(["id": relist.id!, "event": "done", "result": ["volumes": []]])
    }

    func testAWritableMountIsNotFlagged() async throws {
        let transport = FakeTransport()
        let model = VolumesModel(core: CoreClient(transportFactory: { transport }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/Vault.qcv"
        model.fuse = FuseCheck(fuseBackend: .init(ok: true, detail: ""), fusepy: .init(ok: true, detail: ""), ok: true)
        model.mountPath = path
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2"

        model.mount()
        await transport.waitForRequests(1)
        let mount = await transport.request(0)
        // An older helper: no `read_only` at all.
        await transport.emit(["id": mount.id!, "event": "done",
                              "result": ["mount_point": "/tmp/mnt", "volume_path": path, "journal_suspicious": false]])
        try await waitUntil("the mount to finish") { model.mountedNote != nil }
        XCTAssertFalse(model.mountedReadOnly)
        await transport.waitForRequests(2)
        let list = await transport.request(1)
        await transport.emit(["id": list.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": path,
                                                      "stats": NSNull()]]]])
        try await waitUntil("the list to refresh") { !model.mounted.isEmpty }
        XCTAssertEqual(model.mounted.map(\.readOnly), [false])
    }

    /// The helper now reports `read_only` on every `volume_list` entry, so a
    /// drive this app never saw the mount result for (cancelled while the
    /// helper finished anyway, mounted before the app started) is badged
    /// from the list alone, and the flag survives a later list without the
    /// key.
    func testAListedReadOnlyFlagNeedsNoMountResult() async throws {
        let transport = FakeTransport()
        let model = VolumesModel(core: CoreClient(transportFactory: { transport }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/Vault.qcv"

        let first = Task { await model.refreshMounted() }
        await transport.waitForRequests(1)
        let list = await transport.request(0)
        XCTAssertEqual(list.op, "volume_list")
        await transport.emit(["id": list.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": path,
                                                      "stats": NSNull(), "read_only": true]]]])
        await first.value
        XCTAssertEqual(model.mounted.map(\.readOnly), [true])
        XCTAssertFalse(model.mountedReadOnly, "no mount result was processed, so there is no post-mount note")

        // The list taught the fallback set: a list without the key keeps it.
        let second = Task { await model.refreshMounted() }
        await transport.waitForRequests(2)
        let relist = await transport.request(1)
        await transport.emit(["id": relist.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": path,
                                                      "stats": NSNull()]]]])
        await second.value
        XCTAssertEqual(model.mounted.map(\.readOnly), [true])
    }

    /// The set of read-only mount points is written by mount results and
    /// used to be corrected only by the next mount result at the same point,
    /// so a read-only drive replaced by a writable one at the same point
    /// without the app seeing the second result stayed badged for its
    /// lifetime. A list entry reporting `read_only: false` must clear the
    /// row and the set behind it.
    func testAListedWritableFlagClearsAStaleReadOnlyBadge() async throws {
        let transport = FakeTransport()
        let model = VolumesModel(core: CoreClient(transportFactory: { transport }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        let path = "/tmp/\(UUID().uuidString)/Vault.qcv"
        model.fuse = FuseCheck(fuseBackend: .init(ok: true, detail: ""), fusepy: .init(ok: true, detail: ""), ok: true)
        model.mountPath = path
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2"

        // A read-only mount result puts /tmp/mnt in the set.
        model.mount()
        await transport.waitForRequests(1)
        let mount = await transport.request(0)
        await transport.emit(["id": mount.id!, "event": "done",
                              "result": ["mount_point": "/tmp/mnt", "volume_path": path,
                                         "journal_suspicious": false, "suspect_sidecar": NSNull(),
                                         "read_only": true]])
        try await waitUntil("the mount to finish") { model.mountedNote != nil }
        XCTAssertTrue(model.mountedReadOnly)

        // By the time the post-mount poll answers, the helper has a writable
        // drive at that point (a different volume, remounted outside this
        // model's view); the list is the truth, not the set.
        let other = "/tmp/\(UUID().uuidString)/Other.qcv"
        await transport.waitForRequests(2)
        let list = await transport.request(1)
        XCTAssertEqual(list.op, "volume_list")
        await transport.emit(["id": list.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": other,
                                                      "stats": NSNull(), "read_only": false]]]])
        try await waitUntil("the list to refresh") { !model.mounted.isEmpty }
        XCTAssertEqual(model.mounted.map(\.readOnly), [false])

        // The set was corrected, not just overridden for one poll: a list
        // without the key no longer revives the badge.
        let again = Task { await model.refreshMounted() }
        await transport.waitForRequests(3)
        let relist = await transport.request(2)
        await transport.emit(["id": relist.id!, "event": "done",
                              "result": ["volumes": [["mount_point": "/tmp/mnt", "volume_path": other,
                                                      "stats": NSNull()]]]])
        await again.value
        XCTAssertEqual(model.mounted.map(\.readOnly), [false])
    }

    // MARK: The suspect sidecar is named (F-003)

    func testASuspiciousMountNamesTheSidecar() {
        let volume = MountedVolume(mountPoint: "/tmp/mnt", volumePath: "/tmp/Vault.qcv", stats: nil)
        let named = VolumesModel.suspiciousMountMessage(
            .init(volume: volume, suspectSidecar: "/tmp/Vault.qcv.suspect-20260905T101500"))
        XCTAssertTrue(named.contains("saved to Vault.qcv.suspect-20260905T101500 beside the volume"), named)
        XCTAssertTrue(named.contains("keep a copy of the .qcv"), named)
        // An older helper sends no sidecar: don't name a file that isn't there.
        let unnamed = VolumesModel.suspiciousMountMessage(.init(volume: volume, suspectSidecar: nil))
        XCTAssertFalse(unnamed.contains("saved to"), unnamed)
        XCTAssertTrue(unnamed.hasPrefix("Vault's records"), unnamed)
    }

    // MARK: Helpers

    /// Poll the main actor until `condition` holds, failing after five
    /// seconds rather than hanging the suite.
    private func waitUntil(_ what: String, _ condition: () -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + .seconds(5)
        while !condition() {
            if clock.now > deadline {
                XCTFail("timed out waiting for \(what)")
                return
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private static func presentation(named name: String) -> SharesPresentation {
        SharesPresentation(shares: [],
                           context: ShareFiles.Context(stem: "stem", protectedName: name,
                                                       k: 2, n: 3, kind: .qcxFile))
    }

    private static func scratchDefaults() -> UserDefaults {
        UserDefaults(suiteName: "QuantaCryptTests.\(UUID().uuidString)")!
    }
}

/// A transport that refuses to start, for the poll-failure path.
private struct FailingTransport: CoreTransport {
    struct Boom: Error {}
    func start() async throws -> AsyncThrowingStream<String, any Error> { throw Boom() }
    func send(_ line: String) async throws { throw Boom() }
    func closeInput() async {}
    func terminate(timeout: Duration) async {}
}
