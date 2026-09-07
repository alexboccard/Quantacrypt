import XCTest
@testable import QuantaCrypt

/// The helper receives every password and every Shamir share on its stdin, so
/// which binary is chosen is a security decision, not a convenience.
final class HelperLocatorTests: XCTestCase {
    private var scratch: URL!
    /// A stand-in app bundle with a helper where `build.py` puts one.
    private var appBundle: Bundle!
    private var bundledHelper: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let helpers = scratch.appending(path: "QuantaCrypt.app/Contents/Helpers/qc-core.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        bundledHelper = helpers.appending(path: "qc-core")
        try write(executable: bundledHelper)
        appBundle = try XCTUnwrap(Bundle(path: scratch.appending(path: "QuantaCrypt.app").path))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    private func write(executable url: URL) throws {
        try "#!/bin/sh\nexit 0\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }

    private func outsideHelper(_ name: String = "qc-core") throws -> URL {
        let url = scratch.appending(path: name)
        try write(executable: url)
        return url
    }

    /// Stand-in for a real code hash: only its equality matters here.
    private static let pinnedHash = Data([0xC0, 0xDE, 0xF0, 0x0D])

    /// A signature check that reports `target` unsigned and everything else
    /// pinned. The scratch bundle's helper is a script, and since the bundled
    /// helper is measured like any other, a stub that calls *everything*
    /// unsigned would refuse it too and fall through to the dev venv.
    private static func unsigned(only target: URL) -> @Sendable (URL) -> HelperLocator.SignatureStatus {
        let path = target.standardizedFileURL.path
        return { url in
            url.standardizedFileURL.path == path ? .unsigned("no signature") : .satisfiesPin(cdHash: pinnedHash)
        }
    }

    /// The real Security check for `target` alone; the rest pinned, as above.
    private static func measuring(only target: URL) -> @Sendable (URL) -> HelperLocator.SignatureStatus {
        let path = target.standardizedFileURL.path
        return { url in
            url.standardizedFileURL.path == path ? HelperLocator.signatureStatus(of: url) : .satisfiesPin(cdHash: pinnedHash)
        }
    }

    private func resolve(override: String?,
                         environment: [String: String] = [:],
                         signature: @escaping @Sendable (URL) -> HelperLocator.SignatureStatus
                             = { _ in .satisfiesPin(cdHash: HelperLocatorTests.pinnedHash) },
                         approved: @escaping @Sendable (String, Data) -> Bool = { _, _ in false })
    -> HelperLocator.Resolution {
        HelperLocator.resolve(override: override, environment: environment, bundle: appBundle,
                              signature: signature, approved: approved)
    }

    /// A real, ad-hoc-signed helper: `scripts/build.py --helper` signs with
    /// `--sign -` too, so this is the production shape of an override.
    private func signHelper(_ url: URL, contents: String) throws {
        try contents.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        try codesign(["--identifier", "qc-core", url.path])
    }

    private func codesign(_ arguments: [String]) throws {
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--force", "--sign", "-"] + arguments
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        if codesign.terminationStatus != 0 {
            throw XCTSkip("codesign is unavailable, so the pin cannot be exercised end to end")
        }
    }

    /// The smallest thing `codesign` accepts as a bundle: an Info.plist and
    /// a main executable (a script will do).
    private func writeBundleSkeleton(at bundle: URL, identifier: String, executable: String) throws {
        let macOS = bundle.appending(path: "Contents/MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        let plist: [String: Any] = ["CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
                                    "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: bundle.appending(path: "Contents/Info.plist"))
        try write(executable: macOS.appending(path: executable))
    }

    /// An app bundle with a helper bundle nested where `build.py` puts it,
    /// both ad-hoc signed inside-out the way `_codesign_app_bundle` does.
    private func makeSignedAppBundle() throws -> (app: URL, helper: URL) {
        let app = scratch.appending(path: "Signed.app")
        let helper = app.appending(path: "Contents/Helpers/qc-core.app")
        try writeBundleSkeleton(at: app, identifier: "com.alexboccard.quantacrypt", executable: "Signed")
        try writeBundleSkeleton(at: helper, identifier: "com.alexboccard.quantacrypt.core", executable: "qc-core")
        try codesign([helper.path])
        try codesign([app.path])
        return (app, helper)
    }

    // MARK: Resolution order

    func testBundledHelperIsUsedWhenNothingOverridesIt() {
        let resolution = resolve(override: nil)
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertNil(resolution.refusal)
    }

    func testBundledHelperBeatsTheEnvironment() throws {
        let env = try outsideHelper("env-helper")
        let resolution = resolve(override: nil, environment: ["QC_CORE_PATH": env.path])
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path,
                       "the bundle must win over an environment variable")
    }

    func testAnOverrideThatDoesNotExistFallsThroughWithoutRefusing() {
        let resolution = resolve(override: scratch.appending(path: "missing").path)
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertNil(resolution.refusal, "a path that isn't there was never a candidate")
        XCTAssertTrue(resolution.searched.contains { $0.contains("Settings override") })
    }

    // MARK: The override is the attack surface

    func testAnOverrideOutsideTheBundleIsRefusedUntilApproved() throws {
        let planted = try outsideHelper("planted")
        let refused = resolve(override: planted.path)
        XCTAssertEqual(refused.launch?.executable.path, bundledHelper.path,
                       "a planted preference must not receive passwords and shares")
        XCTAssertEqual(refused.refusal?.path, planted.standardizedFileURL.path)
        XCTAssertEqual(refused.refusal?.approvable, true)

        let approved = resolve(override: planted.path,
                               approved: { path, hash in
                                   path == planted.standardizedFileURL.path && hash == Self.pinnedHash
                               })
        XCTAssertEqual(approved.launch?.executable.path, planted.path)
        XCTAssertEqual(approved.launch?.origin, "settings")
        XCTAssertNil(approved.refusal)
    }

    func testAnUnsignedOverrideIsRefusedEvenWhenApproved() throws {
        let planted = try outsideHelper("unsigned")
        let resolution = resolve(override: planted.path,
                                 signature: Self.unsigned(only: planted),
                                 approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.refusal?.approvable, false,
                       "nothing the user can click makes an unsigned binary safe")
    }

    func testAnOverridePointingIntoTheAppBundleNeedsNoApproval() {
        // Signed, if not as qc-core: inside the bundle only a signature is
        // required, because the click exists for paths the user chose.
        let resolution = resolve(override: bundledHelper.path,
                                 signature: { _ in .signedButUnpinned("signed by someone else") })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.launch?.origin, "settings")
        XCTAssertNil(resolution.refusal, "a signed helper inside the bundle needs no click")
    }

    /// `FileManager.isExecutableFile` is true for any searchable folder, so
    /// the bundle `build.py --helper` produces — not the Mach-O inside it —
    /// used to pass, be signature-checked as a bundle, be approvable, and
    /// then fail opaquely in `Process.run()` (F-027).
    func testAnOverridePointingAtABundleFolderIsRefusedAndNamesTheExecutable() throws {
        let bundle = scratch.appending(path: "qc-core.app")
        try writeBundleSkeleton(at: bundle, identifier: "com.alexboccard.quantacrypt.core", executable: "qc-core")
        let resolution = resolve(override: bundle.path, approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path,
                       "a folder cannot be exec'd, approved or not")
        XCTAssertEqual(resolution.refusal?.path, bundle.standardizedFileURL.path)
        XCTAssertEqual(resolution.refusal?.approvable, false)
        XCTAssertTrue(resolution.refusal?.reason.contains("Contents/MacOS/qc-core") == true,
                      "the sentence should say what the path should have been: \(resolution.refusal?.reason ?? "")")
    }

    func testAnOverridePointingAtAPlainFolderIsRefused() throws {
        let folder = scratch.appending(path: "helpers")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let resolution = resolve(override: folder.path, approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertEqual(resolution.refusal?.approvable, false)
        XCTAssertTrue(resolution.refusal?.reason.contains("is a folder") == true)
    }

    // MARK: The bundle is not a trust boundary at runtime (S-03)

    /// The comment used to say the app's seal made a swapped helper
    /// impossible. Nothing checks that seal at exec time, so the bundled
    /// helper is measured like any other; an unsigned one is refused, with
    /// no button, because nothing could be re-checked before `exec`.
    func testAnUnsignedBundledHelperIsRefused() {
        let resolution = resolve(override: nil, signature: { _ in .unsigned("no signature") })
        // On a developer machine the DEBUG-only venv fallback still resolves
        // a launch; anything else here would mean the bundled helper leaked
        // through (review F-210).
        XCTAssertTrue(resolution.launch == nil || resolution.launch?.origin == "dev venv",
                      "an unmeasurable helper must not receive passwords and shares")
        XCTAssertNotEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.refusal?.approvable, false)
        XCTAssertTrue(resolution.refusal?.reason.contains("bundled with QuantaCrypt") == true)
        XCTAssertTrue(resolution.refusal?.reason.contains("Reinstall") == true)
    }

    func testAnUnsignedOverrideInsideTheBundleIsRefusedToo() {
        let resolution = resolve(override: bundledHelper.path, signature: { _ in .unsigned("no signature") })
        XCTAssertNotEqual(resolution.launch?.origin, "settings")
        XCTAssertEqual(resolution.refusal?.approvable, false, "inside the bundle is not a substitute for a signature")
    }

    /// `ProcessTransport` re-measures whatever hash rides on the launch
    /// immediately before `exec`; the bundled helper used to carry none.
    func testABundledHelperCarriesItsCodeHashForTheExecCheck() {
        let resolution = resolve(override: nil)
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertEqual(resolution.launch?.approvedCDHash, Self.pinnedHash)
    }

    /// The launch-time check that gives the old comment's premise some
    /// teeth: a helper swapped inside the bundle and ad-hoc re-signed — so
    /// its own signature is valid, which is all the kernel looks at — fails
    /// the strict, nested validation of the app.
    func testBundleIntegrityCatchesASwappedHelperEvenWhenItIsReSigned() throws {
        let (app, helper) = try makeSignedAppBundle()
        let bundle = try XCTUnwrap(Bundle(path: app.path))
        XCTAssertNil(HelperLocator.bundleIntegrityWarning(for: bundle), "an intact bundle must not warn")

        let helperExecutable = helper.appending(path: "Contents/MacOS/qc-core")
        try "#!/bin/sh\nexec /usr/bin/true\n".write(to: helperExecutable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helperExecutable.path)
        try codesign([helper.path])
        XCTAssertEqual(HelperLocator.signatureStatus(of: helperExecutable).cdHash?.isEmpty, false,
                       "the swapped helper's own signature is valid — that is the attack")

        let warning = try XCTUnwrap(HelperLocator.bundleIntegrityWarning(for: bundle))
        XCTAssertTrue(warning.contains("may have been altered"), warning)
        XCTAssertTrue(warning.contains("Reinstall"), warning)
    }

    /// Never fatal: a build with signing disabled has no seal and must
    /// still launch. It says so instead of pretending to have checked.
    func testAnUnsignedBundleWarnsRatherThanFailing() throws {
        let app = scratch.appending(path: "Unsigned.app")
        try writeBundleSkeleton(at: app, identifier: "com.alexboccard.quantacrypt", executable: "Unsigned")
        let bundle = try XCTUnwrap(Bundle(path: app.path))
        let warning = try XCTUnwrap(HelperLocator.bundleIntegrityWarning(for: bundle))
        XCTAssertTrue(warning.contains("isn't code-signed"), warning)
        XCTAssertFalse(warning.contains("may have been altered"), "unsigned is not evidence of tampering: \(warning)")
    }

    /// A binary that is signed, but not as *this* helper, cannot be approved
    /// at all. Treating "signed by someone else" exactly like "signed as
    /// qc-core" is what made the requirement pin decorative: the check ran and
    /// its answer changed no branch.
    func testASignedButUnpinnedOverrideCannotBeApproved() throws {
        let planted = try outsideHelper("someone-elses")
        let resolution = resolve(override: planted.path,
                                 signature: { _ in .signedButUnpinned("it is signed by someone else") },
                                 approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.refusal?.approvable, false,
                       "the override is for a qc-core, not for any signed binary")
        XCTAssertTrue(resolution.refusal?.reason.contains("not as QuantaCrypt's qc-core helper") == true)
    }

    func testAnApprovedLaunchCarriesTheHashItWasApprovedAt() throws {
        let planted = try outsideHelper("pinned")
        let resolution = resolve(override: planted.path, approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.approvedCDHash, Self.pinnedHash,
                       "ProcessTransport re-measures this immediately before exec")
    }

    /// The approval names the bytes, not the path: swapping the file for a
    /// differently signed one used to inherit the click, and every password
    /// and share typed afterwards would have gone to the replacement.
    func testAnApprovalDoesNotSurviveTheFileBeingReplaced() throws {
        let planted = scratch.appending(path: "swappable")
        try signHelper(planted, contents: "#!/bin/sh\nexit 0\n")
        guard case .satisfiesPin(let first) = HelperLocator.signatureStatus(of: planted) else {
            throw XCTSkip("ad-hoc signing did not take on this machine")
        }
        XCTAssertTrue(HelperLocator.approve(planted.path))
        XCTAssertTrue(HelperLocator.isApproved(planted.standardizedFileURL.path, cdHash: first))
        XCTAssertFalse(HelperLocator.isApproved(scratch.appending(path: "other").path, cdHash: first))

        let allowed = HelperLocator.resolve(override: planted.path, environment: [:], bundle: appBundle,
                                            signature: Self.measuring(only: planted))
        XCTAssertEqual(allowed.launch?.origin, "settings")
        XCTAssertEqual(allowed.launch?.approvedCDHash, first)

        try signHelper(planted, contents: "#!/bin/sh\nexec /usr/bin/true\n")
        guard case .satisfiesPin(let second) = HelperLocator.signatureStatus(of: planted), second != first else {
            return XCTFail("re-signing different bytes must change the code hash")
        }
        XCTAssertFalse(HelperLocator.isApproved(planted.standardizedFileURL.path, cdHash: second))
        let refused = HelperLocator.resolve(override: planted.path, environment: [:], bundle: appBundle,
                                            signature: Self.measuring(only: planted))
        XCTAssertEqual(refused.launch?.executable.path, bundledHelper.path,
                       "the replacement must not inherit the approval")
        XCTAssertEqual(refused.refusal?.approvable, true)
    }

    /// Nothing is recorded for a file that cannot be pinned, so a click on a
    /// stale refusal cannot grant more than it showed.
    func testApprovingAnUnpinnableFileRecordsNothing() throws {
        let script = try outsideHelper("not-signed")
        XCTAssertFalse(HelperLocator.approve(script.path))
        XCTAssertFalse(HelperLocator.isApproved(script.standardizedFileURL.path, cdHash: Self.pinnedHash))
    }

    // MARK: The signature check must not be vacuous

    func testTheRequirementRejectsBinariesSignedBySomeoneElse() {
        // Also asserts the requirement string still compiles: a compile
        // failure has its own `.signedButUnpinned` detail, and now that only
        // pinned binaries are approvable it would lock out every override.
        XCTAssertEqual(HelperLocator.signatureStatus(of: URL(fileURLWithPath: "/bin/ls")),
                       .signedButUnpinned("it is signed by someone else"))
    }

    func testAPinnedBinaryReportsANonEmptyCodeHash() throws {
        let helper = scratch.appending(path: "qc-core-copy")
        try signHelper(helper, contents: "#!/bin/sh\nexit 0\n")
        guard case .satisfiesPin(let hash) = HelperLocator.signatureStatus(of: helper) else {
            return XCTFail("an ad-hoc signature under our identifier must satisfy the pin")
        }
        XCTAssertFalse(hash.isEmpty, "an approval with nothing to compare is an approval of the path")
    }

    func testAnUnsignedFileIsReportedAsUnsigned() throws {
        let script = try outsideHelper("script.sh")
        guard case .unsigned = HelperLocator.signatureStatus(of: script) else {
            return XCTFail("a shell script has no code signature to check")
        }
    }
}
