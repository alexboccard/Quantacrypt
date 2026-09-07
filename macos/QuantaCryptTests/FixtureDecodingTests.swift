import XCTest
@testable import QuantaCrypt

/// The one test that crosses the `qc-core` process boundary.
///
/// `tests/test_service.py` dumps one canonical `done` line per op into
/// `QuantaCryptTests/Fixtures/<op>.json`; this decodes every one of them into
/// the struct the app would use. A renamed result key on the Python side then
/// breaks the Swift build instead of becoming a `protocol_error` in front of a
/// user — which is how F-004 and F-036 survived, with the protocol verified
/// twice in isolation and never once end to end.
final class FixtureDecodingTests: XCTestCase {

    /// Fixture basename → the decode the app performs for that op. A fixture
    /// with no entry here fails: a new op needs a Swift consumer, and an op
    /// whose result nothing decodes is exactly the drift this test exists for.
    /// Names are matched exactly first, then by longest registered prefix, so
    /// `encrypt_shamir.json` uses the `encrypt` decoder.
    private static let decoders: [String: @Sendable (JSONValue) throws -> Any] = [
        "version": { try $0.decoded(as: VersionInfo.self) },
        "fuse_check": { try $0.decoded(as: FuseCheck.self) },
        "inspect": { try $0.decoded(as: InspectInfo.self) },
        "volume_inspect": { try $0.decoded(as: VolumeInspectInfo.self) },
        "encrypt": { try $0.decoded(as: EncryptResult.self) },
        "decrypt": { try $0.decoded(as: DecryptResult.self) },
        "verify": { try $0.decoded(as: VerifyResult.self) },
        "volume_create": { try $0.decoded(as: VolumeCreateResult.self) },
        "volume_mount": { try $0.decoded(as: VolumeMountResult.self) },
        "volume_unmount": { try $0.decoded(as: VolumeUnmountResult.self) },
        "volume_list": { try $0.decoded(as: VolumeListResult.self) },
        "cancel": { try $0.decoded(as: CancelResult.self) },
        // `ping` and `shutdown` carry no fields the app reads; the contract is
        // only that the line frames as an object.
        "ping": { try $0.decoded(as: [String: JSONValue].self) },
        "shutdown": { try $0.decoded(as: [String: JSONValue].self) },
    ]

    /// Wire keys the app reads that a decoder would silently miss if the
    /// helper renamed them (optional / `decodeIfPresent` fields decode to nil
    /// and stay green). The fixture must carry each, so a rename on the
    /// Python side goes red here — `skipped_symlinks` drifted exactly this
    /// way (review F-202, F-210). The `volume_list` entry keys are checked
    /// on the first listed volume.
    private static let requiredKeys: [String: [String]] = [
        "encrypt": ["output", "size", "filename", "mode", "threshold", "total", "shares", "skipped_symlinks"],
        "decrypt": ["output", "filename", "size", "original_size", "timestamp", "renamed"],
        "volume_mount": ["mount_point", "volume_path", "journal_suspicious", "suspect_sidecar", "read_only"],
        "volume_list": ["volumes"],
        "volume_list.volumes[0]": ["mount_point", "volume_path", "read_only", "stats"],
    ]

    private static func keys(of value: JSONValue) -> Set<String> {
        if case .object(let object) = value { return Set(object.keys) }
        return []
    }

    private static func firstVolume(of result: JSONValue) -> JSONValue? {
        guard case .object(let object) = result, case .array(let volumes)? = object["volumes"] else { return nil }
        return volumes.first
    }

    /// The committed fixtures, beside this file in the source tree. They are
    /// read from source rather than from the test bundle so a fixture added
    /// without regenerating the Xcode project is still checked.
    private static var fixturesDirectory: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().appending(path: "Fixtures")
    }

    func testEveryHelperFixtureDecodesIntoItsResultStruct() throws {
        let directory = Self.fixturesDirectory
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))?
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent } ?? []
        try XCTSkipIf(files.isEmpty, """
            No helper fixtures at \(directory.path). Generate them with the dumper in \
            tests/test_service.py and commit them — until then nothing checks the Swift \
            decoders against real qc-core output.
            """)

        var exercised: Set<String> = []
        for file in files {
            let op = file.deletingPathExtension().lastPathComponent
            guard let (key, decode) = Self.decoder(for: op) else {
                XCTFail("\(file.lastPathComponent) has no decoder — add one to FixtureDecodingTests.decoders")
                continue
            }
            exercised.insert(key)
            let text = try String(contentsOf: file, encoding: .utf8)
            do {
                let result = try Self.result(from: text, op: op)
                _ = try decode(result)
                if let required = Self.requiredKeys[key] {
                    let missing = required.filter { !Self.keys(of: result).contains($0) }
                    XCTAssertEqual(missing, [], "\(file.lastPathComponent) no longer carries \(missing)")
                }
                if key == "volume_list", let required = Self.requiredKeys["volume_list.volumes[0]"] {
                    let entry = Self.firstVolume(of: result)
                    XCTAssertNotNil(entry, "volume_list.json lists no volume — dump it after the faked mount")
                    let missing = required.filter { !Self.keys(of: entry ?? .null).contains($0) }
                    XCTAssertEqual(missing, [], "volume_list entry no longer carries \(missing)")
                }
            } catch {
                XCTFail("\(file.lastPathComponent) no longer decodes: \(error)")
            }
        }

        // The loop above only walks the files that exist, so it could never
        // notice one that stopped being dumped — and three ops shipped with a
        // decoder and no fixture for exactly that reason, including
        // `volume_mount`, whose required `journal_suspicious` is the one field
        // that turns a rename on the Python side into a `protocol_error` in the
        // middle of a mount.
        let unexercised = Set(Self.decoders.keys).subtracting(exercised).sorted()
        XCTAssertEqual(unexercised, [], """
            No fixture reaches \(unexercised.joined(separator: ", ")). Dump one from real \
            helper output (tests/test_service.py::test_dump_protocol_fixtures_for_swift, \
            QC_REGEN_FIXTURES=1) and commit it, or drop the decoder if the app no longer \
            performs that op.
            """)
    }

    /// The registered key whose decoder handles `op`, and that decoder.
    private static func decoder(for op: String) -> (key: String, decode: @Sendable (JSONValue) throws -> Any)? {
        if let exact = decoders[op] { return (op, exact) }
        guard let prefix = decoders.keys.filter({ op.hasPrefix($0) }).max(by: { $0.count < $1.count }),
              let decode = decoders[prefix] else { return nil }
        return (prefix, decode)
    }

    /// The `result` of a helper `done` line. A fixture holding the bare result
    /// object is accepted too, so the dumper's shape is not load-bearing.
    private static func result(from text: String, op: String) throws -> JSONValue {
        let line = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let event = try? WireEvent.parse(line: line) {
            guard case .done(let result)? = event.coreEvent else {
                throw CoreError(code: .protocolError,
                                message: "\(op) fixture is a \(event.event) event, not a done line",
                                detail: line)
            }
            return result
        }
        return try JSONDecoder().decode(JSONValue.self, from: Data(line.utf8))
    }
}
