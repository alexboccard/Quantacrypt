import XCTest
@testable import QuantaCrypt

/// The process boundary itself: what the helper is launched with, and how
/// its output is framed.
final class CoreTransportTests: XCTestCase {

    // MARK: Environment (supply-chain L4)

    /// The helper reads every password; the environment is where a same-user
    /// process picks the code it runs first. The app used to hand over its
    /// whole `environ`.
    func testTheHelperInheritsOnlyTheAllowListedEnvironment() {
        let parent = [
            "PATH": "/usr/bin:/bin",
            "HOME": "/Users/someone",
            "TMPDIR": "/var/folders/xx/T/",
            "LANG": "en_US.UTF-8",
            "LC_ALL": "C",
            "LC_CTYPE": "UTF-8",
            "USER": "someone",
            "LOGNAME": "someone",
            "SHELL": "/bin/zsh",
            "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
            "DYLD_LIBRARY_PATH": "/tmp",
            "DYLD_FRAMEWORK_PATH": "/tmp",
            "FUSE_LIBRARY_PATH": "/tmp/libfuse.dylib",
            "PYTHONPATH": "/tmp/sitecustomize",
            "PYTHONSTARTUP": "/tmp/startup.py",
            "PYTHONHOME": "/tmp",
            "PYTHONIOENCODING": "latin-1",
            "PYTHONUNBUFFERED": "0",
            "XPC_SERVICE_NAME": "0",
            "__CF_USER_TEXT_ENCODING": "0x1F5:0:0",
        ]
        let env = ProcessTransport.helperEnvironment(inheriting: parent)

        for key in ProcessTransport.inheritedEnvironmentKeys {
            XCTAssertEqual(env[key], parent[key], "\(key) is on the allow-list and must pass through unchanged")
        }
        // The two protocol settings are ours, whatever the parent said.
        XCTAssertEqual(env["PYTHONUNBUFFERED"], "1")
        XCTAssertEqual(env["PYTHONIOENCODING"], "utf-8")
        // And nothing else crosses: no loader, interpreter or FUSE hooks.
        let expected = ProcessTransport.inheritedEnvironmentKeys.union(["PYTHONUNBUFFERED", "PYTHONIOENCODING"])
        XCTAssertEqual(Set(env.keys), expected)
        for key in parent.keys where key.hasPrefix("DYLD_") || key == "FUSE_LIBRARY_PATH" || key == "PYTHONPATH" {
            XCTAssertNil(env[key], "\(key) must never reach the helper")
        }
    }

    func testTheAllowListIsTheDocumentedOne() {
        XCTAssertEqual(ProcessTransport.inheritedEnvironmentKeys,
                       ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME", "SHELL"])
    }

    // MARK: Line framing (S-08)

    func testLineFramerSplitsAcrossChunksAndFlushesTheTail() throws {
        var framer = LineFramer()
        XCTAssertEqual(try framer.append(Data("{\"a\":1}\n{\"b\"".utf8)), ["{\"a\":1}"])
        XCTAssertEqual(try framer.append(Data(":2}\n\n{\"c\":3}".utf8)), ["{\"b\":2}", ""])
        XCTAssertEqual(framer.flush(), "{\"c\":3}")
        XCTAssertNil(framer.flush(), "the tail is delivered once")
    }

    /// A helper that stops writing newlines used to grow the buffer for as
    /// long as it kept talking. Past the limit the transport fails instead.
    func testLineFramerRefusesALineOverTheLimit() throws {
        var framer = LineFramer(limit: 64)
        XCTAssertEqual(try framer.append(Data(repeating: 0x41, count: 40)), [])
        XCTAssertThrowsError(try framer.append(Data(repeating: 0x41, count: 40))) { error in
            guard let error = error as? CoreError else { return XCTFail("wrong error \(error)") }
            XCTAssertEqual(error.code, .protocolError)
            XCTAssertTrue(error.detail.contains("without a newline"), error.detail)
            XCTAssertTrue(error.message.contains("restarts automatically"), error.message)
        }
        XCTAssertNil(framer.flush(), "the oversized fragment is dropped, not delivered")
    }

    /// The cap is per line, not per stream: a long-running helper writes far
    /// more than 16 MiB over a session, one event at a time.
    func testManyShortLinesNeverTripTheLimit() throws {
        var framer = LineFramer(limit: 64)
        var delivered = 0
        for _ in 0..<100 {
            delivered += try framer.append(Data(repeating: 0x41, count: 60) + Data([0x0A])).count
        }
        XCTAssertEqual(delivered, 100)
        // Exactly at the limit is still fine; it is the byte after that fails.
        XCTAssertEqual(try framer.append(Data(repeating: 0x41, count: 64)), [])
        XCTAssertThrowsError(try framer.append(Data([0x41])))
    }

    // MARK: stderr privacy (run 17 F-012 / run 18 F-003, F-101)

    /// Public or private is decided per line by the helper's level prefix.
    /// The helper prefixes every line of a traceback with its record's
    /// level, so an ERROR traceback survives whole and an INFO one — the
    /// path-bearing kind — stays private; a substring never decides.
    func testStderrPublicityFollowsTheLevelPrefixLineByLine() {
        let isPublic = ProcessTransport.isPublicStderrLine
        XCTAssertTrue(isPublic("qc-core ERROR quantacrypt.core.fuse_ops: post-eject save failed: PermissionError: [Errno 13] Permission denied"))
        XCTAssertTrue(isPublic("qc-core ERROR fuse:   File \"fuse_ops.py\", line 1, in flush"))
        XCTAssertTrue(isPublic("qc-core CRITICAL quantacrypt.service: giving up"))
        XCTAssertTrue(isPublic("qc-core: unmount failed: OSError: [Errno 16] Resource busy"))
        XCTAssertTrue(isPublic("Traceback (most recent call last):"))
        XCTAssertFalse(isPublic("qc-core INFO quantacrypt.core.fuse_ops: read-only flip at /Users/a/Taxes 2025.qcv"))
        XCTAssertFalse(isPublic("qc-core INFO quantacrypt.core.fuse_ops: PermissionError: [Errno 13] Permission denied: '/Users/a/Taxes 2025.qcv'"))
        XCTAssertFalse(isPublic("qc-core WARNING quantacrypt.core.fuse_ops: Error report.docx could not be read"))
        XCTAssertFalse(isPublic("  File \"/app/fuse_ops.py\", line 1, in flush"))
        XCTAssertFalse(isPublic("PermissionError: [Errno 13] Permission denied: '/v.qcv'"))
    }

    func testTheStdoutLimitIsSixteenMebibytes() {
        XCTAssertEqual(LineFramer.maxLineBytes, 16 * 1024 * 1024)
        XCTAssertEqual(LineFramer().limit, LineFramer.maxLineBytes)
    }
}
