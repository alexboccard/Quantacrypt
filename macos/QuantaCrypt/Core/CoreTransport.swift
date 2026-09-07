import Foundation
import os

/// A byte pipe to one helper instance: send request lines, receive event lines.
/// `ProcessTransport` is the real one; tests substitute a fake.
protocol CoreTransport: Sendable {
    /// Launch the helper and return its stdout as a stream of lines. The
    /// stream ends when the helper exits.
    func start() async throws -> AsyncThrowingStream<String, any Error>
    /// Write one line (already newline-terminated) to the helper's stdin.
    func send(_ line: String) async throws
    /// Close stdin so the helper can finish gracefully.
    func closeInput() async
    /// Wait up to `timeout` for exit, then escalate SIGTERM → SIGKILL.
    func terminate(timeout: Duration) async
}

/// Where and how to launch the helper.
struct HelperLaunch: Sendable, Equatable {
    let executable: URL
    let arguments: [String]
    /// Which resolution rule produced this launch, for the status line.
    let origin: String
    /// The code hash this binary had when it was resolved, re-measured
    /// immediately before `exec`. Approved helpers and a bundled helper
    /// under the app's own signature carry one; nil for a launch whose
    /// signature was never pinned — the DEBUG-only development helpers
    /// (Python scripts) and a bundled helper signed under another identity,
    /// which is trusted by location and not re-measured.
    let approvedCDHash: Data?

    init(executable: URL, arguments: [String], origin: String, approvedCDHash: Data? = nil) {
        self.executable = executable
        self.arguments = arguments
        self.origin = origin
        self.approvedCDHash = approvedCDHash
    }

    var displayPath: String { (executable.path as NSString).abbreviatingWithTildeInPath }
}

extension Logger {
    static let helper = Logger(subsystem: "com.alexboccard.quantacrypt", category: "helper")
    static let client = Logger(subsystem: "com.alexboccard.quantacrypt", category: "core-client")
}

/// Splits a byte stream into newline-terminated lines, holding at most
/// `limit` bytes of an unfinished line.
///
/// The helper is our own binary and every line it writes is one JSON
/// event, so a line that runs past 16 MiB without a newline is not a big
/// result — it is a helper that has stopped speaking the protocol, and the
/// old reader would have kept appending to `buffer` for as long as it kept
/// talking.
struct LineFramer: Sendable {
    static let maxLineBytes = 16 << 20

    let limit: Int
    private var buffer = Data()

    init(limit: Int = LineFramer.maxLineBytes) {
        self.limit = limit
    }

    /// Feed `chunk`; returns every line completed by it, in order. Throws
    /// once the unfinished line exceeds `limit`, after which the caller
    /// should stop reading — nothing further can be framed.
    mutating func append(_ chunk: Data) throws -> [String] {
        buffer.append(chunk)
        var lines: [String] = []
        while let nl = buffer.firstIndex(of: 0x0A) {
            lines.append(String(decoding: buffer[buffer.startIndex..<nl], as: UTF8.self))
            buffer.removeSubrange(buffer.startIndex...nl)
        }
        guard buffer.count <= limit else {
            let over = buffer.count
            buffer.removeAll()
            throw CoreError(
                code: .protocolError,
                message: "The encryption helper sent more than \(limit >> 20) MB without finishing a line, so QuantaCrypt stopped it. Try the action again; it restarts automatically.",
                detail: "stdout line reached \(over) bytes without a newline (limit \(limit))")
        }
        return lines
    }

    /// The unterminated tail at EOF, if any.
    mutating func flush() -> String? {
        guard !buffer.isEmpty else { return nil }
        defer { buffer.removeAll() }
        return String(decoding: buffer, as: UTF8.self)
    }
}

/// Spawns `qc-core` with `Process` and pipes. Stdout lines are the protocol;
/// stderr is forwarded to the unified log (it never carries params).
actor ProcessTransport: CoreTransport {
    private let launch: HelperLaunch
    private var process: Process?
    private var input: FileHandle?

    init(launch: HelperLaunch) {
        self.launch = launch
    }

    // MARK: Environment

    /// The variables a helper launch inherits from the app. Nothing else
    /// crosses.
    ///
    /// Every password and share goes to the helper's stdin, and the
    /// environment is where a same-user process can decide what code that
    /// helper runs before it reads a byte: `DYLD_INSERT_LIBRARIES` picks a
    /// dylib for the loader, `PYTHONPATH` and `PYTHONSTARTUP` pick code for
    /// the interpreter, `FUSE_LIBRARY_PATH` picks the FUSE backend. The
    /// hardened runtime drops `DYLD_*` from this app's *own* process, but
    /// whatever shaped the environment the app was launched with — a
    /// LaunchAgent, `launchctl setenv`, a shell — used to reach the helper
    /// unchanged, because the launch copied `environ` wholesale. So the
    /// helper gets a search path, a home, a temp dir, a locale and an
    /// identity, plus the two Python settings the protocol depends on.
    static let inheritedEnvironmentKeys: Set<String> = [
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME", "SHELL",
    ]

    static func helperEnvironment(inheriting parent: [String: String]) -> [String: String] {
        var env = parent.filter { inheritedEnvironmentKeys.contains($0.key) }
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        return env
    }

    func start() async throws -> AsyncThrowingStream<String, any Error> {
        // A write to a pipe whose reader died raises SIGPIPE, which would kill
        // the app instead of surfacing an error.
        signal(SIGPIPE, SIG_IGN)

        try verifyStillTheApprovedBinary()

        let process = Process()
        process.executableURL = launch.executable
        process.arguments = launch.arguments
        process.environment = Self.helperEnvironment(inheriting: ProcessInfo.processInfo.environment)

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        self.process = process
        self.input = stdin.fileHandleForWriting
        Logger.client.info("helper started pid=\(process.processIdentifier, privacy: .public) via \(self.launch.origin, privacy: .public)")

        // Plain blocking reads on dedicated threads.  `FileHandle.bytes.lines`
        // proved unreliable on a pipe here (it delivered the first line or
        // nothing, depending on timing), and a helper that answers "never"
        // is the worst failure mode this client can have.
        // The helper's own ERROR-level lines are the only trace of why a
        // volume was torn down uncleanly, so they must survive the default
        // log level and stay `.public`; the helper keeps them path-free
        // (errno and strerror only) and prefixes every line of a traceback
        // with its record's level, so the rule holds line by line. Paths —
        // container, mount point, and since run 13 files inside a vault —
        // travel on INFO/WARNING/DEBUG lines, which are `.private` and so
        // redacted in a log a user hands over. Decided by the level prefix,
        // not by a substring anywhere in the line: a vault file called
        // "Error report.docx" must not make its line public.
        Self.readLines(from: stderr.fileHandleForReading, name: "stderr") { line in
            if Self.isPublicStderrLine(line) {
                Logger.helper.error("\(line, privacy: .public)")
            } else {
                Logger.helper.info("\(line, privacy: .private)")
            }
        } onEnd: { _ in }

        let outHandle = stdout.fileHandleForReading
        return AsyncThrowingStream { continuation in
            Self.readLines(from: outHandle, name: "stdout") { line in
                continuation.yield(line)
            } onEnd: { error in
                continuation.finish(throwing: error)
                // A reader that gave up on the protocol has a helper still
                // running on the other end; stop it so the next request
                // launches a fresh one rather than talking past this one.
                if error != nil {
                    Task { await self.terminate(timeout: .seconds(1)) }
                }
            }
            continuation.onTermination = { _ in try? outHandle.close() }
        }
    }

    /// Re-measure the helper immediately before `exec`.
    ///
    /// `HelperLocator.resolve()` runs once per launch and the approval it
    /// consults is per session, so between the check and `Process.run()` the
    /// file can be replaced by anything — and everything the user types is
    /// about to be written to whatever gets exec'd. `Process` takes a path,
    /// not a descriptor, so this narrows the window rather than closing it;
    /// closing it needs `fexecve`, which `Process` does not expose.
    /// Which helper stderr lines are `.public` in the unified log — see
    /// the note in `start()`. A bare `Traceback` only arrives from an
    /// interpreter that died before logging was configured.
    static func isPublicStderrLine(_ line: String) -> Bool {
        line.hasPrefix("Traceback") || line.hasPrefix("qc-core ERROR ")
            || line.hasPrefix("qc-core CRITICAL ") || line.hasPrefix("qc-core: ")
    }

    private func verifyStillTheApprovedBinary() throws {
        guard let expected = launch.approvedCDHash else { return }
        let now = HelperLocator.signatureStatus(of: launch.executable)
        guard now.cdHash == expected else {
            Logger.client.error("helper at \(self.launch.executable.path, privacy: .public) changed after it was approved")
            throw CoreError(
                code: .helperUnavailable,
                message: "The helper at \(launch.displayPath) changed since you approved it, so QuantaCrypt did not run it. Approve it again in Settings if you made the change.",
                detail: "code hash no longer matches the approved one")
        }
    }

    /// Read newline-delimited UTF-8 from `handle` on its own thread and hand
    /// each line to `onLine`; `onEnd` fires once at EOF (or with an error).
    private static func readLines(from handle: FileHandle, name: String,
                                  onLine: @escaping @Sendable (String) -> Void,
                                  onEnd: @escaping @Sendable ((any Error)?) -> Void) {
        let thread = Thread {
            var framer = LineFramer()
            while true {
                let chunk = handle.availableData   // blocks until data or EOF
                if chunk.isEmpty { break }
                do {
                    for line in try framer.append(chunk) { onLine(line) }
                } catch {
                    Logger.helper.error("\(name, privacy: .public) exceeded the line limit; closing the pipe")
                    try? handle.close()
                    onEnd(error)
                    return
                }
            }
            if let tail = framer.flush() { onLine(tail) }
            Logger.helper.debug("\(name, privacy: .public) reached EOF")
            onEnd(nil)
        }
        thread.name = "qc-core-\(name)-reader"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    func send(_ line: String) async throws {
        guard let input, let process, process.isRunning else {
            throw CoreError.helperExited
        }
        do {
            try input.write(contentsOf: Data(line.utf8))
        } catch {
            throw CoreError(code: .helperExited,
                            message: CoreError.helperExited.message,
                            detail: "stdin write failed: \(error.localizedDescription)")
        }
    }

    func closeInput() async {
        try? input?.close()
        input = nil
    }

    func terminate(timeout: Duration) async {
        guard let process else { return }
        await closeInput()
        if await Self.waitForExit(process, timeout: timeout) { return }
        Logger.client.warning("helper did not exit after EOF; sending SIGTERM")
        process.terminate()
        if await Self.waitForExit(process, timeout: .seconds(3)) { return }
        Logger.client.error("helper ignored SIGTERM; sending SIGKILL")
        kill(process.processIdentifier, SIGKILL)
        _ = await Self.waitForExit(process, timeout: .seconds(1))
    }

    private static func waitForExit(_ process: Process, timeout: Duration) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while process.isRunning {
            if clock.now >= deadline { return false }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return true
    }
}
