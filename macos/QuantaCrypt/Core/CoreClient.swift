import Foundation
import os

/// Owns one helper process and routes its events to the request that asked.
///
/// Every request gets an `AsyncStream<CoreEvent>`; `perform` collapses that
/// into progress callbacks plus a typed result. If the helper dies, pending
/// requests fail with `.helperExited` and the next request relaunches it.
/// Params are never logged — they carry passwords and shares.
actor CoreClient {
    typealias TransportFactory = @Sendable () throws -> any CoreTransport

    private let makeTransport: TransportFactory
    private var transport: (any CoreTransport)?
    private var generation = 0
    private var readTask: Task<Void, Never>?
    private var launching: Task<any CoreTransport, any Error>?
    private var pending: [String: AsyncStream<CoreEvent>.Continuation] = [:]
    private var counter = 0
    private var shuttingDown = false
    /// Set while `restart()` is stopping the old helper and launching the
    /// new one; requests arriving meanwhile wait for it instead of hitting
    /// the dying transport.
    private var restarting: Task<Void, Never>?
    private let idPrefix: String

    /// Number of times the helper had to be (re)launched after an exit.
    private(set) var restartCount = 0

    /// Called when the helper dies without being asked to. Lets the window
    /// show the failure instead of leaving a stale "ready" indicator up.
    private var unexpectedExitHandler: (@Sendable () -> Void)?

    func onUnexpectedExit(_ handler: @escaping @Sendable () -> Void) {
        unexpectedExitHandler = handler
    }

    /// How long a cancelled request waits for the helper's own `cancelled`
    /// event before being failed locally.
    private let cancelGrace: Duration

    /// A fixed deadline for `shutdown`, for tests. Nil — the production
    /// client — derives one per call from the mounted count, see
    /// `shutdownTimeout(mountedVolumes:)`.
    private let fixedShutdownTimeout: Duration?

    init(transportFactory: @escaping TransportFactory, cancelGrace: Duration = .seconds(5),
         shutdownTimeout: Duration? = nil) {
        self.makeTransport = transportFactory
        self.cancelGrace = cancelGrace
        self.fixedShutdownTimeout = shutdownTimeout
        self.idPrefix = String(UInt32.random(in: 0...UInt32.max), radix: 36)
    }

    /// How long `shutdown` waits for the helper's `done`. The helper cancels
    /// in-flight work and unmounts every volume *before* answering, so this
    /// has to cover that work; the EOF grace only starts once it arrives.
    /// Its worst case is the 5 s worker join plus one 30 s `diskutil
    /// unmount` per mounted volume (a file held open elsewhere makes each
    /// one wait). A flat 30 s used to SIGTERM it mid-loop with two volumes
    /// up: the rest were never saved through `unmount_volume`, and the
    /// `unmount_failed` report was never sent.
    static func shutdownTimeout(mountedVolumes: Int) -> Duration {
        .seconds(10 + 35 * max(1, mountedVolumes))
    }

    private func shutdownDeadline(mountedVolumes: Int) -> Duration {
        fixedShutdownTimeout ?? Self.shutdownTimeout(mountedVolumes: mountedVolumes)
    }

    /// Production client: resolves the helper on each launch so a Settings
    /// change takes effect after the next restart.
    static func live() -> CoreClient {
        CoreClient {
            let resolution = HelperLocator.resolve()
            guard let launch = resolution.launch else {
                throw CoreError(
                    code: .helperUnavailable,
                    message: "The encryption helper (qc-core) could not be found. Set its location in Settings, or reinstall QuantaCrypt.",
                    detail: resolution.searched.joined(separator: "\n"))
            }
            return ProcessTransport(launch: launch)
        }
    }

    var isRunning: Bool { transport != nil }

    // MARK: Requests

    /// Register a request and return its event stream. The stream finishes
    /// after `done`, `error`, or a helper exit.
    func events(for request: CoreRequest) async throws -> (id: String, events: AsyncStream<CoreEvent>) {
        if shuttingDown && request.op != "shutdown" {
            throw CoreError(code: .helperUnavailable, message: "QuantaCrypt is quitting.", detail: "")
        }
        if let restarting, request.op != "shutdown" {
            await restarting.value
        }
        counter += 1
        let id = "\(idPrefix)-\(counter)"
        let (stream, continuation) = AsyncStream<CoreEvent>.makeStream(bufferingPolicy: .unbounded)
        pending[id] = continuation

        do {
            let transport = try await ensureTransport()
            let line = try WireRequest(id: id, request: request).encodedLine()
            try await transport.send(line)
            Logger.client.debug("sent \(request.op, privacy: .public) as \(id, privacy: .public)")
        } catch {
            pending.removeValue(forKey: id)
            continuation.finish()
            throw error
        }
        return (id, stream)
    }

    /// Run a request to completion. Progress events call `progress`;
    /// `done` returns its payload; `error` throws `CoreError`. Cancelling the
    /// calling task sends a `cancel` for this request, after which the helper
    /// answers with a `cancelled` error.
    func perform(_ request: CoreRequest,
                 progress: (@Sendable (CoreProgress) -> Void)? = nil) async throws -> JSONValue {
        let (id, stream) = try await events(for: request)
        // Iterate in an unstructured task: an AsyncStream stops yielding as
        // soon as the consuming task is cancelled, but we need the helper's
        // own `cancelled` error to know nothing was written.
        let consumer = Task {
            for await event in stream {
                switch event {
                case .progress(let p):
                    progress?(p)
                case .done(let result):
                    return result
                case .error(let error):
                    throw error
                }
            }
            throw CoreError.helperExited
        }
        return try await withTaskCancellationHandler {
            try await consumer.value
        } onCancel: {
            Task {
                await self.cancel(id: id)
                await self.giveUpAfterGrace(id: id)
            }
        }
    }

    /// A helper that never acknowledges a cancel (hung worker, dead pipe)
    /// must not pin the caller forever: after `cancelGrace` the request is
    /// failed locally with a `cancelled` error.
    private func giveUpAfterGrace(id: String) async {
        try? await Task.sleep(for: cancelGrace)
        guard let continuation = pending.removeValue(forKey: id) else { return }
        Logger.client.warning("request \(id, privacy: .public) ignored cancel for \(self.cancelGrace.components.seconds, privacy: .public)s; failing locally")
        continuation.yield(.error(CoreError(
            code: .cancelled,
            message: "Cancelled, but the helper did not confirm. Check the destination before assuming nothing was written.",
            detail: "no cancelled event within \(cancelGrace.components.seconds)s")))
        continuation.finish()
    }

    func perform<T: Decodable & Sendable>(_ request: CoreRequest, as type: T.Type = T.self,
                                          progress: (@Sendable (CoreProgress) -> Void)? = nil) async throws -> T {
        let raw = try await perform(request, progress: progress)
        do {
            return try raw.decoded(as: T.self)
        } catch {
            throw CoreError(code: .protocolError,
                            message: "The helper answered in a format this version of QuantaCrypt does not understand.",
                            detail: "\(request.op): \(error)")
        }
    }

    /// Ask the helper to stop request `id`. Best effort: a request that has
    /// already finished simply reports `cancelled: false`.
    func cancel(id: String) async {
        guard pending[id] != nil, !shuttingDown, restarting == nil else { return }
        do {
            // Fire and forget: a hung helper would never answer, and the
            // caller is already waiting on the original request's stream.
            let (_, acknowledgement) = try await events(for: .cancel(target: id))
            Task { for await _ in acknowledgement {} }
        } catch {
            Logger.client.debug("cancel \(id, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Launch the helper now so the first real request does not pay for it.
    func start() async throws {
        _ = try await ensureTransport()
    }

    /// What the helper reported when it stopped.
    struct ShutdownOutcome: Sendable, Equatable {
        /// Mount points the helper could not unmount (files still open).
        var unmountFailed: [String] = []
    }

    /// Graceful stop: `shutdown` (the helper cancels work and unmounts every
    /// volume, then answers), EOF, then escalate if it hangs. Safe to call
    /// twice. `mountedVolumes` is the caller's count of what the helper has
    /// to unmount; it only sizes the wait, so an overestimate is the safe
    /// side.
    @discardableResult
    func shutdown(mountedVolumes: Int = 0) async -> ShutdownOutcome {
        shuttingDown = true
        guard let transport else { return ShutdownOutcome() }
        let gen = generation
        var outcome = ShutdownOutcome()
        var answered = false
        do {
            let result = try await withTimeout(shutdownDeadline(mountedVolumes: mountedVolumes)) {
                try await self.perform(.shutdown)
            }
            answered = true
            if case .array(let failed)? = result["unmount_failed"] {
                outcome.unmountFailed = failed.compactMap(\.stringValue)
            }
        } catch {
            Logger.client.warning("shutdown request failed: \(error.localizedDescription, privacy: .public)")
        }
        // A helper that did not answer `shutdown` inside its deadline is
        // wedged, and waiting the full EOF grace on top of that is what made
        // quit read as a hang: go to SIGTERM sooner. The grace is for the
        // helper that did answer and is finishing its last write.
        await transport.terminate(timeout: answered ? .seconds(10) : .seconds(1))
        if generation == gen { transportEnded(generation: gen) }
        return outcome
    }

    /// Stop the current helper (if any) and launch a fresh one, e.g. after the
    /// helper path changed in Settings. Pending requests fail with `.helperExited`.
    func restart(mountedVolumes: Int = 0) async {
        // A second caller joins the restart in progress rather than
        // stopping the helper the first one is about to launch.
        if let restarting {
            await restarting.value
            return
        }
        let task = Task { await performRestart(mountedVolumes: mountedVolumes) }
        restarting = task
        await task.value
        restarting = nil
    }

    private func performRestart(mountedVolumes: Int) async {
        if let transport {
            let gen = generation
            try? await withTimeout(shutdownDeadline(mountedVolumes: mountedVolumes)) {
                _ = try await self.perform(.shutdown)
            }
            await transport.terminate(timeout: .seconds(5))
            if generation == gen { transportEnded(generation: gen) }
        }
        shuttingDown = false
        do {
            try await start()
        } catch {
            Logger.client.error("restart failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: Transport lifecycle

    private func ensureTransport() async throws -> any CoreTransport {
        if let transport { return transport }
        // Actor reentrancy: a second caller arriving while `start()` is
        // suspended must wait for the same launch, not spawn a second helper.
        if let launching {
            return try await launching.value
        }
        let launch = Task<any CoreTransport, any Error> {
            let transport = try makeTransport()
            let lines = try await transport.start()
            attach(transport, lines: lines)
            return transport
        }
        launching = launch
        defer { launching = nil }
        return try await launch.value
    }

    private func attach(_ transport: any CoreTransport, lines: AsyncThrowingStream<String, any Error>) {
        generation += 1
        let gen = generation
        self.transport = transport
        readTask = Task { [weak self] in
            do {
                for try await line in lines {
                    Logger.client.debug("read loop got \(line.utf8.count, privacy: .public) bytes")
                    await self?.handle(line: line)
                }
                Logger.client.debug("read loop ended (stream finished)")
            } catch {
                Logger.client.error("helper stdout failed: \(error.localizedDescription, privacy: .public)")
            }
            await self?.transportEnded(generation: gen)
        }
    }

    private func transportEnded(generation gen: Int) {
        Logger.client.debug("transportEnded gen=\(gen, privacy: .public) current=\(self.generation, privacy: .public)")
        guard gen == generation, transport != nil else { return }
        transport = nil
        readTask = nil
        // A stop we asked for (quit or restart) is not a crash.
        if !shuttingDown && restarting == nil {
            restartCount += 1
            Logger.client.error("helper exited with \(self.pending.count, privacy: .public) request(s) pending")
            unexpectedExitHandler?()
        }
        let waiting = pending
        pending.removeAll()
        for (_, continuation) in waiting {
            continuation.yield(.error(.helperExited))
            continuation.finish()
        }
    }

    private func handle(line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let wire: WireEvent
        do {
            wire = try WireEvent.parse(line: trimmed)
        } catch {
            Logger.client.error("unparseable helper line (\(trimmed.count, privacy: .public) bytes): \(error.localizedDescription, privacy: .public)")
            return
        }
        guard let id = wire.id else {
            Logger.client.error("helper error without id: \(wire.message ?? "", privacy: .public)")
            return
        }
        Logger.client.debug("event \(wire.event, privacy: .public) for \(id, privacy: .public); pending=\(self.pending.count, privacy: .public)")
        guard let continuation = pending[id] else {
            Logger.client.debug("event for unknown request \(id, privacy: .public)")
            return
        }
        guard let event = wire.coreEvent else {
            Logger.client.debug("unknown event kind \(wire.event, privacy: .public)")
            return
        }
        continuation.yield(event)
        switch event {
        case .done, .error:
            pending.removeValue(forKey: id)
            continuation.finish()
        case .progress:
            break
        }
    }
}

/// First-wins hand-off between the work and the deadline.
///
/// Both racers call `settle`; the first one resumes the waiter and the loser
/// is dropped. `attach` copes with a racer that settled before the
/// continuation existed.
private final class TimeoutGate<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, any Error>?
    private var early: Result<T, any Error>?
    private var settled = false

    func attach(_ waiter: CheckedContinuation<T, any Error>) {
        lock.lock()
        if let early {
            self.early = nil
            lock.unlock()
            waiter.resume(with: early)
            return
        }
        continuation = waiter
        lock.unlock()
    }

    func settle(_ result: Result<T, any Error>) {
        lock.lock()
        guard !settled else { return lock.unlock() }
        settled = true
        if let waiter = continuation {
            continuation = nil
            lock.unlock()
            waiter.resume(with: result)
        } else {
            early = result
            lock.unlock()
        }
    }
}

/// Run `body`, failing with `TimeoutError` if it takes longer than `limit`.
///
/// The deadline is wall-clock: at `limit` this returns, and the body is
/// cancelled but left to drain on its own. Racing inside a
/// `withThrowingTaskGroup` — the obvious shape, and the one this replaced —
/// does not do that, because a throwing group cancels *and awaits* its
/// remaining children before rethrowing. `CoreClient.perform` deliberately
/// outlives its own cancellation by `cancelGrace` so that "cancelled" can
/// keep meaning "nothing was written", so every deadline here overshot by
/// five seconds and quit read as a hang.
func withTimeout<T: Sendable>(_ limit: Duration,
                              _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    let gate = TimeoutGate<T>()
    let work = Task {
        do { gate.settle(.success(try await body())) } catch { gate.settle(.failure(error)) }
    }
    // Unstructured, so the caller's own cancellation cannot stop the clock:
    // a cancelled caller still has to be released within `limit`.
    let deadline = Task {
        try? await Task.sleep(for: limit)
        guard !Task.isCancelled else { return }
        gate.settle(.failure(TimeoutError()))
        work.cancel()
    }
    defer { deadline.cancel() }
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { gate.attach($0) }
    } onCancel: {
        work.cancel()
    }
}

struct TimeoutError: Error, Sendable {}
