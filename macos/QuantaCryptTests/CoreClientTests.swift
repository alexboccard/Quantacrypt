import XCTest
@testable import QuantaCrypt

final class CoreClientTests: XCTestCase {
    /// One shared transport per client; `Holder` lets the factory hand it out.
    private final class Holder: @unchecked Sendable {
        var transports: [FakeTransport] = []
        let lock = NSLock()
        func make() -> FakeTransport {
            let t = FakeTransport()
            lock.lock(); transports.append(t); lock.unlock()
            return t
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return transports.count }
        var last: FakeTransport { lock.lock(); defer { lock.unlock() }; return transports.last! }
    }

    private func makeClient() -> (CoreClient, Holder) {
        let holder = Holder()
        let client = CoreClient { holder.make() }
        return (client, holder)
    }

    func testEventsAreRoutedByIdAcrossConcurrentRequests() async throws {
        let (client, holder) = makeClient()

        async let first: JSONValue = client.perform(.ping)
        async let second: JSONValue = client.perform(.version)

        let transport = await waitForTransport(holder)
        await transport.waitForRequests(2)
        // `async let` children start in no guaranteed order; find each by op.
        let requests = [await transport.request(0), await transport.request(1)]
        let idPing = try XCTUnwrap(requests.first { $0.op == "ping" }?.id)
        let idVersion = try XCTUnwrap(requests.first { $0.op == "version" }?.id)
        XCTAssertNotEqual(idPing, idVersion)

        // Answer out of order.
        await transport.emit(["id": idVersion, "event": "done", "result": ["version": "9.9.9", "format_version": 1, "platform": "darwin"]])
        await transport.emit(["id": idPing, "event": "done", "result": [:]])

        let pingResult = try await first
        let versionResult = try await second
        XCTAssertEqual(pingResult, .object([:]))
        XCTAssertEqual(versionResult["version"], .string("9.9.9"))
    }

    func testProgressThenDone() async throws {
        let (client, holder) = makeClient()
        let seen = ProgressSink()

        async let result: JSONValue = client.perform(.fuseCheck) { seen.append($0) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": id, "event": "progress", "stage": "kdf", "label": "Securing password", "pct": 0.5, "message": "m"])
        await transport.emit(["id": id, "event": "progress", "stage": "payload", "label": "Encrypting file", "pct": NSNull(), "message": "m2"])
        await transport.emit(["id": id, "event": "done", "result": ["ok": true]])

        let r = try await result
        XCTAssertEqual(r["ok"], .bool(true))
        XCTAssertEqual(seen.labels, ["Securing password", "Encrypting file"])
    }

    func testErrorEventThrowsCoreError() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.inspect(path: "/nope"))
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": id, "event": "error", "code": "not_found", "message": "File not found", "detail": "FileNotFoundError"])

        do {
            _ = try await result
            XCTFail("expected throw")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .notFound)
            XCTAssertEqual(error.detail, "FileNotFoundError")
        }
    }

    func testEventsForUnknownIdAreIgnored() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.ping)
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": "stranger", "event": "done", "result": ["x": 1]])
        await transport.emit("not json at all")
        await transport.emit(["id": id, "event": "done", "result": ["x": 2]])
        let r = try await result
        XCTAssertEqual(r["x"], .number(2))
    }

    func testHelperExitFailsPendingAndRestartsOnNextRequest() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.ping)
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        await transport.crash()

        do {
            _ = try await result
            XCTFail("expected helperExited")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperExited)
        }

        async let second: JSONValue = client.perform(.ping)
        while holder.count < 2 { await Task.yield() }
        let fresh = holder.last
        await fresh.waitForRequests(1)
        let freshReq = await fresh.request(0)
        let id = try XCTUnwrap(freshReq.id)
        await fresh.emit(["id": id, "event": "done", "result": [:]])
        _ = try await second
        let restarts = await client.restartCount
        XCTAssertEqual(restarts, 1)
        XCTAssertEqual(holder.count, 2)
    }

    func testTaskCancellationSendsCancelRequest() async throws {
        let (client, holder) = makeClient()
        let task = Task { try await client.perform(.encrypt(source: "/a", output: "/a.qcx", credential: .password("pw"))) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)

        task.cancel()
        await transport.waitForRequests(2)
        let cancelReq = await transport.request(1)
        XCTAssertEqual(cancelReq.op, "cancel")
        XCTAssertEqual(cancelReq.params?["target"]?.stringValue, id)

        // The helper answers the cancel, then the original request errors out.
        let cancelId = try XCTUnwrap(cancelReq.id)
        await transport.emit(["id": cancelId, "event": "done", "result": ["cancelled": true]])
        await transport.emit(["id": id, "event": "error", "code": "cancelled", "message": "Cancelled. Nothing was written.", "detail": ""])
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as CoreError {
            XCTAssertTrue(error.isCancellation)
        }
    }

    func testCancelIgnoredByHelperFailsLocallyAfterGrace() async throws {
        let holder = Holder()
        let client = CoreClient(transportFactory: { holder.make() }, cancelGrace: .milliseconds(100))
        let task = Task { try await client.perform(.encrypt(source: "/a", output: "/a.qcx", credential: .password("pw"))) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        task.cancel()
        await transport.waitForRequests(2)   // the cancel request went out; the helper never answers
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .cancelled)
            XCTAssertTrue(error.detail.contains("no cancelled event"))
        }
    }

    func testShutdownSendsShutdownThenTerminates() async throws {
        let (client, holder) = makeClient()
        try await client.start()
        let transport = await waitForTransport(holder)
        let shutdownTask = Task { await client.shutdown() }
        await transport.waitForRequests(1)
        let req = await transport.request(0)
        XCTAssertEqual(req.op, "shutdown")
        await transport.emit(["id": req.id!, "event": "done", "result": [:]])
        _ = await shutdownTask.value
        let terminated = await transport.terminated
        XCTAssertTrue(terminated)
        let running = await client.isRunning
        XCTAssertFalse(running)

        do {
            _ = try await client.perform(.ping)
            XCTFail("requests after shutdown must fail")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperUnavailable)
        }
    }

    func testShutdownReportsUnmountFailures() async throws {
        let (client, holder) = makeClient()
        try await client.start()
        let transport = await waitForTransport(holder)
        let shutdownTask = Task { await client.shutdown() }
        await transport.waitForRequests(1)
        let req = await transport.request(0)
        await transport.emit(["id": req.id!, "event": "done",
                              "result": ["unmount_failed": ["/Users/x/QuantaCrypt Volumes/Vault"]]])
        let outcome = await shutdownTask.value
        XCTAssertEqual(outcome.unmountFailed, ["/Users/x/QuantaCrypt Volumes/Vault"])
    }

    func testRestartHoldsRequestsForTheNewHelperAndIsNotACrash() async throws {
        let (client, holder) = makeClient()
        try await client.start()
        let old = await waitForTransport(holder)

        let restartTask = Task { await client.restart() }
        await old.waitForRequests(1)
        let shutdownReq = await old.request(0)
        XCTAssertEqual(shutdownReq.op, "shutdown")

        // Arrives while the old helper is being stopped: it must wait for
        // the new one, not be written to the dying pipe.
        let pingTask = Task { try await client.perform(.ping) }
        try await Task.sleep(for: .milliseconds(50))
        let oldSent = await old.sent.count
        XCTAssertEqual(oldSent, 1, "only the shutdown went to the old helper")

        await old.emit(["id": shutdownReq.id!, "event": "done", "result": [:]])
        await restartTask.value
        XCTAssertEqual(holder.count, 2)
        let fresh = holder.last
        await fresh.waitForRequests(1)
        let pingReq = await fresh.request(0)
        XCTAssertEqual(pingReq.op, "ping")
        await fresh.emit(["id": pingReq.id!, "event": "done", "result": ["pong": true]])
        let result = try await pingTask.value
        XCTAssertEqual(result["pong"], .bool(true))

        let restarts = await client.restartCount
        XCTAssertEqual(restarts, 0, "a requested restart is not a crash")
        let oldTerminated = await old.terminated
        XCTAssertTrue(oldTerminated)
    }

    // MARK: withTimeout bounds the clock, not just the error (F-018)

    func testWithTimeoutReturnsOnTheDeadlineEvenWhenTheBodyIgnoresCancellation() async {
        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await withTimeout(.milliseconds(100)) { await uncancellable(after: 3) }
            XCTFail("expected the deadline to fire")
        } catch is TimeoutError {
        } catch {
            XCTFail("wrong error \(error)")
        }
        // The task-group version waited for the abandoned body and returned
        // three seconds late; this is the guarantee its callers document.
        XCTAssertLessThan(start.duration(to: clock.now), .seconds(1))
    }

    func testWithTimeoutStillReturnsTheValueAndPropagatesErrors() async throws {
        let value = try await withTimeout(.seconds(5)) { 42 }
        XCTAssertEqual(value, 42)
        do {
            _ = try await withTimeout(.seconds(5)) { () -> Int in
                throw CoreError(code: .io, message: "boom", detail: "")
            }
            XCTFail("expected the body's own error")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .io)
        }
    }

    func testAWedgedHelperIsNotGivenTheFullEofGraceOnTopOfTheTimeout() async throws {
        let holder = Holder()
        let client = CoreClient(transportFactory: { holder.make() }, cancelGrace: .milliseconds(50),
                                shutdownTimeout: .milliseconds(100))
        try await client.start()
        let transport = await waitForTransport(holder)
        // No answer to `shutdown`, ever.
        _ = await client.shutdown()
        let waited = await transport.terminateTimeout
        XCTAssertEqual(waited, .seconds(1), "a helper that ignored shutdown has already had its chance")
    }

    func testAHelperThatAnsweredShutdownKeepsTheFullEofGrace() async throws {
        let (client, holder) = makeClient()
        try await client.start()
        let transport = await waitForTransport(holder)
        let shutdownTask = Task { await client.shutdown() }
        await transport.waitForRequests(1)
        let req = await transport.request(0)
        await transport.emit(["id": req.id!, "event": "done", "result": [:]])
        _ = await shutdownTask.value
        let waited = await transport.terminateTimeout
        XCTAssertEqual(waited, .seconds(10))
    }

    /// The helper's teardown is a 5 s join plus up to 30 s per wedged
    /// `diskutil unmount`, one per mounted volume; a flat 30 s SIGTERMed it
    /// mid-loop with two volumes up (F-006).
    func testTheShutdownDeadlineGrowsWithEachMountedVolume() {
        XCTAssertEqual(CoreClient.shutdownTimeout(mountedVolumes: 0), .seconds(45))
        XCTAssertEqual(CoreClient.shutdownTimeout(mountedVolumes: 1), .seconds(45))
        XCTAssertEqual(CoreClient.shutdownTimeout(mountedVolumes: 2), .seconds(80))
        XCTAssertEqual(CoreClient.shutdownTimeout(mountedVolumes: 3), .seconds(115))
    }

    func testTransportFactoryFailureSurfacesAsCoreError() async {
        let client = CoreClient {
            throw CoreError(code: .helperUnavailable, message: "missing", detail: "searched")
        }
        do {
            _ = try await client.perform(.ping)
            XCTFail("expected throw")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperUnavailable)
        } catch {
            XCTFail("wrong error \(error)")
        }
    }

    // MARK: Helpers

    private func waitForTransport(_ holder: Holder) async -> FakeTransport {
        while holder.count == 0 { await Task.yield() }
        return holder.last
    }
}

/// Thread-safe collector for progress callbacks.
private final class ProgressSink: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [CoreProgress] = []
    func append(_ p: CoreProgress) { lock.lock(); items.append(p); lock.unlock() }
    var labels: [String] { lock.lock(); defer { lock.unlock() }; return items.map(\.label) }
}

/// A body that cannot be cancelled — the shape `CoreClient.perform` takes while
/// it waits out `cancelGrace` for the helper's own `cancelled` event.
private func uncancellable(after seconds: Double) async -> Int {
    await withCheckedContinuation { continuation in
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
            continuation.resume(returning: 1)
        }
    }
}
