import Foundation

// MARK: - Requests

/// One request to `qc-core`. Cases mirror docs/design/core-service-protocol.md.
enum CoreRequest: Sendable, Equatable {
    case version
    case ping
    case fuseCheck
    case inspect(path: String)
    case volumeInspect(path: String)
    case encrypt(source: String, output: String, credential: Credential)
    case decrypt(path: String, outputDir: String?, credential: Credential, verifyOnly: Bool)
    case volumeCreate(path: String, credential: Credential)
    case volumeMount(path: String, mountPoint: String, credential: Credential)
    case volumeUnmount(mountPoint: String)
    case volumeList
    case cancel(target: String)
    case shutdown

    /// How a file or volume is protected. Passwords and shares live only in
    /// memory and on the private stdin pipe; never log a `Credential`.
    enum Credential: Sendable, Equatable {
        case password(String)
        case splitKey(k: Int, n: Int)
        case shares([String])

        var mode: String {
            switch self {
            case .password: return "password"
            case .splitKey, .shares: return "shamir"
            }
        }
    }

    var op: String {
        switch self {
        case .version: return "version"
        case .ping: return "ping"
        case .fuseCheck: return "fuse_check"
        case .inspect: return "inspect"
        case .volumeInspect: return "volume_inspect"
        case .encrypt: return "encrypt"
        case .decrypt: return "decrypt"
        case .volumeCreate: return "volume_create"
        case .volumeMount: return "volume_mount"
        case .volumeUnmount: return "volume_unmount"
        case .volumeList: return "volume_list"
        case .cancel: return "cancel"
        case .shutdown: return "shutdown"
        }
    }

    /// True for ops the helper answers inline; they never emit progress.
    var isControl: Bool {
        switch self {
        case .version, .ping, .cancel, .shutdown: return true
        default: return false
        }
    }

    var params: [String: JSONValue]? {
        switch self {
        case .version, .ping, .fuseCheck, .volumeList, .shutdown:
            return nil
        case .inspect(let path), .volumeInspect(let path):
            return ["path": .string(path)]
        case .encrypt(let source, let output, let credential):
            var p: [String: JSONValue] = ["source": .string(source), "output": .string(output),
                                          "mode": .string(credential.mode)]
            Self.merge(credential, into: &p)
            return p
        case .decrypt(let path, let outputDir, let credential, let verifyOnly):
            var p: [String: JSONValue] = ["path": .string(path), "verify_only": .bool(verifyOnly)]
            if let outputDir { p["output_dir"] = .string(outputDir) }
            Self.merge(credential, into: &p)
            return p
        case .volumeCreate(let path, let credential):
            var p: [String: JSONValue] = ["path": .string(path), "mode": .string(credential.mode)]
            Self.merge(credential, into: &p)
            return p
        case .volumeMount(let path, let mountPoint, let credential):
            var p: [String: JSONValue] = ["path": .string(path), "mount_point": .string(mountPoint)]
            Self.merge(credential, into: &p)
            return p
        case .volumeUnmount(let mountPoint):
            return ["mount_point": .string(mountPoint)]
        case .cancel(let target):
            return ["target": .string(target)]
        }
    }

    private static func merge(_ credential: Credential, into p: inout [String: JSONValue]) {
        switch credential {
        case .password(let pw):
            p["password"] = .string(pw)
        case .splitKey(let k, let n):
            // The helper's `_int_pair` requires JSON integers; never send `3.0`.
            p["k"] = .integer(k)
            p["n"] = .integer(n)
        case .shares(let shares):
            p["shares"] = .array(shares.map(JSONValue.string))
        }
    }
}

/// The exact object written to the helper's stdin (one per line).
struct WireRequest: Encodable, Sendable {
    let id: String
    let op: String
    let params: [String: JSONValue]?

    init(id: String, request: CoreRequest) {
        self.id = id
        self.op = request.op
        self.params = request.params
    }

    func encodedLine() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard let text = String(data: data, encoding: .utf8) else {
            throw CoreError(code: .protocolError, message: "Could not encode the request.", detail: "")
        }
        return text + "\n"
    }
}

// MARK: - Events

/// One line of helper stdout, before routing.
struct WireEvent: Decodable, Sendable {
    let id: String?
    let event: String
    let stage: String?
    let label: String?
    let pct: Double?
    let message: String?
    let result: JSONValue?
    let code: String?
    let detail: String?

    static func parse(line: String) throws -> WireEvent {
        try JSONDecoder().decode(WireEvent.self, from: Data(line.utf8))
    }

    /// Typed event, or nil for event names this client does not know.
    var coreEvent: CoreEvent? {
        switch event {
        case "progress":
            return .progress(CoreProgress(stage: stage ?? "work", label: label ?? message ?? "Working…",
                                          pct: pct, message: message ?? ""))
        case "done":
            return .done(result ?? .object([:]))
        case "error":
            return .error(CoreError.fromWire(code: code, message: message, detail: detail))
        default:
            return nil
        }
    }
}

struct CoreProgress: Sendable, Equatable {
    let stage: String
    let label: String
    /// 0…1 within the stage when the core reports one.
    let pct: Double?
    let message: String
}

enum CoreEvent: Sendable, Equatable {
    case progress(CoreProgress)
    case done(JSONValue)
    case error(CoreError)
}

struct CoreError: Error, Sendable, Equatable, LocalizedError {
    enum Code: String, Sendable {
        case wrongCredentials = "wrong_credentials"
        case cancelled
        case notFound = "not_found"
        case permissionDenied = "permission_denied"
        case alreadyExists = "already_exists"
        case io
        case format
        case unsupported
        case busy
        case invalidRequest = "invalid_request"
        case invalidInput = "invalid_input"
        case `internal`
        // Client-side conditions, never sent by the helper.
        case helperUnavailable = "helper_unavailable"
        case helperExited = "helper_exited"
        case protocolError = "protocol_error"

        init(wire: String?) {
            self = wire.flatMap(Code.init(rawValue:)) ?? .internal
        }
    }

    let code: Code
    let message: String
    let detail: String

    var errorDescription: String? { message }
    var isCancellation: Bool { code == .cancelled }

    /// Build the error for a helper `error` event. Every code but one keeps
    /// the helper's message verbatim: `invalid_input` (an unreadable share,
    /// too few shares, a missing password) and `format` (a payload that
    /// failed authentication after the key was proven) are written for the
    /// user. `invalid_request` alone means the app sent something the helper
    /// could not accept (a missing or malformed parameter, or a line it
    /// could not frame) — that is our bug, so the user gets a message that
    /// says so and the helper's own text moves into the details.
    static func fromWire(code: String?, message: String?, detail: String?) -> CoreError {
        let code = Code(wire: code)
        // Never a bare "Something went wrong": if the helper sends an error
        // with no message, the user still needs a cause and a next step.
        let helperMessage = message ?? "The helper reported a problem but didn't say what. Try again. If it keeps happening, restart the helper in Settings."
        guard code == .invalidRequest else {
            return CoreError(code: code, message: helperMessage, detail: detail ?? "")
        }
        let combined = [helperMessage, detail ?? ""].filter { !$0.isEmpty }.joined(separator: ": ")
        return CoreError(code: .invalidRequest,
                         message: "QuantaCrypt sent a request the helper rejected. This is a bug in the app, not a problem with your file. Please report it.",
                         detail: combined)
    }

    static let helperExited = CoreError(
        code: .helperExited,
        message: "The encryption helper stopped unexpectedly. Try the action again; it restarts automatically.",
        detail: "qc-core exited before answering")
}

// MARK: - Results

struct VersionInfo: Decodable, Sendable, Equatable {
    let version: String
    let formatVersion: Int
    let platform: String
    let python: String?

    enum CodingKeys: String, CodingKey {
        case version, platform, python
        case formatVersion = "format_version"
    }
}

struct FuseCheck: Decodable, Sendable, Equatable {
    struct Component: Decodable, Sendable, Equatable {
        let ok: Bool
        let detail: String
    }
    let fuseBackend: Component
    let fusepy: Component
    let ok: Bool

    enum CodingKeys: String, CodingKey {
        case fusepy, ok
        case fuseBackend = "fuse_backend"
    }

    var missingSummary: String {
        var parts: [String] = []
        if !fuseBackend.ok { parts.append("disk mounting support") }
        if !fusepy.ok { parts.append("mounting helper") }
        return parts.joined(separator: " and ")
    }
}

/// What `volume_inspect` reveals about a `.qcv` without any credential.
struct VolumeInspectInfo: Decodable, Sendable, Equatable {
    let path: String
    let size: Int
    let mode: String
    let threshold: Int?
    let total: Int?
    /// Optional so an older helper still decodes. It was published as always
    /// null for the shell's whole life because nothing here consumed it and
    /// nothing there populated it — decoding it is what keeps that honest.
    let formatVersion: Int?

    enum CodingKeys: String, CodingKey {
        case path, size, mode, threshold, total
        case formatVersion = "format_version"
    }

    var isSplitKey: Bool { mode == "shamir" }

    var protectionSummary: String {
        if isSplitKey, let k = threshold, let n = total {
            return "Protected by a split key. Any \(k) of the \(n) shares unlock it."
        }
        return "Protected by a password."
    }
}

struct InspectInfo: Decodable, Sendable, Equatable {
    let path: String
    let size: Int
    let version: Int
    let mode: String
    let threshold: Int?
    let total: Int?
    let embedded: Bool

    var isSplitKey: Bool { mode == "shamir" }

    /// Plain-language protection summary for the Decrypt screen.
    var protectionSummary: String {
        if isSplitKey, let k = threshold, let n = total {
            return "Protected by a split key. Any \(k) of the \(n) shares unlock it."
        }
        return "Protected by a password."
    }
}

struct Share: Decodable, Sendable, Equatable, Identifiable {
    let index: Int
    let code: String
    let mnemonic: String?
    var id: Int { index }
}

struct EncryptResult: Decodable, Sendable, Equatable {
    let output: String
    let size: Int
    /// The plaintext's name as the helper reports it — what was encrypted,
    /// not the file a recipient will be asked to pick.
    let filename: String
    let mode: String
    let threshold: Int?
    let total: Int?
    let shares: [Share]?
    /// Links (and sockets/FIFOs) inside an encrypted folder that the helper
    /// left out of the archive, by design; the result panel names them so
    /// the omission is not discovered by the recipient (review F-202).
    let skippedSymlinks: [String]?

    enum CodingKeys: String, CodingKey {
        case output, size, filename, mode, threshold, total, shares
        case skippedSymlinks = "skipped_symlinks"
    }

    init(output: String, size: Int, filename: String, mode: String,
         threshold: Int?, total: Int?, shares: [Share]?, skippedSymlinks: [String]? = nil) {
        self.output = output; self.size = size; self.filename = filename; self.mode = mode
        self.threshold = threshold; self.total = total; self.shares = shares
        self.skippedSymlinks = skippedSymlinks
    }

    /// The same result with its key material dropped, for once the shares
    /// are proven saved and working.
    func withoutShares() -> EncryptResult {
        EncryptResult(output: output, size: size, filename: filename, mode: mode,
                      threshold: threshold, total: total, shares: nil,
                      skippedSymlinks: skippedSymlinks)
    }
}

struct VerifyResult: Decodable, Sendable, Equatable {
    let verified: Bool
    let mode: String?
}

struct DecryptResult: Decodable, Sendable, Equatable {
    let output: String
    let filename: String
    let size: Int
    let originalSize: Int?
    let timestamp: Double?
    let renamed: Bool

    enum CodingKeys: String, CodingKey {
        case output, filename, size, timestamp, renamed
        case originalSize = "original_size"
    }
}

struct VolumeCreateResult: Decodable, Sendable, Equatable {
    let path: String
    let mode: String
    let threshold: Int?
    let total: Int?
    let shares: [Share]
}

struct VolumeMountResult: Decodable, Sendable, Equatable {
    let mountPoint: String
    let volumePath: String?
    let journalSuspicious: Bool
    /// `<vault>.qcv.suspect-<stamp>`, where the helper copied the journal
    /// tail it could not verify; set only with `journalSuspicious`. Optional
    /// because an older helper never sent it. A file beside the volume that
    /// nothing names is the one the user deletes, so the alert names it.
    let suspectSidecar: String?
    /// The container or its folder refuses writes, so the helper served the
    /// drive `-o ro` instead of failing on the first save. Absent from an
    /// older helper, so it decodes as false when missing rather than making
    /// the whole result undecodable.
    let readOnly: Bool

    enum CodingKeys: String, CodingKey {
        case mountPoint = "mount_point"
        case volumePath = "volume_path"
        case journalSuspicious = "journal_suspicious"
        case suspectSidecar = "suspect_sidecar"
        case readOnly = "read_only"
    }
}

extension VolumeMountResult {
    // In an extension so the memberwise initializer stays available.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mountPoint = try c.decode(String.self, forKey: .mountPoint)
        volumePath = try c.decodeIfPresent(String.self, forKey: .volumePath)
        journalSuspicious = try c.decode(Bool.self, forKey: .journalSuspicious)
        suspectSidecar = try c.decodeIfPresent(String.self, forKey: .suspectSidecar)
        readOnly = try c.decodeIfPresent(Bool.self, forKey: .readOnly) ?? false
    }
}

struct VolumeUnmountResult: Decodable, Sendable, Equatable {
    let mountPoint: String
    enum CodingKeys: String, CodingKey { case mountPoint = "mount_point" }
}

struct MountedVolume: Decodable, Sendable, Equatable, Identifiable {
    struct Stats: Decodable, Sendable, Equatable {
        let fileCount: Int?
        let dirCount: Int?
        let totalPlaintextSize: Int?

        enum CodingKeys: String, CodingKey {
            case fileCount = "file_count"
            case dirCount = "dir_count"
            case totalPlaintextSize = "total_plaintext_size"
        }
    }
    let mountPoint: String
    let volumePath: String?
    let stats: Stats?
    /// `read_only` exactly as `volume_list` sent it, nil when the entry had
    /// no such key. Kept apart from `readOnly` because the model treats a
    /// reported value as final, and only for nil falls back to the flag it
    /// remembers from the `volume_mount` result that opened the drive (the
    /// key is new; an older helper never sends it).
    let reportedReadOnly: Bool?
    /// What the row shows: the reported flag, false when the helper sent
    /// none, until the model stamps it from its fallback.
    var readOnly: Bool

    var id: String { mountPoint }
    var name: String {
        let source = volumePath ?? mountPoint
        return URL(fileURLWithPath: source).deletingPathExtension().lastPathComponent
    }

    enum CodingKeys: String, CodingKey {
        case stats
        case mountPoint = "mount_point"
        case volumePath = "volume_path"
        case readOnly = "read_only"
    }
}

extension MountedVolume {
    /// A row the model builds itself, for the drive a `volume_mount` result
    /// just opened: nothing was listed, so nothing was reported.
    init(mountPoint: String, volumePath: String?, stats: Stats?, readOnly: Bool = false) {
        self.mountPoint = mountPoint
        self.volumePath = volumePath
        self.stats = stats
        self.reportedReadOnly = nil
        self.readOnly = readOnly
    }

    // In an extension so the memberwise initializer stays available.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mountPoint = try c.decode(String.self, forKey: .mountPoint)
        volumePath = try c.decodeIfPresent(String.self, forKey: .volumePath)
        stats = try c.decodeIfPresent(Stats.self, forKey: .stats)
        reportedReadOnly = try c.decodeIfPresent(Bool.self, forKey: .readOnly)
        readOnly = reportedReadOnly ?? false
    }
}

struct VolumeListResult: Decodable, Sendable, Equatable {
    let volumes: [MountedVolume]
}

struct CancelResult: Decodable, Sendable, Equatable {
    let cancelled: Bool
}
