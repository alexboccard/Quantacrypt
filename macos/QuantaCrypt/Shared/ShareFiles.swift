import CryptoKit
import Darwin
import Foundation
import UniformTypeIdentifiers

/// Writes and reads the `<stem>.share-N-of-M.txt` files the Tk encryptor
/// produces, so both UIs stay interchangeable.
///
/// Files are created exclusively (`O_CREAT|O_EXCL`, mode 0600): an earlier
/// run's shares with the same stem are the only copy of that run's key, so
/// a collision picks `<stem>_2.share-N-of-M.txt` (then `_3`, …) instead of
/// overwriting, and the caller is told so it can say where the files went.
enum ShareFiles {
    /// What the shares protect. The embedded instructions differ: a `.qcx`
    /// is opened from Decrypt, a `.qcv` is mounted from Volumes.
    enum Kind: Sendable {
        case qcxFile
        case qcvVolume
    }

    struct Context: Sendable {
        let stem: String
        let protectedName: String
        let k: Int
        let n: Int
        let kind: Kind
        /// `fingerprint(ofFileAt:)` of the protected file, when it could be
        /// read. Printed so a share can be matched to its file by more than
        /// a name that may since have been changed.
        var fingerprint: String? = nil
    }

    /// The first 64 KiB of the protected file, hashed with SHA-256 and cut
    /// to 12 hex characters.
    ///
    /// The Tk encryptor (`ui/encryptor.py`) prints exactly this —
    /// `hashlib.sha256(fh.read(65536)).hexdigest()[:12]` — so a share file
    /// written by either app names the same `.qcx` the same way. 64 KiB is
    /// deliberate: it covers the header and key material without reading a
    /// multi-gigabyte container to print one line. Nil when the file cannot
    /// be read; the share text then omits the line, as the Tk app does.
    static let fingerprintBytes = 65536
    static let fingerprintLength = 12

    static func fingerprint(ofFileAt path: String) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)),
              let data = try? (handle.read(upToCount: fingerprintBytes) ?? Data()) else { return nil }
        let hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(fingerprintLength))
    }

    /// Where the files ended up and whether the run had to be renamed.
    struct Outcome: Sendable, Equatable {
        let files: [URL]
        /// Stem actually used, or nil when the requested name was free.
        let renamedStem: String?
    }

    /// Runs `_2` … `_99` before giving up on a stem.
    static let maxRenameAttempts = 99

    static func fileName(stem: String, index: Int, total: Int) -> String {
        "\(stem).share-\(index)-of-\(total).txt"
    }

    /// One private file per share. Every file of one run shares one stem: if
    /// any `<stem>.share-…` exists, the whole run moves to `<stem>_2` and so
    /// on. Throws on the first failure; files created for that run are
    /// removed so a retry starts clean (an earlier run's files are never
    /// touched).
    @discardableResult
    static func writeIndividual(_ shares: [Share], context: Context, into directory: URL,
                                fileManager: FileManager = .default) throws -> Outcome {
        var attempt = 1
        while true {
            let stem = attempt == 1 ? context.stem : "\(context.stem)_\(attempt)"
            var written: [URL] = []
            do {
                for share in shares {
                    let url = directory.appending(path: fileName(stem: stem, index: share.index, total: context.n))
                    try createExclusive(individualText(share, context: context), at: url)
                    written.append(url)
                }
                return Outcome(files: written, renamedStem: attempt == 1 ? nil : stem)
            } catch let error as CollisionError {
                for url in written { try? fileManager.removeItem(at: url) }
                attempt += 1
                if attempt > maxRenameAttempts { throw error.asCocoaError() }
            } catch {
                for url in written { try? fileManager.removeItem(at: url) }
                throw error
            }
        }
    }

    /// All shares in one file, created exclusively; on collision the name
    /// becomes `<stem>_2.shares.txt` (or `<name>_2.<ext>` for other names).
    @discardableResult
    static func writeCombined(_ shares: [Share], context: Context, to url: URL,
                              fileManager: FileManager = .default) throws -> Outcome {
        let text = combinedText(shares, context: context)
        var attempt = 1
        while true {
            let target = attempt == 1 ? url : renamedSibling(of: url, attempt: attempt)
            do {
                try createExclusive(text, at: target)
                return Outcome(files: [target], renamedStem: attempt == 1 ? nil : target.lastPathComponent)
            } catch let error as CollisionError {
                attempt += 1
                if attempt > maxRenameAttempts { throw error.asCocoaError() }
            }
        }
    }

    /// `report.pdf.shares.txt` → `report.pdf_2.shares.txt`; any other
    /// `name.ext` → `name_2.ext`.
    static func renamedSibling(of url: URL, attempt: Int) -> URL {
        let name = url.lastPathComponent
        let directory = url.deletingLastPathComponent()
        let combinedSuffix = ".shares.txt"
        if name.hasSuffix(combinedSuffix), name.count > combinedSuffix.count {
            let stem = String(name.dropLast(combinedSuffix.count))
            return directory.appending(path: "\(stem)_\(attempt)\(combinedSuffix)")
        }
        let ext = url.pathExtension
        let base = ext.isEmpty ? name : String(name.dropLast(ext.count + 1))
        return directory.appending(path: ext.isEmpty ? "\(base)_\(attempt)" : "\(base)_\(attempt).\(ext)")
    }

    static func individualText(_ share: Share, context: Context) -> String {
        let rule = String(repeating: "=", count: 60)
        let (noun, heading) = switch context.kind {
        case .qcxFile: ("decrypt", "Encrypted file:  ")
        case .qcvVolume: ("unlock", "Encrypted volume:")
        }
        // Same label and layout as the Tk encryptor's line.
        let fingerprintLine = context.fingerprint.map { "File fingerprint:  \($0)...\n" } ?? ""
        var text = """
        QuantaCrypt Share \(share.index) of \(context.n)
        \(rule)
        \(heading) \(context.protectedName)
        \(fingerprintLine)Threshold:         Any \(context.k) of \(context.n) shares are needed to \(noun)
        \(rule)

        This file contains one of the \(context.n) keys to \(context.protectedName). \
        Either format below works — use whichever is easier.

        KEEP THIS FILE PRIVATE. Do not share it with other shareholders.

        ── QCSHARE- code (for copy-paste) ──────────────────────
        \(share.code)


        """
        if let mnemonic = share.mnemonic {
            text += """
            ── 50-word mnemonic (for offline backup) ───────────────
            \(mnemonic)


            """
        }
        switch context.kind {
        case .qcxFile:
            text += """
            ── How to decrypt ───────────────────────────────────────
            1. Collect \(context.k) share files from \(context.k) of the \(context.n) shareholders.
            2. Open QuantaCrypt, choose Decrypt, and pick the encrypted file.
            3. Load the share files, or paste each QCSHARE- code (or the 50 words).
            4. Click Decrypt file.

            """
        case .qcvVolume:
            text += """
            ── How to open the volume ───────────────────────────────
            1. Collect \(context.k) share files from \(context.k) of the \(context.n) shareholders.
            2. Open QuantaCrypt, choose Volumes, and pick the volume under Mount a volume.
            3. Choose Split key, then load the share files or paste any \(context.k) of the \(context.n) shares.
            4. Click Mount volume. The volume appears as a drive while it is mounted.

            """
        }
        return text
    }

    static func combinedText(_ shares: [Share], context: Context) -> String {
        let rule = String(repeating: "=", count: 60)
        let label = switch context.kind {
        case .qcxFile: "File:      "
        case .qcvVolume: "Volume:    "
        }
        let fingerprintLine = context.fingerprint.map { "Fingerprint (SHA-256 prefix): \($0)...\n" } ?? ""
        var text = "QuantaCrypt Key Shares\nThreshold: \(context.k) of \(context.n)\n\(label)\(context.protectedName)\n\(fingerprintLine)\(rule)\n\n"
        for share in shares {
            text += "Share \(share.index), QCSHARE- code:\n\(share.code)\n\n"
            if let mnemonic = share.mnemonic {
                text += "Share \(share.index), 50-word mnemonic:\n\(mnemonic)\n\n"
            }
            text += String(repeating: "-", count: 60) + "\n\n"
        }
        switch context.kind {
        case .qcxFile:
            text += "To decrypt: open QuantaCrypt → Decrypt, pick \(context.protectedName), and load this file.\n"
        case .qcvVolume:
            text += "To open: open QuantaCrypt → Volumes, pick \(context.protectedName) under Mount a volume, choose Split key, and load this file.\n"
        }
        return text
    }

    // MARK: Loading

    /// A share file is a few KB. Anything larger is refused before it is
    /// read, the same 1 MB cap the Tk decryptor applies, so a mis-clicked
    /// disk image never lands in a `String`.
    static let maxFileSize = 1 << 20

    /// What the open panel offers when loading shares.
    static let fileTypes: [UTType] = [.plainText, .text]

    enum LoadError: Error, Equatable {
        case tooLarge(name: String, size: Int)
        case notText(name: String)
        case unreadable(name: String)

        var message: String {
            switch self {
            case .tooLarge(let name, let size):
                return "\(name) is \(Format.bytes(size)). A share file is a few KB, so this isn't one."
            case .notText(let name):
                return "\(name) isn't a text file."
            case .unreadable(let name):
                return "\(name) couldn't be read as text."
            }
        }
    }

    /// Read one share file, refusing non-text types and files over
    /// `maxFileSize` before touching their contents.
    static func read(_ url: URL) throws -> String {
        let name = url.lastPathComponent
        let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentTypeKey])
        if let type = values?.contentType, type != .data, !type.conforms(to: .text) {
            throw LoadError.notText(name: name)
        }
        if let size = values?.fileSize, size > maxFileSize {
            throw LoadError.tooLarge(name: name, size: size)
        }
        guard let handle = try? FileHandle(forReadingFrom: url),
              let data = try? handle.read(upToCount: maxFileSize + 1) else {
            throw LoadError.unreadable(name: name)
        }
        // The size check above can be stale (a file still being written).
        if data.count > maxFileSize { throw LoadError.tooLarge(name: name, size: data.count) }
        guard let text = String(data: data, encoding: .utf8) else { throw LoadError.unreadable(name: name) }
        return text
    }

    /// Shares found across `urls`, plus one message per file that could not
    /// be used. Duplicate share strings collapse.
    static func load(_ urls: [URL]) -> (shares: [String], problems: [String]) {
        var shares: [String] = []
        var problems: [String] = []
        for url in urls {
            do {
                let result = parsed(try read(url))
                for share in result.shares where !shares.contains(share) { shares.append(share) }
                // A damaged code is the normal shape of a wrapped or truncated
                // paste, and it is dropped rather than handed back as a share.
                // Say so: the user who pasted it into an email is the only one
                // who can go and fetch an intact copy.
                if result.damagedCodes > 0 {
                    problems.append(damagedCodeMessage(name: url.lastPathComponent,
                                                       count: result.damagedCodes,
                                                       recovered: result.shares.count))
                }
            } catch let error as LoadError {
                problems.append(error.message)
            } catch {
                problems.append(LoadError.unreadable(name: url.lastPathComponent).message)
            }
        }
        return (shares, problems)
    }

    static func damagedCodeMessage(name: String, count: Int, recovered: Int) -> String {
        let codes = count == 1 ? "a QCSHARE- code that is cut short or wrapped"
                               : "\(count) QCSHARE- codes that are cut short or wrapped"
        let tail = switch recovered {
        case 0: "Nothing in it could be used. Copy the code again as one unbroken line."
        case 1: "One usable share was loaded from the rest of the file."
        default: "\(recovered) usable shares were loaded from the rest of the file."
        }
        return "\(name) holds \(codes). \(tail)"
    }

    /// Number of BIP-39 words in one share's mnemonic; the core's
    /// `MNEMONIC_WORDS_PER_SHARE`.
    static let phraseWordCount = 50

    /// Extract every share (code or 50-word phrase) from a text file's
    /// contents.
    ///
    /// Codes are taken as written. Phrases are gathered from runs of plain
    /// words and cut at the next non-word line: a run that is an exact
    /// multiple of 50 is consecutive phrases (two pasted with one newline
    /// between them, or each wrapped 8 per line with no blank line); anything
    /// else keeps its last 50 words, so a mnemonic re-wrapped at 7, 8 or 12
    /// words per line under a wordy header still loads — the old exact-50
    /// test threw those away silently, and this is the paper-backup recovery
    /// path. Case is not evidence either: a word is lower-cased before it is
    /// tested, as the core does.
    ///
    /// One deliberate divergence from the core: a phrase is dropped when a
    /// code earlier in the file has not yet been paired with one. Every file
    /// QuantaCrypt writes carries each share as a code *and* its mnemonic, and
    /// unlike the core — which owns the wordlist, converts phrases to codes
    /// and de-duplicates — nothing here can tell that the two name the same
    /// share. Emitting both would fill two fields with one share and push a
    /// real one past `total`. Extra phrases beyond the codes are unpaired, so
    /// they are returned: a file mixing codes with a retyped phrase works.
    ///
    /// Only a code that *decodes* counts, though. A share code is one ~496
    /// character line and every transport that wraps — mail, chat, a diff, an
    /// editor with wrap-on-save — cuts it in two; the fragment still starts
    /// with `QCSHARE-`. Trusting the prefix alone made the fragment stand in
    /// for the share and swallow the intact mnemonic printed underneath it,
    /// which is the one form of the share a damaged file is meant to survive
    /// on. The core skips whatever `decode_share` refuses for the same
    /// reason; `codeIdentity` is that check, minus the modulus.
    static func parse(_ contents: String) -> [String] { parsed(contents).shares }

    /// What one file yielded: the usable shares, and how many `QCSHARE-`
    /// lines had to be thrown away so the caller can say so.
    struct Parsed: Equatable, Sendable {
        var shares: [String] = []
        var damagedCodes = 0
    }

    static func parsed(_ contents: String) -> Parsed {
        let lines = contents.components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        var codes: [String] = []
        var phrases: [String] = []
        var buffer: [String] = []
        var damagedCodes = 0
        /// Codes seen so far minus phrases already attributed to one.
        var unpairedCodes = 0

        func flush() {
            defer { buffer.removeAll() }
            guard buffer.count >= phraseWordCount else { return }
            // An exact multiple of 50 is adjacent phrases; the last-50 window
            // used to keep only the second of two pasted a newline apart.
            // The core splits a run wherever a 50-word candidate passes the
            // mnemonic checksum; with no wordlist here, the exact-multiple
            // rule is the deliberate approximation, and a run a wordy header
            // pushed past 50 (50 + k words) still falls to the window.
            let runs: [ArraySlice<String>] = buffer.count % phraseWordCount == 0
                ? stride(from: 0, to: buffer.count, by: phraseWordCount).map { buffer[$0..<$0 + phraseWordCount] }
                : [buffer.suffix(phraseWordCount)]
            for run in runs {
                if unpairedCodes > 0 {
                    unpairedCodes -= 1
                    continue
                }
                phrases.append(run.joined(separator: " "))
            }
        }

        for line in lines {
            if line.uppercased().hasPrefix("QCSHARE-") {
                flush()
                guard ShareValidation.codeIdentity(line) != nil else {
                    damagedCodes += 1
                    continue
                }
                codes.append(line)
                unpairedCodes += 1
                continue
            }
            let words = line.split(separator: " ").map { String($0).lowercased() }
            let isWordLine = !words.isEmpty && words.allSatisfy { w in
                w.count >= 3 && w.unicodeScalars.allSatisfy { CharacterSet.lowercaseLetters.contains($0) }
            }
            if isWordLine {
                buffer.append(contentsOf: words)
            } else {
                flush()
            }
        }
        flush()

        if codes.isEmpty && phrases.isEmpty {
            let all = contents.split(whereSeparator: { $0.isWhitespace }).map { String($0).lowercased() }
            if all.count == phraseWordCount { phrases.append(all.joined(separator: " ")) }
        }
        return Parsed(shares: codes + phrases, damagedCodes: damagedCodes)
    }

    // MARK: Exclusive creation

    /// `open(2)` refused because the name is taken.
    private struct CollisionError: Error {
        let path: String
        func asCocoaError() -> CocoaError {
            CocoaError(.fileWriteFileExists, userInfo: [NSFilePathErrorKey: path])
        }
    }

    /// Create `url` with `O_CREAT|O_EXCL` (mode 0600) and write `text`. A
    /// name that already exists throws `CollisionError`; a write failure
    /// removes the half-written file before rethrowing.
    private static func createExclusive(_ text: String, at url: URL) throws {
        let path = url.path
        let fd = path.withCString { Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600) }
        guard fd >= 0 else {
            let code = errno
            if code == EEXIST { throw CollisionError(path: path) }
            throw CocoaError(.fileWriteUnknown, userInfo: [
                NSFilePathErrorKey: path,
                NSUnderlyingErrorKey: POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO),
            ])
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: Data(text.utf8))
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(atPath: path)
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: path, NSUnderlyingErrorKey: error])
        }
    }
}
