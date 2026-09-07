import AppKit
import XCTest
@testable import QuantaCrypt

final class ShareFilesTests: XCTestCase {
    /// A structurally real code: base64 of the JSON `crypto.encode_share`
    /// emits. `ShareFiles.parse` drops anything that does not decode, so a
    /// made-up `QCSHARE-AAAA` is no longer a stand-in for a share.
    static func code(_ index: Int) -> String {
        "QCSHARE-" + Data(#"{"index": \#(index), "value": 4242\#(index), "modulus": 6789, "threshold": 2}"#.utf8)
            .base64EncodedString()
    }

    private let shares = [
        Share(index: 1, code: ShareFilesTests.code(1), mnemonic: Array(repeating: "apple", count: 50).joined(separator: " ")),
        Share(index: 2, code: ShareFilesTests.code(2), mnemonic: nil),
        Share(index: 3, code: ShareFilesTests.code(3), mnemonic: nil),
    ]
    private let context = ShareFiles.Context(stem: "report.pdf", protectedName: "report.pdf.qcx", k: 2, n: 3, kind: .qcxFile)
    private let volumeContext = ShareFiles.Context(stem: "Vault", protectedName: "Vault.qcv", k: 2, n: 3, kind: .qcvVolume)

    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testIndividualFilesAreNamedAndPrivate() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let outcome = try ShareFiles.writeIndividual(shares, context: context, into: dir)
        XCTAssertNil(outcome.renamedStem)
        XCTAssertEqual(outcome.files.map(\.lastPathComponent),
                       ["report.pdf.share-1-of-3.txt", "report.pdf.share-2-of-3.txt", "report.pdf.share-3-of-3.txt"])
        for url in outcome.files {
            let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
            XCTAssertEqual(perms, 0o600)
        }
        let text = try String(contentsOf: outcome.files[0], encoding: .utf8)
        XCTAssertTrue(text.contains(Self.code(1)))
        XCTAssertTrue(text.contains("Any 2 of 3 shares"))
        XCTAssertTrue(text.contains("Encrypted file:"))
        XCTAssertTrue(text.contains("choose Decrypt"))
        XCTAssertEqual(ShareFiles.parse(text), [Self.code(1)])
    }

    func testIndividualFilesNeverOverwriteAnEarlierRun() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try ShareFiles.writeIndividual(shares, context: context, into: dir)
        let firstText = try String(contentsOf: first.files[1], encoding: .utf8)

        // Only one of the three names is taken: the whole second run must move.
        try FileManager.default.removeItem(at: first.files[0])
        try FileManager.default.removeItem(at: first.files[2])
        let newShares = shares.map { Share(index: $0.index, code: Self.code($0.index + 10), mnemonic: nil) }
        let second = try ShareFiles.writeIndividual(newShares, context: context, into: dir)
        XCTAssertEqual(second.renamedStem, "report.pdf_2")
        XCTAssertEqual(second.files.map(\.lastPathComponent),
                       ["report.pdf_2.share-1-of-3.txt", "report.pdf_2.share-2-of-3.txt", "report.pdf_2.share-3-of-3.txt"])
        XCTAssertEqual(try String(contentsOf: first.files[1], encoding: .utf8), firstText, "earlier run untouched")
        XCTAssertTrue(try String(contentsOf: second.files[0], encoding: .utf8).contains(Self.code(11)))
        // No stray file from the aborted first attempt of the second run.
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.files[0].path))

        let third = try ShareFiles.writeIndividual(newShares, context: context, into: dir)
        XCTAssertEqual(third.renamedStem, "report.pdf_3")
        let perms = try FileManager.default.attributesOfItem(atPath: third.files[0].path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testCombinedFileRoundTrips() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".txt")
        defer { try? FileManager.default.removeItem(at: url) }
        let outcome = try ShareFiles.writeCombined(shares, context: context, to: url)
        XCTAssertEqual(outcome.files, [url])
        XCTAssertNil(outcome.renamedStem)
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertEqual(ShareFiles.parse(text), [Self.code(1), Self.code(2), Self.code(3)])
    }

    func testCombinedFileNeverOverwrites() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "report.pdf.shares.txt")
        try Data("earlier run".utf8).write(to: url)

        let outcome = try ShareFiles.writeCombined(shares, context: context, to: url)
        XCTAssertEqual(outcome.files.map(\.lastPathComponent), ["report.pdf_2.shares.txt"])
        XCTAssertEqual(outcome.renamedStem, "report.pdf_2.shares.txt")
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "earlier run")

        let other = dir.appending(path: "keys.txt")
        try Data("x".utf8).write(to: other)
        let second = try ShareFiles.writeCombined(shares, context: context, to: other)
        XCTAssertEqual(second.files.map(\.lastPathComponent), ["keys_2.txt"])
    }

    func testVolumeSharesCarryVolumeInstructions() {
        let text = ShareFiles.individualText(shares[0], context: volumeContext)
        XCTAssertTrue(text.contains("Encrypted volume: Vault.qcv"))
        XCTAssertTrue(text.contains("choose Volumes"))
        XCTAssertTrue(text.contains("Choose Split key"))
        XCTAssertTrue(text.contains("Click Mount volume"))
        XCTAssertFalse(text.contains("choose Decrypt"))
        XCTAssertFalse(text.contains("Click Decrypt file"))
        XCTAssertEqual(ShareFiles.parse(text), [Self.code(1)])

        let combined = ShareFiles.combinedText(shares, context: volumeContext)
        XCTAssertTrue(combined.contains("Volume:    Vault.qcv"))
        XCTAssertTrue(combined.contains("Volumes"))
        XCTAssertFalse(combined.contains("Decrypt"))
        XCTAssertEqual(ShareFiles.parse(combined), [Self.code(1), Self.code(2), Self.code(3)])
    }

    // MARK: Fingerprint (F-032 / S-05)

    /// The literal values are what `ui/encryptor.py` prints:
    /// `hashlib.sha256(fh.read(65536)).hexdigest()[:12]`. Both apps' share
    /// files must name the same `.qcx` the same way.
    func testFingerprintMatchesThePythonEncryptor() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let small = dir.appending(path: "small.qcx")
        try Data("abc".utf8).write(to: small)
        // python3 -c 'import hashlib; print(hashlib.sha256(b"abc").hexdigest()[:12])'
        XCTAssertEqual(ShareFiles.fingerprint(ofFileAt: small.path), "ba7816bf8f01")

        // Only the first 64 KiB count, so a multi-gigabyte container costs
        // one read; the full-file digest would start with b80935d45c7f.
        let large = dir.appending(path: "large.qcx")
        try Data(repeating: 0x41, count: 70_000).write(to: large)
        // python3 -c 'import hashlib; print(hashlib.sha256((b"A"*70000)[:65536]).hexdigest()[:12])'
        XCTAssertEqual(ShareFiles.fingerprint(ofFileAt: large.path), "156c38442089")

        XCTAssertNil(ShareFiles.fingerprint(ofFileAt: dir.appending(path: "missing.qcx").path))
    }

    func testShareTextsCarryTheFingerprintLine() {
        var fingerprinted = context
        fingerprinted.fingerprint = "ba7816bf8f01"
        let individual = ShareFiles.individualText(shares[0], context: fingerprinted)
        XCTAssertTrue(individual.contains("Encrypted file:   report.pdf.qcx\nFile fingerprint:  ba7816bf8f01...\nThreshold:"),
                      individual)
        XCTAssertEqual(ShareFiles.parse(individual), [Self.code(1)], "the hex line must not read as a share")

        let combined = ShareFiles.combinedText(shares, context: fingerprinted)
        XCTAssertTrue(combined.contains("File:      report.pdf.qcx\nFingerprint (SHA-256 prefix): ba7816bf8f01...\n"),
                      combined)
        XCTAssertEqual(ShareFiles.parse(combined), [Self.code(1), Self.code(2), Self.code(3)])

        // A file that could not be read gets no line, as in the Tk app.
        XCTAssertFalse(ShareFiles.individualText(shares[0], context: context).contains("ingerprint"))
        XCTAssertFalse(ShareFiles.combinedText(shares, context: context).contains("ingerprint"))
    }

    func testSavedNoteMentionsRename() {
        let files = [URL(fileURLWithPath: "/tmp/x/report.pdf_2.share-1-of-3.txt")]
        let renamed = ShareFiles.Outcome(files: files, renamedStem: "report.pdf_2")
        let note = SharesSheet.savedNote(for: renamed, count: 1, location: "/tmp/x")
        XCTAssertTrue(note.contains("already existed"))
        XCTAssertTrue(note.contains("report.pdf_2.share-1-of-3.txt"))
        let plain = SharesSheet.savedNote(for: ShareFiles.Outcome(files: files, renamedStem: nil), count: 1, location: "/tmp/x")
        XCTAssertFalse(plain.contains("already existed"))
    }

    func testMnemonicOnlyFileParses() {
        let words = (0..<50).map { "word\($0 % 7 + 3)" }.map { String($0.filter { $0.isLetter }) }
        let text = "Some header\n" + words.prefix(25).joined(separator: " ") + "\n" + words.suffix(25).joined(separator: " ") + "\n"
        let parsed = ShareFiles.parse(text)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed.first?.split(separator: " ").count, 50)
    }

    // MARK: Wrapped, capitalised and mixed files (F-007)

    /// 50 words wrapped at 7 per line, under a header line that is itself made
    /// of plain words. The old parser flushed the moment the buffer reached
    /// 50 and appended only on an exact 50, so the header's words pushed the
    /// count past it and the whole phrase was discarded with no message.
    func testWrappedMnemonicUnderAWordyHeaderParses() {
        let words = Array(repeating: "apple", count: 50)
        let wrapped = stride(from: 0, to: 50, by: 7).map {
            words[$0..<min($0 + 7, 50)].joined(separator: " ")
        }.joined(separator: "\n")
        let text = "keep this file secret\n" + wrapped + "\n"
        let parsed = ShareFiles.parse(text)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed.first?.split(separator: " ").count, 50)
        XCTAssertEqual(parsed.first, words.joined(separator: " "))
    }

    /// Retyped from paper with a capital at the start of the sentence. The
    /// core lower-cases before testing each word; this used to reject the line
    /// outright.
    func testCapitalisedMnemonicParses() {
        var words = Array(repeating: "apple", count: 50)
        words[0] = "Apple"
        let text = "Share 1 of 3\n" + words.joined(separator: " ") + "\n"
        let parsed = ShareFiles.parse(text)
        XCTAssertEqual(parsed, [Array(repeating: "apple", count: 50).joined(separator: " ")])
    }

    // MARK: Adjacent mnemonics (F-010)

    /// Two phrases with only a newline between them used to arrive as one
    /// 100-word run, and the last-50 window kept only the second — "Found 1
    /// share, but this file needs 2" with no hint the first was dropped.
    func testTwoPhrasesSeparatedByOneNewlineBothParse() {
        let first = Array(repeating: "apple", count: 50).joined(separator: " ")
        let second = Array(repeating: "cabin", count: 50).joined(separator: " ")
        XCTAssertEqual(ShareFiles.parse(first + "\n" + second + "\n"), [first, second])
        let third = Array(repeating: "eagle", count: 50).joined(separator: " ")
        XCTAssertEqual(ShareFiles.parse([first, second, third].joined(separator: "\n")), [first, second, third])
    }

    /// The same two, each wrapped 8 words per line with no blank line
    /// between them: still one run, still two phrases.
    func testTwoWrappedPhrasesWithNoBlankLineBetweenBothParse() {
        func wrapped(_ word: String) -> String {
            let words = Array(repeating: word, count: 50)
            return stride(from: 0, to: 50, by: 8).map {
                words[$0..<min($0 + 8, 50)].joined(separator: " ")
            }.joined(separator: "\n")
        }
        XCTAssertEqual(ShareFiles.parse(wrapped("apple") + "\n" + wrapped("cabin") + "\n"),
                       [Array(repeating: "apple", count: 50).joined(separator: " "),
                        Array(repeating: "cabin", count: 50).joined(separator: " ")])
    }

    /// A wordy header plus one phrase is 50 + k words, not a multiple of 50,
    /// so the window rule still applies and the header is not a share.
    func testAWordyHeaderAndOnePhraseIsStillOnePhrase() {
        let phrase = Array(repeating: "apple", count: 50).joined(separator: " ")
        XCTAssertEqual(ShareFiles.parse("keep this file private and safe\n" + phrase + "\n"), [phrase])
    }

    /// Codes and phrases are no longer mutually exclusive: a file holding two
    /// generated shares plus a third one retyped as words yields all three.
    /// The two mnemonics that came with the codes are not repeated — nothing
    /// here can decode a phrase, so an unpaired-code count stands in for the
    /// core's decode-and-de-duplicate.
    func testCodesAndAnExtraPhraseAreBothReturned() {
        let phrase = Array(repeating: "apple", count: 50).joined(separator: " ")
        let other = Array(repeating: "cabin", count: 50).joined(separator: " ")
        let text = """
        QuantaCrypt Key Shares

        Share 1, QCSHARE- code:
        \(Self.code(1))

        Share 1, 50-word mnemonic:
        \(phrase)

        Share 2, QCSHARE- code:
        \(Self.code(2))

        Share 2, 50-word mnemonic:
        \(phrase)

        Share 3 (typed from the paper backup):
        \(other)
        """
        XCTAssertEqual(ShareFiles.parse(text), [Self.code(1), Self.code(2), other])
    }

    // MARK: Wrapped codes must not eat the mnemonic (F-001)

    /// A combined file mailed through something that hard-wraps long lines.
    /// Each code is cut in two; only the first half still starts with
    /// `QCSHARE-`. The mnemonic printed under each code is intact and is the
    /// whole reason it is printed — so it, not the fragment, is what loads.
    func testAWrappedCodeIsDroppedAndItsMnemonicSurvives() {
        let first = Array(repeating: "apple", count: 50).joined(separator: " ")
        let second = Array(repeating: "cabin", count: 50).joined(separator: " ")
        func wrapped(_ index: Int) -> String {
            let code = Self.code(index)
            let cut = code.index(code.startIndex, offsetBy: 28)
            return String(code[..<cut]) + "\n" + String(code[cut...])
        }
        let text = """
        QuantaCrypt Key Shares

        Share 1, QCSHARE- code:
        \(wrapped(1))

        Share 1, 50-word mnemonic:
        \(first)

        Share 2, QCSHARE- code:
        \(wrapped(2))

        Share 2, 50-word mnemonic:
        \(second)
        """
        let result = ShareFiles.parsed(text)
        XCTAssertEqual(result.shares, [first, second],
                       "the fragment is not a share, and it must not consume the phrase below it")
        XCTAssertEqual(result.damagedCodes, 2)
    }

    /// The same file with the codes intact: the mnemonics are still the
    /// paired copies and are still dropped, so the pairing counter has not
    /// simply been switched off.
    func testIntactCodesStillPairWithTheirMnemonics() {
        let phrase = Array(repeating: "apple", count: 50).joined(separator: " ")
        let text = """
        Share 1, QCSHARE- code:
        \(Self.code(1))

        Share 1, 50-word mnemonic:
        \(phrase)
        """
        XCTAssertEqual(ShareFiles.parsed(text), ShareFiles.Parsed(shares: [Self.code(1)], damagedCodes: 0))
    }

    func testLoadNamesTheFileWhoseCodeIsDamaged() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let phrase = Array(repeating: "apple", count: 50).joined(separator: " ")
        let url = dir.appending(path: "share-1.txt")
        try Data("QCSHARE-truncated\n\n\(phrase)\n".utf8).write(to: url)

        let (loaded, problems) = ShareFiles.load([url])
        XCTAssertEqual(loaded, [phrase], "a recoverable file must still load")
        XCTAssertEqual(problems.count, 1)
        let problem = try XCTUnwrap(problems.first)
        XCTAssertTrue(problem.contains("share-1.txt"))
        XCTAssertTrue(problem.contains("cut short or wrapped"))
        XCTAssertTrue(problem.contains("One usable share was loaded"))
    }

    func testAFileOfNothingButDamagedCodesSaysSo() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "broken.txt")
        try Data("QCSHARE-one\nQCSHARE-two\n".utf8).write(to: url)

        let (loaded, problems) = ShareFiles.load([url])
        XCTAssertEqual(loaded, [], "an undecodable fragment must not fill a share field")
        XCTAssertEqual(problems.first, "broken.txt holds 2 QCSHARE- codes that are cut short or wrapped. "
                       + "Nothing in it could be used. Copy the code again as one unbroken line.")
    }

    // MARK: Pasteboard (F-017)

    @MainActor
    func testCopiedSecretsAreMarkedConcealed() throws {
        // A private pasteboard: the test must not clobber what the user copied.
        let pasteboard = NSPasteboard(name: NSPasteboard.Name("QuantaCryptTests-\(UUID().uuidString)"))
        defer { pasteboard.releaseGlobally() }
        Clipboard.copy("QCSHARE-SECRET", to: pasteboard)
        XCTAssertEqual(pasteboard.string(forType: .string), "QCSHARE-SECRET")
        let item = try XCTUnwrap(pasteboard.pasteboardItems?.first)
        XCTAssertTrue(item.types.contains(Clipboard.concealedType),
                      "clipboard managers keep everything that isn't marked concealed")

        // Non-secret copies stay ordinary, so managers can still record them.
        Clipboard.copy(VolumesModel.brewCommand, expiring: false, to: pasteboard)
        XCTAssertEqual(pasteboard.string(forType: .string), VolumesModel.brewCommand)
        XCTAssertFalse(pasteboard.pasteboardItems?.first?.types.contains(Clipboard.concealedType) ?? true)
    }

    /// ⌘C on a selectable `Text` goes through AppKit, not through
    /// `Clipboard.copy`: plain `public.utf8-plain-text`, no `ConcealedType`
    /// marker, no 60-second clear — and the sheet's own body text promises
    /// the user otherwise. A SwiftUI modifier is not observable from a unit
    /// test, so this reads the source: the invariant is one line long and one
    /// line is all it takes to put back.
    func testTheSharesSheetDoesNotOfferSystemCopyOnASecret() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "QuantaCrypt/Shared/SharesSheet.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertFalse(text.contains(".textSelection("), """
            SharesSheet renders the share code and its mnemonic. Selectable text there is \
            copied by AppKit without the concealed-pasteboard marker or the clear timer, so \
            the share lands in whatever clipboard-history database is running and stays there. \
            The per-share Copy buttons go through Clipboard.copy; use those.
            """)
    }

    /// Same shape as the test above, for the same reason. `.privacySensitive()`
    /// is the one-modifier step SwiftUI offers; it is not window-level
    /// capture exclusion, and the comment beside it says so.
    func testTheSharesSheetMarksTheSharesPrivacySensitive() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "QuantaCrypt/Shared/SharesSheet.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        XCTAssertTrue(text.contains(".privacySensitive()"),
                      "the share cards are the one place the split key is rendered in full")
    }

    func testPasswordStrengthOrdering() {
        XCTAssertEqual(PasswordStrength.estimate("").level, .empty)
        XCTAssertEqual(PasswordStrength.estimate("abc").level, .weak)
        XCTAssertEqual(PasswordStrength.estimate("password123").level, .weak)
        XCTAssertLessThan(PasswordStrength.estimate("aaaaaaaaaaaa").level, PasswordStrength.estimate("correct horse battery staple").level)
        XCTAssertEqual(PasswordStrength.estimate("Tr0ub4dor&3-Jump-Over-Lazy-Dogs!").level, .strong)
    }
}
