import XCTest
@testable import QuantaCrypt

final class ShareValidationTests: XCTestCase {
    /// A real share code (index 1 of a 2-of-3 split) as the helper prints it.
    private let code = "QCSHARE-eyJpbmRleCI6IDEsICJ2YWx1ZSI6IDEyMzQ1LCAibW9kdWx1cyI6IDY3ODksICJ0aHJlc2hvbGQiOiAyfQ=="
    private let phrase = Array(repeating: "apple", count: 50).joined(separator: " ")
    private var otherCode: String {
        "QCSHARE-" + Data(#"{"index": 2, "value": 99, "modulus": 6789, "threshold": 2}"#.utf8).base64EncodedString()
    }

    func testWellFormedSharesPass() {
        XCTAssertNil(ShareValidation.formatProblem(code))
        XCTAssertNil(ShareValidation.formatProblem("  " + code + "\n"))
        XCTAssertNil(ShareValidation.formatProblem(phrase))
        XCTAssertNil(ShareValidation.formatProblem("  " + phrase.replacingOccurrences(of: " ", with: "\n  ") + "  "))
    }

    func testMalformedSharesAreNamed() {
        XCTAssertNotNil(ShareValidation.formatProblem("QCSHARE-"))
        XCTAssertNil(ShareValidation.formatProblem("qcshare-" + code.dropFirst(8)), "the prefix is case-insensitive end to end")
        XCTAssertNotNil(ShareValidation.formatProblem("QCSHARE-not base64!"))
        XCTAssertNotNil(ShareValidation.formatProblem("QCSHARE-" + Data("[1,2]".utf8).base64EncodedString()))
        XCTAssertEqual(ShareValidation.formatProblem("apple banana"),
                       "expected a QCSHARE- code or a 50-word phrase, got 2 words")
        XCTAssertEqual(ShareValidation.formatProblem("word"),
                       "expected a QCSHARE- code or a 50-word phrase, got 1 word")
        let digits = Array(repeating: "apple", count: 49).joined(separator: " ") + " 4pple"
        XCTAssertTrue(ShareValidation.formatProblem(digits)?.contains("4pple") == true)
    }

    func testMessageCountsAgainstThreshold() {
        XCTAssertEqual(ShareValidation.message(shares: ["", ""], threshold: 2), "Enter 2 shares. Shares 1, 2 are empty.")
        XCTAssertEqual(ShareValidation.message(shares: [code, ""], threshold: 2), "Enter 2 shares. Share 2 is empty.")
        XCTAssertEqual(ShareValidation.message(shares: [code, otherCode], threshold: 3), "Enter 3 shares. 2 so far.")
        XCTAssertNil(ShareValidation.message(shares: [code, otherCode], threshold: 2))
        XCTAssertNil(ShareValidation.message(shares: [code, otherCode, ""], threshold: 2))
        // Unknown threshold (auth block unreadable): two or more, the helper says the rest.
        XCTAssertNotNil(ShareValidation.message(shares: [code], threshold: nil))
        XCTAssertNil(ShareValidation.message(shares: [code, otherCode], threshold: nil))
    }

    func testMessageNamesTheUnreadableShare() {
        XCTAssertEqual(ShareValidation.message(shares: [code, "typo"], threshold: 2),
                       "Share 2 can't be read: expected a QCSHARE- code or a 50-word phrase, got 1 word.")
    }

    func testDuplicatesCompareByDecodedIdentity() {
        // Same payload, different base64 spelling of the prefix and stray whitespace.
        let spaced = "QCSHARE-" + String(code.dropFirst(8)).inserting(" ", every: 10)
        XCTAssertEqual(ShareValidation.identity(code), ShareValidation.identity(spaced))
        XCTAssertEqual(ShareValidation.message(shares: [code, spaced], threshold: 2), "Shares 1 and 2 are the same share.")
        XCTAssertEqual(ShareValidation.message(shares: [phrase, phrase.uppercased()], threshold: 2),
                       "Shares 1 and 2 are the same share.")
        XCTAssertNotEqual(ShareValidation.identity(code), ShareValidation.identity(otherCode))
        // A code and its phrase cannot be matched locally; the helper decides.
        XCTAssertNil(ShareValidation.message(shares: [code, phrase], threshold: 2))
    }

    func testPreparedTrimsAndDropsBlanks() {
        XCTAssertEqual(ShareValidation.prepared(["  a ", "", "\n", "b"]), ["a", "b"])
    }

    // MARK: Share files

    func testMergeLoadedSharesPadsToThreshold() {
        XCTAssertEqual(ShareValidation.merge(["A"], into: ["", ""], threshold: 3, total: 5), ["A", "", ""])
        XCTAssertEqual(ShareValidation.merge(["A", "B"], into: ["B", ""], threshold: 2, total: 3), ["B", "A"])
        XCTAssertEqual(ShareValidation.merge(["A", "B", "C", "D"], into: [], threshold: 2, total: 3), ["A", "B", "C"])
        XCTAssertEqual(ShareValidation.merge(["A"], into: [], threshold: nil, total: nil), ["A"])
    }

    /// F-016: `prepared` drops blanks, so a load used to hand back fewer rows
    /// than were on screen — a field disappearing under the user, and the
    /// array shrink that an index-keyed `ForEach` traps on.
    func testMergeNeverReturnsFewerRowsThanItWasGiven() {
        XCTAssertEqual(ShareValidation.merge(["A"], into: ["a", "", "", ""], threshold: 3, total: nil),
                       ["a", "A", "", ""])
        XCTAssertEqual(ShareValidation.merge([], into: ["", "", ""], threshold: nil, total: nil).count, 3)
        // The cut at `total` is the one deliberate shrink and stays.
        XCTAssertEqual(ShareValidation.merge(["A", "B", "C"], into: ["", ""], threshold: 2, total: 2), ["A", "B"])
    }

    func testMergeKeepsTheIdentityOfRowsThatSurvive() {
        let entries = [ShareEntry(text: "a"), ShareEntry(text: ""), ShareEntry(text: ""), ShareEntry(text: "")]
        let merged = ShareValidation.merge(["A"], into: entries, threshold: 3, total: nil)
        XCTAssertEqual(merged.map(\.text), ["a", "A", "", ""])
        XCTAssertEqual(merged.count, entries.count, "a row must not vanish under the view")
        XCTAssertEqual(merged[0].id, entries[0].id, "the row being typed into keeps its identity")
        XCTAssertEqual(Set(merged.map(\.id)).count, merged.count, "identities are unique")
    }

    func testEntryOverloadsMatchTheStringOnes() {
        let entries = [ShareEntry(text: "  " + code + " "), ShareEntry(text: "")]
        XCTAssertEqual(ShareValidation.prepared(entries), [code])
        XCTAssertEqual(ShareValidation.message(entries: entries, threshold: 2),
                       ShareValidation.message(shares: [code, ""], threshold: 2))
    }

    func testOversizedShareFileIsRefusedUnread() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".txt")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(count: ShareFiles.maxFileSize + 1).write(to: url)
        XCTAssertThrowsError(try ShareFiles.read(url)) { error in
            guard case ShareFiles.LoadError.tooLarge(let name, let size)? = error as? ShareFiles.LoadError else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(name, url.lastPathComponent)
            XCTAssertEqual(size, ShareFiles.maxFileSize + 1)
        }
        let result = ShareFiles.load([url])
        XCTAssertTrue(result.shares.isEmpty)
        XCTAssertEqual(result.problems.count, 1)
        XCTAssertTrue(result.problems[0].contains("share file is a few KB"))
    }

    func testNonTextShareFileIsRefused() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".png")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data([0x89, 0x50, 0x4E, 0x47]).write(to: url)
        XCTAssertThrowsError(try ShareFiles.read(url)) { error in
            XCTAssertEqual(error as? ShareFiles.LoadError, .notText(name: url.lastPathComponent))
        }
    }

    func testTextShareFileLoads() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".txt")
        defer { try? FileManager.default.removeItem(at: url) }
        try "Share 1\n\(code)\n\nShare 2\n\(otherCode)\n".write(to: url, atomically: true, encoding: .utf8)
        let result = ShareFiles.load([url, url])
        XCTAssertEqual(result.shares, [code, otherCode])
        XCTAssertTrue(result.problems.isEmpty)
    }
}

private extension String {
    func inserting(_ separator: String, every stride: Int) -> String {
        var out = ""
        for (i, ch) in enumerated() {
            if i > 0, i % stride == 0 { out += separator }
            out.append(ch)
        }
        return out
    }
}
