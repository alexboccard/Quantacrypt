import Foundation

/// One share field, with an identity of its own.
///
/// The rows used to be a bare `[String]` rendered with
/// `ForEach(shares.indices, id: \.self)` and `$shares[index]` — the classic
/// SwiftUI out-of-bounds shape, because the array shrinks under the view
/// (`ShareValidation.merge` drops blanks, "Remove last share" pops one) and a
/// row body evaluated against the previous index set traps. A `UUID` per row
/// means the diff is over identities, not positions.
struct ShareEntry: Identifiable, Equatable, Sendable {
    let id = UUID()
    var text: String

    init(text: String = "") { self.text = text }
}

/// Client-side mirror of the core's `normalize_shares`: trims, drops blanks,
/// checks each share is *shaped* like a QCSHARE- code or a 50-word phrase,
/// and de-duplicates by decoded identity where that can be done locally.
///
/// The BIP-39 wordlist and the checksum live in the helper, so a phrase with
/// a typo, or the same share entered once as a code and once as its phrase,
/// still gets through — the helper answers `invalid_input` with a message
/// written for the user, and the models show that text verbatim.
enum ShareValidation {
    static let phraseWordCount = 50
    static let codePrefix = "QCSHARE-"

    /// One entry as the user typed it, with its 1-based position kept so a
    /// message can name the field.
    struct Entry: Equatable {
        let position: Int
        let text: String
    }

    /// Entries with surrounding whitespace removed and blanks dropped.
    static func filled(_ shares: [String]) -> [Entry] {
        shares.enumerated().compactMap { index, raw in
            let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? nil : Entry(position: index + 1, text: text)
        }
    }

    /// The share texts to put on the wire: trimmed, blanks dropped, order kept.
    static func prepared(_ shares: [String]) -> [String] {
        filled(shares).map(\.text)
    }

    /// Shares from files appended to the non-blank fields, padded with empty
    /// fields up to `threshold` and cut at `total`.
    static func merge(_ loaded: [String], into shares: [String], threshold: Int?, total: Int?) -> [String] {
        var merged = prepared(shares)
        for share in loaded where !merged.contains(share) { merged.append(share) }
        // Never hand back fewer rows than the user is looking at. `prepared`
        // drops blanks, so loading one file into four empty-ish fields used to
        // return three rows — a field vanishing under the user's cursor, and
        // the shrink SwiftUI's index-based diffing crashed on.
        let needed = max(threshold ?? merged.count, shares.count)
        while merged.count < needed { merged.append("") }
        if let total, merged.count > total { merged = Array(merged.prefix(total)) }
        return merged
    }

    /// The same merge over identified rows: a row whose text survives keeps
    /// its identity, so what the user is typing into does not jump.
    static func merge(_ loaded: [String], into entries: [ShareEntry], threshold: Int?, total: Int?) -> [ShareEntry] {
        let merged = merge(loaded, into: entries.map(\.text), threshold: threshold, total: total)
        var reusable = entries
        return merged.map { text in
            if let index = reusable.firstIndex(where: { $0.text == text }) {
                return reusable.remove(at: index)
            }
            return ShareEntry(text: text)
        }
    }

    static func prepared(_ entries: [ShareEntry]) -> [String] { prepared(entries.map(\.text)) }

    static func message(entries: [ShareEntry], threshold: Int?) -> String? {
        message(shares: entries.map(\.text), threshold: threshold)
    }

    /// Why `share` cannot be a share, or nil when it looks like one.
    static func formatProblem(_ share: String) -> String? {
        let text = share.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.uppercased().hasPrefix(codePrefix) {
            // The helper's `decode_share` accepts the prefix in any case, as
            // every caller already routed it (review F-011).
            return codeIdentity(text) == nil
                ? "the QCSHARE- code is incomplete or has a typo; copy it again from the share file"
                : nil
        }
        let words = text.split(whereSeparator: { $0.isWhitespace })
        if words.count != phraseWordCount {
            return "expected a QCSHARE- code or a \(phraseWordCount)-word phrase, got \(words.count) word\(words.count == 1 ? "" : "s")"
        }
        if let bad = words.first(where: { !$0.unicodeScalars.allSatisfy(CharacterSet.letters.contains) }) {
            return "\"\(bad)\" isn't a word; a phrase is \(phraseWordCount) plain words separated by spaces"
        }
        return nil
    }

    /// A key that is equal for two strings naming the same share, as far as
    /// the client can tell: codes compare by their decoded payload, phrases
    /// by their lower-cased words. A code and a phrase never compare equal
    /// here — that case is left to the helper.
    static func identity(_ share: String) -> String {
        let text = share.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.uppercased().hasPrefix(codePrefix), let payload = codeIdentity(text) {
            return "code:" + payload
        }
        let words = text.split(whereSeparator: { $0.isWhitespace }).map { $0.lowercased() }
        return "phrase:" + words.joined(separator: " ")
    }

    /// The decoded JSON of a QCSHARE- code with its whitespace removed, or
    /// nil when the code is not base64-wrapped JSON carrying a share's three
    /// integer fields. Values are not interpreted: the modulus does not fit
    /// a native integer and the helper validates it anyway.
    static func codeIdentity(_ code: String) -> String? {
        let payload = String(code.dropFirst(codePrefix.count)).filter { !$0.isWhitespace }
        guard !payload.isEmpty, let data = Data(base64Encoded: payload, options: [.ignoreUnknownCharacters]),
              let text = String(data: data, encoding: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              ["index", "value", "modulus"].allSatisfy({ object[$0] is NSNumber }) else {
            return nil
        }
        return text.filter { !$0.isWhitespace }
    }

    /// The message to show instead of enabling the action, or nil when the
    /// shares are ready to send. `threshold` is the file's k; nil (the auth
    /// block could not be read) accepts any two or more.
    static func message(shares: [String], threshold: Int?) -> String? {
        let needed = max(threshold ?? 2, 1)
        let entries = filled(shares)
        if entries.count < needed {
            let empty = shares.indices.filter {
                shares[$0].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            }.map { "\($0 + 1)" }
            if empty.isEmpty {
                return "Enter \(needed) shares. \(entries.count) so far."
            }
            return "Enter \(needed) shares. Share\(empty.count == 1 ? "" : "s") \(empty.joined(separator: ", ")) \(empty.count == 1 ? "is" : "are") empty."
        }
        for entry in entries {
            if let problem = formatProblem(entry.text) {
                return "Share \(entry.position) can't be read: \(problem)."
            }
        }
        var seen: [String: Int] = [:]
        for entry in entries {
            let key = identity(entry.text)
            if let first = seen[key] {
                return "Shares \(first) and \(entry.position) are the same share."
            }
            seen[key] = entry.position
        }
        return nil
    }
}
