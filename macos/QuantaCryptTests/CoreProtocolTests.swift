import XCTest
@testable import QuantaCrypt

final class CoreProtocolTests: XCTestCase {
    func testProgressEventParses() throws {
        let line = #"{"id":"r1","event":"progress","stage":"kdf","label":"Securing password","pct":0.25,"message":"Deriving key"}"#
        let event = try WireEvent.parse(line: line).coreEvent
        XCTAssertEqual(event, .progress(CoreProgress(stage: "kdf", label: "Securing password", pct: 0.25, message: "Deriving key")))
    }

    func testProgressWithNullPct() throws {
        let line = #"{"id":"r1","event":"progress","stage":"mount","label":"Mounting","pct":null,"message":"Mounting..."}"#
        guard case .progress(let p)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not progress") }
        XCTAssertNil(p.pct)
        XCTAssertEqual(p.stage, "mount")
    }

    func testDoneEventCarriesResult() throws {
        let line = #"{"id":"r1","event":"done","result":{"version":"1.3.0","format_version":1,"platform":"darwin"}}"#
        guard case .done(let result)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not done") }
        let info: VersionInfo = try result.decoded()
        XCTAssertEqual(info.version, "1.3.0")
        XCTAssertEqual(info.formatVersion, 1)
        XCTAssertNil(info.python)
    }

    func testErrorEventMapsCode() throws {
        let line = #"{"id":"r1","event":"error","code":"wrong_credentials","message":"Wrong.","detail":"InvalidTag"}"#
        guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
        XCTAssertEqual(error.code, .wrongCredentials)
        XCTAssertEqual(error.message, "Wrong.")
        XCTAssertEqual(error.detail, "InvalidTag")
    }

    /// Every code `classify_error` in src/quantacrypt/core/errors.py can
    /// return (its docstring lists them), plus the service's own
    /// `invalid_request`. A code missing here would decode as `.internal`
    /// and lose its code-specific handling.
    func testEveryHelperErrorCodeDecodesToItsOwnCase() throws {
        let helperCodes = ["wrong_credentials", "cancelled", "invalid_request", "invalid_input", "not_found",
                           "already_exists", "permission_denied", "io", "format", "unsupported", "busy", "internal"]
        for code in helperCodes {
            let line = #"{"id":"r1","event":"error","code":"\#(code)","message":"m","detail":"d"}"#
            guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else {
                return XCTFail("not error for \(code)")
            }
            XCTAssertEqual(error.code.rawValue, code, "\(code) must map to its own case")
            if code != "internal" {
                XCTAssertNotEqual(error.code, .internal, "\(code) decoded as .internal")
            }
        }
        XCTAssertEqual(CoreError.Code(wire: "permission_denied"), .permissionDenied)
        XCTAssertEqual(CoreError.Code(wire: "already_exists"), .alreadyExists)
    }

    func testInvalidRequestGetsAppBugMessage() throws {
        let line = #"{"id":"r1","event":"error","code":"invalid_request","message":"missing 'path'","detail":"InvalidRequest"}"#
        guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
        XCTAssertEqual(error.code, .invalidRequest)
        XCTAssertTrue(error.message.contains("QuantaCrypt sent a request the helper rejected"))
        XCTAssertTrue(error.detail.contains("missing 'path'"))
        XCTAssertTrue(error.detail.contains("InvalidRequest"))
    }

    /// `invalid_input` is the user's mistake (a share with a typo, too few
    /// shares); `format` is a damaged payload. Both messages are written for
    /// the user and must reach them untouched — never the "bug in the app"
    /// text, never "wrong password".
    func testUserFacingCodesKeepTheHelperMessage() throws {
        let cases: [(code: String, expected: CoreError.Code)] = [("invalid_input", .invalidInput), ("format", .format)]
        for (code, expected) in cases {
            let line = #"{"id":"r1","event":"error","code":"\#(code)","message":"Share 2 can't be read: checksum mismatch","detail":"InvalidInput"}"#
            guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
            XCTAssertEqual(error.code, expected)
            XCTAssertEqual(error.message, "Share 2 can't be read: checksum mismatch")
            XCTAssertEqual(error.detail, "InvalidInput")
            XCTAssertFalse(error.message.contains("bug in the app"))
        }
    }

    func testUnknownErrorCodeFallsBackToInternal() throws {
        let line = #"{"id":"r1","event":"error","code":"brand_new","message":"?","detail":""}"#
        guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
        XCTAssertEqual(error.code, .internal)
    }

    func testErrorWithoutIdParses() throws {
        let line = #"{"id":null,"event":"error","code":"invalid_request","message":"bad","detail":""}"#
        let wire = try WireEvent.parse(line: line)
        XCTAssertNil(wire.id)
    }

    func testUnknownEventKindIsNil() throws {
        let line = #"{"id":"r1","event":"heartbeat"}"#
        XCTAssertNil(try WireEvent.parse(line: line).coreEvent)
    }

    func testRequestEncodingOmitsParamsForControlOps() throws {
        let line = try WireRequest(id: "a", request: .version).encodedLine()
        XCTAssertEqual(line, #"{"id":"a","op":"version"}"# + "\n")
    }

    func testEncryptRequestParams() throws {
        let req = CoreRequest.encrypt(source: "/tmp/in.txt", output: "/tmp/in.txt.qcx", credential: .splitKey(k: 3, n: 5))
        let line = try WireRequest(id: "e1", request: req).encodedLine()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        XCTAssertEqual(json["op"] as? String, "encrypt")
        let params = try XCTUnwrap(json["params"] as? [String: Any])
        XCTAssertEqual(params["mode"] as? String, "shamir")
        XCTAssertEqual(params["k"] as? Int, 3)
        XCTAssertEqual(params["n"] as? Int, 5)
        XCTAssertEqual(params["source"] as? String, "/tmp/in.txt")
        XCTAssertNil(params["password"])
        // The helper's `_int_pair` checks `isinstance(k, int)`: the raw text
        // must carry JSON integers, not `3.0` that an encoder happens to trim.
        XCTAssertTrue(line.contains(#""k":3,"#), line)
        XCTAssertTrue(line.contains(#""n":5"#), line)
        XCTAssertFalse(line.contains("3.0"), line)
    }

    func testVolumeCreateEncodesIntegerThreshold() throws {
        let line = try WireRequest(id: "v", request: .volumeCreate(path: "/v.qcv", credential: .splitKey(k: 2, n: 3))).encodedLine()
        XCTAssertEqual(line, #"{"id":"v","op":"volume_create","params":{"k":2,"mode":"shamir","n":3,"path":"/v.qcv"}}"# + "\n")
    }

    func testJSONIntegerRoundTrips() throws {
        XCTAssertEqual(JSONValue.integer(7).intValue, 7)
        XCTAssertEqual(JSONValue.integer(7).doubleValue, 7)
        XCTAssertEqual(JSONValue.number(7).intValue, 7)
        XCTAssertNil(JSONValue.number(.infinity).intValue)
        let data = try JSONEncoder().encode(JSONValue.integer(42))
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "42")
    }

    // MARK: Model message mapping

    private let passwordFile = InspectInfo(path: "/f.qcx", size: 1, version: 1, mode: "password",
                                           threshold: nil, total: nil, embedded: false)
    private let splitFile = InspectInfo(path: "/f.qcx", size: 1, version: 1, mode: "shamir",
                                        threshold: 2, total: 3, embedded: false)

    @MainActor
    func testDecryptRewritesOnlyWrongCredentials() {
        let wrong = CoreError(code: .wrongCredentials, message: "helper text", detail: "InvalidTag")
        let shown = DecryptModel.userFacingError(wrong, info: passwordFile, wrongPasswordCount: 3)
        XCTAssertTrue(shown.error.message.contains("Caps Lock"))
        XCTAssertEqual(shown.note, DecryptModel.noRecoveryNote)
        XCTAssertNil(DecryptModel.userFacingError(wrong, info: passwordFile, wrongPasswordCount: 2).note)
        XCTAssertTrue(DecryptModel.userFacingError(wrong, info: splitFile, wrongPasswordCount: 0)
            .error.message.contains("Any 2 of the 3 shares"))

        let damaged = CoreError(code: .format, message: "The file's contents are damaged. Restore it from a backup.",
                                detail: "CorruptPayload")
        let unreadable = CoreError(code: .invalidInput, message: "Share 1 can't be read: checksum mismatch",
                                   detail: "InvalidInput")
        for info in [passwordFile, splitFile] {
            for error in [damaged, unreadable] {
                let shown = DecryptModel.userFacingError(error, info: info, wrongPasswordCount: 5)
                XCTAssertEqual(shown.error, error, "\(error.code) must pass through for \(info.mode)")
                XCTAssertNil(shown.note)
                XCTAssertFalse(shown.error.message.lowercased().contains("password is incorrect"))
            }
        }
    }

    @MainActor
    func testMountRewritesOnlyWrongCredentials() {
        let wrong = CoreError(code: .wrongCredentials, message: "helper text", detail: "InvalidTag")
        XCTAssertTrue(VolumesModel.friendlyMountError(wrong, credential: .password, path: "/v.qcv")
            .message.contains("Caps Lock"))
        XCTAssertTrue(VolumesModel.friendlyMountError(wrong, credential: .shares, path: "/v.qcv")
            .message.contains("swapping in a different share"))
        let damaged = CoreError(code: .format, message: "The volume's contents are damaged.", detail: "CorruptPayload")
        let unreadable = CoreError(code: .invalidInput, message: "Need 3 different shares to unlock this volume, got 2",
                                   detail: "InvalidInput")
        for credential in VolumesModel.MountCredential.allCases {
            XCTAssertEqual(VolumesModel.friendlyMountError(damaged, credential: credential, path: "/v.qcv"), damaged)
            XCTAssertEqual(VolumesModel.friendlyMountError(unreadable, credential: credential, path: "/v.qcv"), unreadable)
        }
        let inspect = VolumesModel.inspectFailure(CoreError(code: .format, message: "File too small to be a valid .qcv volume", detail: "ValueError"))
        XCTAssertEqual(inspect.code, .format)
        XCTAssertEqual(inspect.message, "Couldn't read this volume: File too small to be a valid .qcv volume")
    }

    func testDecryptVerifyOnlyOmitsOutputDir() throws {
        let req = CoreRequest.decrypt(path: "/f.qcx", outputDir: nil, credential: .shares(["QCSHARE-1", "QCSHARE-2"]), verifyOnly: true)
        let line = try WireRequest(id: "d", request: req).encodedLine()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        let params = try XCTUnwrap(json["params"] as? [String: Any])
        XCTAssertEqual(params["verify_only"] as? Bool, true)
        XCTAssertNil(params["output_dir"])
        XCTAssertEqual(params["shares"] as? [String], ["QCSHARE-1", "QCSHARE-2"])
    }

    func testCancelRequestTargets() throws {
        let line = try WireRequest(id: "c", request: .cancel(target: "r9")).encodedLine()
        XCTAssertEqual(line, #"{"id":"c","op":"cancel","params":{"target":"r9"}}"# + "\n")
    }

    func testResultStructsDecode() throws {
        let encrypt: JSONValue = ["output": "/o.qcx", "size": 10, "filename": "o.txt", "mode": "shamir",
                                  "threshold": 2, "total": 3,
                                  "shares": [["index": 1, "code": "QCSHARE-A", "mnemonic": "a b c"]]]
        let e: EncryptResult = try encrypt.decoded()
        XCTAssertEqual(e.shares?.first?.code, "QCSHARE-A")
        XCTAssertEqual(e.threshold, 2)

        let decrypt: JSONValue = ["output": "/x_2.txt", "filename": "x.txt", "size": 5, "original_size": 5,
                                  "timestamp": 1.0, "renamed": true]
        let d: DecryptResult = try decrypt.decoded()
        XCTAssertTrue(d.renamed)

        let fuse: JSONValue = ["fuse_backend": ["ok": false, "detail": "no backend"],
                               "fusepy": ["ok": true, "detail": "installed"], "ok": false]
        let f: FuseCheck = try fuse.decoded()
        XCTAssertFalse(f.ok)
        XCTAssertEqual(f.missingSummary, "disk mounting support")

        let list: JSONValue = ["volumes": [["mount_point": "/Users/x/QuantaCrypt Volumes/v", "volume_path": "/Users/x/v.qcv",
                                            "stats": ["file_count": 2, "dir_count": 0, "total_plaintext_size": 99]]]]
        let l: VolumeListResult = try list.decoded()
        XCTAssertEqual(l.volumes.first?.name, "v")
        XCTAssertEqual(l.volumes.first?.stats?.fileCount, 2)

        let inspect: JSONValue = ["path": "/f.qcx", "size": 1, "version": 1, "mode": "shamir", "threshold": 2,
                                  "total": 3, "embedded": false]
        let i: InspectInfo = try inspect.decoded()
        XCTAssertEqual(i.protectionSummary, "Protected by a split key. Any 2 of the 3 shares unlock it.")
    }

    /// `suspect_sidecar` names the file the helper saved the unreadable
    /// journal tail to. It is null on a clean mount and absent from an older
    /// helper; both must still decode, and a flagged mount must carry the
    /// path so the alert can name it (F-003).
    func testVolumeMountResultCarriesTheSuspectSidecar() throws {
        let flagged: JSONValue = ["mount_point": "/Users/x/QuantaCrypt Volumes/v", "volume_path": "/Users/x/v.qcv",
                                  "journal_suspicious": true,
                                  "suspect_sidecar": "/Users/x/v.qcv.suspect-20260905T101500"]
        let f: VolumeMountResult = try flagged.decoded()
        XCTAssertTrue(f.journalSuspicious)
        XCTAssertEqual(f.suspectSidecar, "/Users/x/v.qcv.suspect-20260905T101500")

        let clean: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "journal_suspicious": false,
                                "suspect_sidecar": .null]
        XCTAssertNil(try clean.decoded(as: VolumeMountResult.self).suspectSidecar)

        let older: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "journal_suspicious": false]
        XCTAssertNil(try older.decoded(as: VolumeMountResult.self).suspectSidecar)
    }

    /// `read_only` says the helper served the drive `-o ro` because the
    /// container or its folder refuses writes. An older helper never sends
    /// it, and a missing flag must read as a writable mount, not as a
    /// `protocol_error` in the middle of a mount.
    func testVolumeMountResultDefaultsReadOnlyToFalse() throws {
        let readOnly: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "journal_suspicious": false,
                                   "suspect_sidecar": .null, "read_only": true]
        XCTAssertTrue(try readOnly.decoded(as: VolumeMountResult.self).readOnly)

        let writable: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "journal_suspicious": false,
                                   "suspect_sidecar": .null, "read_only": false]
        XCTAssertFalse(try writable.decoded(as: VolumeMountResult.self).readOnly)

        let older: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "journal_suspicious": false]
        XCTAssertFalse(try older.decoded(as: VolumeMountResult.self).readOnly)
    }

    /// `volume_list` entries carry `read_only` too. The value must come
    /// through as sent, and its absence (an older helper) must decode as a
    /// writable row while staying distinguishable from a reported false,
    /// since only a reported value may overrule what the model remembers
    /// from the mount result.
    func testMountedVolumeDecodesReadOnly() throws {
        let readOnly: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "stats": .null, "read_only": true]
        let flagged: MountedVolume = try readOnly.decoded()
        XCTAssertTrue(flagged.readOnly)
        XCTAssertEqual(flagged.reportedReadOnly, true)

        let writable: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "stats": .null, "read_only": false]
        let plain: MountedVolume = try writable.decoded()
        XCTAssertFalse(plain.readOnly)
        XCTAssertEqual(plain.reportedReadOnly, false)

        let older: JSONValue = ["mount_point": "/m", "volume_path": "/v.qcv", "stats": .null]
        let unreported: MountedVolume = try older.decoded()
        XCTAssertFalse(unreported.readOnly)
        XCTAssertNil(unreported.reportedReadOnly)
    }
}
