import XCTest
@testable import ChampollionCore

final class CLIEventsTests: XCTestCase {
    func testParsesProgress() {
        XCTAssertEqual(parseCLIEvent(#"{"event":"progress","fraction":0.4,"text":"Translating"}"#),
                       .progress(fraction: 0.4, text: "Translating"))
    }

    func testClampsProgress() {
        XCTAssertEqual(parseCLIEvent(#"{"event":"progress","fraction":7,"text":"x"}"#),
                       .progress(fraction: 1, text: "x"))
    }

    func testParsesResultAndError() {
        XCTAssertEqual(parseCLIEvent(#"{"event":"result","message":"ok","artifact":"/a.s"}"#),
                       .result(message: "ok", artifact: "/a.s", report: nil))
        XCTAssertEqual(parseCLIEvent(#"{"event":"error","message":"bad"}"#), .error("bad"))
    }

    func testIgnoresNoise() {
        XCTAssertNil(parseCLIEvent(""))
        XCTAssertNil(parseCLIEvent("DeprecationWarning: something"))
        XCTAssertNil(parseCLIEvent(#"{"event":"mystery"}"#))
    }

    func testLineBufferHandlesSplitChunks() {
        var buffer = LineBuffer()
        XCTAssertEqual(buffer.append("{\"a\":1}\n{\"b\""), ["{\"a\":1}"])
        XCTAssertEqual(buffer.append(":2}\n"), ["{\"b\":2}"])
        XCTAssertNil(buffer.flush())
        _ = buffer.append("partial")
        XCTAssertEqual(buffer.flush(), "partial")
    }

    func testBackendCandidatesIncludeOverrideFirst() {
        let urls = Backend.candidateScriptURLs(bundle: .main, environment: ["CHAMPOLLION_BACKEND": "/tmp/x"])
        XCTAssertEqual(urls.first?.path, "/tmp/x/champollion_cli.py")
    }
}
