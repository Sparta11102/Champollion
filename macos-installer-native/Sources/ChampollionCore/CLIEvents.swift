import Foundation

/// One line of output from `champollion_cli.py install`.
public enum CLIEvent: Equatable {
    case progress(fraction: Double, text: String)
    case result(message: String, artifact: String?, report: String?)
    case error(String)
}

/// Parses a single JSON line printed by champollion_cli.py. Returns nil for blank or
/// unrecognised lines (for example Python warnings) so callers can simply skip them.
public func parseCLIEvent(_ line: String) -> CLIEvent? {
    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          let data = trimmed.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let event = object["event"] as? String
    else { return nil }

    switch event {
    case "progress":
        let fraction = (object["fraction"] as? NSNumber)?.doubleValue ?? 0
        return .progress(fraction: min(max(fraction, 0), 1), text: object["text"] as? String ?? "")
    case "result":
        return .result(message: object["message"] as? String ?? "",
                       artifact: object["artifact"] as? String,
                       report: object["report"] as? String)
    case "error":
        return .error(object["message"] as? String ?? "Unknown error")
    default:
        return nil
    }
}

/// Splits streamed output into complete lines, keeping any partial trailing line for later.
public struct LineBuffer {
    private var pending = ""
    public init() {}

    public mutating func append(_ chunk: String) -> [String] {
        pending += chunk
        var lines: [String] = []
        while let newline = pending.firstIndex(of: "\n") {
            lines.append(String(pending[pending.startIndex..<newline]))
            pending.removeSubrange(pending.startIndex...newline)
        }
        return lines
    }

    /// Whatever is left when the process exits without a final newline.
    public mutating func flush() -> String? {
        defer { pending = "" }
        return pending.isEmpty ? nil : pending
    }
}
