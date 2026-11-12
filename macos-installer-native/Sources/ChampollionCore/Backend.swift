import Foundation

public enum InstallMode: String, CaseIterable {
    case native, aot, jit, ipa
}

public enum BackendError: Error, LocalizedError {
    case scriptNotFound
    case pythonNotFound

    public var errorDescription: String? {
        switch self {
        case .scriptNotFound:
            return "The Champollion backend (champollion_cli.py) could not be found."
        case .pythonNotFound:
            return "Python 3 was not found. Install the Xcode Command Line Tools (xcode-select --install)."
        }
    }
}

/// Locates and runs the Python backend (`champollion_cli.py`).
public final class Backend {
    public let scriptURL: URL
    public let pythonURL: URL

    public init(scriptURL: URL, pythonURL: URL) {
        self.scriptURL = scriptURL
        self.pythonURL = pythonURL
    }

    /// Candidate locations for the backend folder, most specific first.
    public static func candidateScriptURLs(bundle: Bundle = .main,
                                           environment: [String: String] = ProcessInfo.processInfo.environment) -> [URL] {
        var urls: [URL] = []
        if let override = environment["CHAMPOLLION_BACKEND"] {
            urls.append(URL(fileURLWithPath: override).appendingPathComponent("champollion_cli.py"))
        }
        if let resources = bundle.resourceURL {
            urls.append(resources.appendingPathComponent("backend/champollion_cli.py"))
        }
        // Running from the source tree: macos-installer-native/.build/<config>/ChampollionInstaller
        if let exe = bundle.executableURL {
            var dir = exe.deletingLastPathComponent()
            for _ in 0..<5 {
                urls.append(dir.appendingPathComponent("champollion_cli.py"))
                dir.deleteLastPathComponent()
            }
        }
        return urls
    }

    public static func candidatePythonURLs() -> [URL] {
        ["/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"]
            .map { URL(fileURLWithPath: $0) }
    }

    public static func locate(fileManager: FileManager = .default,
                              bundle: Bundle = .main,
                              environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Backend {
        guard let script = candidateScriptURLs(bundle: bundle, environment: environment)
                .first(where: { fileManager.fileExists(atPath: $0.path) }) else {
            throw BackendError.scriptNotFound
        }
        guard let python = candidatePythonURLs()
                .first(where: { fileManager.isExecutableFile(atPath: $0.path) }) else {
            throw BackendError.pythonNotFound
        }
        return Backend(scriptURL: script, pythonURL: python)
    }

    /// Runs an install, streaming events on the main queue. `completion` always fires once.
    public func install(mode: InstallMode, input: URL?, destination: URL,
                        onEvent: @escaping (CLIEvent) -> Void) {
        var arguments = [scriptURL.path, "install", "--mode", mode.rawValue,
                         "--destination", destination.path]
        if let input = input { arguments += ["--input", input.path] }

        let process = Process()
        process.executableURL = pythonURL
        process.arguments = arguments
        process.currentDirectoryURL = scriptURL.deletingLastPathComponent()
        let out = Pipe()
        process.standardOutput = out
        process.standardError = Pipe()   // Python tracebacks must not reach the UI

        var buffer = LineBuffer()
        var sawFinalEvent = false
        let lock = NSLock()

        func deliver(_ line: String) {
            guard let event = parseCLIEvent(line) else { return }
            switch event {
            case .result, .error: sawFinalEvent = true
            default: break
            }
            DispatchQueue.main.async { onEvent(event) }
        }

        out.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            lock.lock(); defer { lock.unlock() }
            buffer.append(text).forEach(deliver)
        }

        process.terminationHandler = { finished in
            out.fileHandleForReading.readabilityHandler = nil
            let rest = out.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); defer { lock.unlock() }
            if let text = String(data: rest, encoding: .utf8) { buffer.append(text).forEach(deliver) }
            if let tail = buffer.flush() { deliver(tail) }
            if !sawFinalEvent {
                let message = "The backend stopped unexpectedly (exit code \(finished.terminationStatus))."
                DispatchQueue.main.async { onEvent(.error(message)) }
            }
        }

        do {
            try process.run()
        } catch {
            DispatchQueue.main.async { onEvent(.error("Could not start the backend: \(error.localizedDescription)")) }
        }
    }
}
