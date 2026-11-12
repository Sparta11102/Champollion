import SwiftUI
import UniformTypeIdentifiers
import ChampollionCore

// MARK: - Steps

enum InstallStep: Hashable {
    case introduction, selectApp, license, translation, destination, installation, summary

    var title: String {
        switch self {
        case .introduction: return "Introduction"
        case .selectApp:    return "Select App"
        case .license:      return "License"
        case .translation:  return "Translation"
        case .destination:  return "Destination"
        case .installation: return "Installation"
        case .summary:      return "Summary"
        }
    }
}

enum TranslationMode: String, CaseIterable, Identifiable {
    case aot, jit
    var id: String { rawValue }

    var name: String {
        switch self {
        case .aot: return "Ahead-of-Time (AOT)"
        case .jit: return "Just-in-Time (JIT)"
        }
    }

    var detail: String {
        switch self {
        case .aot: return "Translates the app once during installation. Launches faster and runs more consistently, but installation takes longer and uses more disk space."
        case .jit: return "Translates code while the app runs. Installs instantly and uses less disk space, but the first launches may feel slower."
        }
    }
}

// MARK: - State

final class WizardModel: ObservableObject {
    @Published var step: InstallStep = .introduction
    @Published var sourceURL: URL?          // set when opened from a DMG / app / IPA, or chosen manually
    @Published var openedFromInstaller = false
    @Published var mode: TranslationMode = .aot   // AOT preselected
    @Published var agreed = false
    @Published var progress: Double = 0
    @Published var progressText = ""
    @Published var isInstalling = false
    @Published var resultMessage = ""
    @Published var errorMessage: String?
    @Published var artifactURL: URL?

    /// Destination used by the backend. Inside the user's home folder, so no admin rights are needed.
    static let destinationURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Applications/Champollion", isDirectory: true)

    var isIPA: Bool { sourceURL?.pathExtension.lowercased() == "ipa" }

    /// The manual "Select App" step only appears when the app was NOT launched from a DMG/installer.
    /// IPA files always use the IPA pipeline, so the translation-mode step is skipped for them.
    var steps: [InstallStep] {
        var s: [InstallStep] = [.introduction]
        if !openedFromInstaller { s.append(.selectApp) }
        s.append(.license)
        if !isIPA { s.append(.translation) }
        s += [.destination, .installation, .summary]
        return s
    }

    private var index: Int { steps.firstIndex(of: step) ?? 0 }

    /// Call from .onOpenURL when a DMG, app or IPA is handed to the wizard.
    func open(_ url: URL) {
        sourceURL = url
        openedFromInstaller = true
        if step == .selectApp { step = .license }
    }

    var canGoBack: Bool {
        step != .introduction && step != .summary && !isInstalling
    }

    var canContinue: Bool {
        switch step {
        case .selectApp:    return sourceURL != nil
        case .license:      return agreed
        case .installation: return false
        default:            return !isInstalling
        }
    }

    var continueTitle: String {
        switch step {
        case .license:      return "Agree"
        case .destination:  return "Install"
        case .summary:      return "Close"
        default:            return "Continue"
        }
    }

    func goBack() {
        guard index > 0 else { return }
        step = steps[index - 1]
    }

    func goForward() {
        if step == .summary { NSApp.terminate(nil); return }
        guard index + 1 < steps.count else { return }
        step = steps[index + 1]
        if step == .installation { startInstall() }
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose an app, disk image or IPA"
        var types: [UTType] = [.applicationBundle, .diskImage]
        if let ipa = UTType(filenameExtension: "ipa") { types.append(ipa) }
        panel.allowedContentTypes = types
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK { sourceURL = panel.url }
    }

    private func fail(_ message: String) {
        isInstalling = false
        errorMessage = message
        step = .summary
    }

    /// Runs the real backend (champollion_cli.py); progress and results arrive as JSON events.
    private func startInstall() {
        isInstalling = true
        progress = 0
        progressText = "Starting"
        errorMessage = nil
        resultMessage = ""

        let backend: Backend
        do {
            backend = try Backend.locate()
        } catch {
            fail(error.localizedDescription)
            return
        }

        let installMode: InstallMode = isIPA ? .ipa : (mode == .aot ? .aot : .jit)
        backend.install(mode: installMode, input: sourceURL, destination: WizardModel.destinationURL) { [weak self] event in
            guard let self = self else { return }
            switch event {
            case .progress(let fraction, let text):
                self.progress = fraction
                self.progressText = text
            case .result(let message, let artifact, _):
                self.isInstalling = false
                self.resultMessage = message
                self.artifactURL = artifact.map { URL(fileURLWithPath: $0) }
                self.progress = 1
                self.step = .summary
            case .error(let message):
                self.fail(message)
            }
        }
    }
}

// MARK: - Root view

struct InstallerWizardView: View {
    @ObservedObject var model: WizardModel

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                Sidebar(steps: model.steps, current: model.step)
                    .frame(width: 180)
                Divider()
                StepContent(model: model)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            Divider()

            HStack {
                Spacer()
                Button("Go Back") { model.goBack() }
                    .disabled(!model.canGoBack)
                Button(model.continueTitle) { model.goForward() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canContinue && model.step != .summary)
            }
            .padding(12)
        }
        .frame(minWidth: 640, maxWidth: 640, minHeight: 460, maxHeight: 460)
    }
}

// MARK: - Sidebar

struct Sidebar: View {
    let steps: [InstallStep]
    let current: InstallStep

    var body: some View {
        ZStack {
            VisualEffectBackground(material: .sidebar)

            VStack(alignment: .leading, spacing: 0) {
                // Your own branding goes here, not Apple's package icon.
                Image(systemName: "shippingbox.fill")
                    .font(.system(size: 44))
                    .foregroundColor(.accentColor)
                    .padding(.top, 28)
                    .padding(.bottom, 24)
                    .frame(maxWidth: .infinity)

                ForEach(steps, id: \.self) { step in
                    StepRow(step: step, steps: steps, current: current)
                }
                Spacer()
            }
            .padding(.horizontal, 16)
        }
    }
}

struct StepRow: View {
    let step: InstallStep
    let steps: [InstallStep]
    let current: InstallStep

    private var isCurrent: Bool { step == current }
    private var isDone: Bool {
        (steps.firstIndex(of: step) ?? 0) < (steps.firstIndex(of: current) ?? 0)
    }

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(isCurrent ? Color.accentColor : (isDone ? Color.secondary : Color.clear))
                .overlay(Circle().stroke(Color.secondary.opacity(0.6),
                                         lineWidth: isCurrent || isDone ? 0 : 1))
                .frame(width: 8, height: 8)

            Text(step.title)
                .font(.system(size: 13, weight: isCurrent ? .semibold : .regular))
                .foregroundColor(isCurrent ? .primary : .secondary)
            Spacer()
        }
        .padding(.vertical, 6)
    }
}

// MARK: - Content per step

struct StepContent: View {
    @ObservedObject var model: WizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(headline)
                .font(.title2.weight(.semibold))

            switch model.step {
            case .introduction:
                Text("Welcome to the installer. It inspects the app you choose and translates ARM64 code for this Mac.")
                    .foregroundColor(.secondary)
                Text("Translation support is early: only simple integer code is handled, so most real apps will not run yet. You will see exactly what happened at the end.")
                    .font(.callout)
                    .foregroundColor(.secondary)
                if let url = model.sourceURL {
                    Label(url.lastPathComponent, systemImage: "shippingbox")
                        .padding(.top, 4)
                }

            case .selectApp:
                SelectAppPane(model: model)

            case .license:
                ScrollView {
                    Text("Software license text goes here.")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .background(Color(NSColor.textBackgroundColor))   // Color(nsColor:) needs macOS 12; this form works on 11
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
                Toggle("I have read and agree to the license", isOn: $model.agreed)

            case .translation:
                TranslationPane(model: model)

            case .destination:
                HStack {
                    Image(systemName: "internaldrive").font(.title)
                    VStack(alignment: .leading) {
                        Text("Macintosh HD").font(.headline)
                        Text("Output goes to ~/Applications/Champollion").foregroundColor(.secondary)
                    }
                }
                if let url = model.sourceURL {
                    Text("App: \(url.lastPathComponent)  •  Mode: \(model.isIPA ? "IPA" : model.mode.name)")
                        .font(.callout)
                        .foregroundColor(.secondary)
                }

            case .installation:
                Text(model.progressText.isEmpty ? "Working…" : model.progressText)
                    .foregroundColor(.secondary)
                ProgressView(value: model.progress)
                    .progressViewStyle(.linear)

            case .summary:
                SummaryPane(model: model)
            }
            Spacer()
        }
        .padding(24)
    }

    private var headline: String {
        switch model.step {
        case .introduction: return "Welcome"
        case .selectApp:    return "Select an App to Install"
        case .license:      return "Software License Agreement"
        case .translation:  return "Choose a Translation Mode"
        case .destination:  return "Select a Destination"
        case .installation: return "Installing"
        case .summary:      return model.errorMessage == nil ? "Finished" : "The app was not installed"
        }
    }
}

// MARK: - Manual selection pane

struct SelectAppPane: View {
    @ObservedObject var model: WizardModel
    @State private var isTargeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose the app (.app), disk image (.dmg) or iOS app (.ipa) you want to install.")
                .foregroundColor(.secondary)

            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6]))
                    .foregroundColor(isTargeted ? Color.accentColor : Color.secondary.opacity(0.5))
                    .background(isTargeted ? Color.accentColor.opacity(0.08) : Color.clear)

                VStack(spacing: 8) {
                    if let url = model.sourceURL {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                            .resizable().frame(width: 48, height: 48)
                        Text(url.lastPathComponent).font(.headline)
                        Text(url.deletingLastPathComponent().path)
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        Image(systemName: "square.and.arrow.down").font(.system(size: 32))
                            .foregroundColor(.secondary)
                        Text("Drop an app, disk image or IPA here")
                            .foregroundColor(.secondary)
                    }
                    Button(model.sourceURL == nil ? "Choose…" : "Choose Another…") {
                        model.chooseFile()
                    }
                }
                .padding()
            }
            .frame(height: 170)
            .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
                guard let p = providers.first else { return false }
                _ = p.loadObject(ofClass: URL.self) { url, _ in
                    guard let url = url,
                          ["app", "dmg", "ipa"].contains(url.pathExtension.lowercased()) else { return }
                    DispatchQueue.main.async { model.sourceURL = url }
                }
                return true
            }
        }
    }
}

// MARK: - Summary

struct SummaryPane: View {
    @ObservedObject var model: WizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let error = model.errorMessage {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title).foregroundColor(.orange)
                    Text(error)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.title).foregroundColor(.green)
                    Text(model.resultMessage.isEmpty ? "Finished." : model.resultMessage)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let url = model.artifactURL {
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                }
            }
        }
    }
}

// MARK: - Translation mode pane

struct TranslationPane: View {
    @ObservedObject var model: WizardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Choose how ARM code is translated to run on this Mac.")
                .foregroundColor(.secondary)

            ForEach(TranslationMode.allCases) { mode in
                Button { model.mode = mode } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: model.mode == mode ? "largecircle.fill.circle" : "circle")
                            .foregroundColor(model.mode == mode ? Color.accentColor : .secondary)
                            .font(.title3)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(mode.name).font(.headline)
                                if mode == .aot {
                                    Text("Recommended")
                                        .font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                                        .foregroundColor(Color.accentColor)
                                }
                            }
                            Text(mode.detail)
                                .font(.callout).foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer()
                    }
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(model.mode == mode ? Color.accentColor : Color.secondary.opacity(0.3),
                                    lineWidth: model.mode == mode ? 1.5 : 1)
                    )
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }
}

// MARK: - Translucent sidebar material

struct VisualEffectBackground: NSViewRepresentable {
    let material: NSVisualEffectView.Material

    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .behindWindow
        v.state = .active
        return v
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
    }
}

// MARK: - App entry

@main
struct InstallerApp: App {
    @StateObject private var model = WizardModel()

    var body: some Scene {
        WindowGroup {
            InstallerWizardView(model: model)
                // Fired when a DMG/app is opened with this app (Open With, default handler, Quick Action).
                .onOpenURL { url in model.open(url) }
        }
        .windowStyle(.hiddenTitleBar)
    }
}
