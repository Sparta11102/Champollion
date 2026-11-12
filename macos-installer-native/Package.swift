// swift-tools-version:5.4
// Tools version 5.4 builds with Xcode 12.5 (macOS 11) and every later Xcode.
import PackageDescription

let package = Package(
    name: "ChampollionInstaller",
    platforms: [.macOS(.v11)],
    products: [
        .executable(name: "ChampollionInstaller", targets: ["ChampollionInstaller"]),
    ],
    targets: [
        // Pure logic (CLI protocol, backend lookup); unit-tested.
        .target(name: "ChampollionCore"),
        // SwiftUI app.
        .executableTarget(name: "ChampollionInstaller", dependencies: ["ChampollionCore"]),
        .testTarget(name: "ChampollionCoreTests", dependencies: ["ChampollionCore"]),
    ]
)
