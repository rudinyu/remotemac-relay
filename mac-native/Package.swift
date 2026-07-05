// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RemoteMacViewer",
    platforms: [.macOS(.v12)],
    targets: [
        .target(name: "RemoteMacCore"),
        .executableTarget(name: "remotemac-viewer", dependencies: ["RemoteMacCore"]),
        .executableTarget(name: "RemoteMacViewerApp", dependencies: ["RemoteMacCore"]),
        .testTarget(name: "RemoteMacCoreTests", dependencies: ["RemoteMacCore"]),
    ]
)
