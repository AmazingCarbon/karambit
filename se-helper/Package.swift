// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "se-helper",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "karambit-se-helper",
            path: "Sources/se-helper",
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
                .linkedFramework("AppKit"),
            ]
        )
    ]
)
