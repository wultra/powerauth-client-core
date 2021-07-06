// swift-tools-version:5.4
import PackageDescription

let package = Package(
    name: "PowerAuthCore",
    platforms: [
        .iOS(.v9),
        .tvOS(.v9),
        .macOS(.v10_15)
    ],
    products: [
        .library(name: "PowerAuthCore", targets: ["PowerAuthCore"])
    ],
    targets: [
        .binaryTarget(
            name: "PowerAuthCore",
            url: "https://github.com/wultra/powerauth-client-core/releases/download/1.9.9-b1/PowerAuthCore-b1.zip",
            checksum: "34ea1b957ee7bca5f3c2ea0e27b33111b107293bad56a752d8ad0b83e26bb744")
    ]
)