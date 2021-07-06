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
            url: "https://github.com/wultra/powerauth-client-core/releases/download/1.9.9-b1/PowerAuthCore-b2.zip",
            checksum: "d8d053f6b13a773f8843ac7d6b859085c0c7f04a96238158368906f619fca3cd")
    ]
)