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
            url: "https://github.com/wultra/powerauth-client-core/releases/download/1.9.9-b1/PowerAuthCore-b4.zip",
            checksum: "f8a861d128d11e768acae51a2dc34351a07a92f1ecab64229701cb944b7ab49b")
    ]
)