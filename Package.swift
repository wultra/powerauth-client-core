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
            url: "https://github.com/wultra/powerauth-client-core/releases/download/1.9.9-b1/PowerAuthCore-b3.zip",
            checksum: "fd61e42cb40270cc12ea7825bee42b7745a4d5839fb34775a7e973a5f2dc5396")
    ]
)