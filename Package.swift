// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "SignOps",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "SignOps", targets: ["SignOps"])],
    targets: [
        .target(name: "SignOps"),
        .testTarget(name: "SignOpsTests", dependencies: ["SignOps"]),
    ]
)
