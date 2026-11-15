import CryptoKit
import Security
import XCTest
@testable import SignOps

final class ApproveTests: XCTestCase {
    func testSignsWhatTheApiChecks() {
        XCTAssertEqual(ApproveMessages.pending("1700000000000"), "1700000000000.pending")
        XCTAssertEqual(ApproveMessages.respond("1700000000000", "apr_x", "approve", "47"), "1700000000000.apr_x.approve.47")
        XCTAssertEqual(ApproveMessages.respond("1700000000000", "apr_x", "deny", ""), "1700000000000.apr_x.deny.")
        let pay = Approve.Payment(amount: "1499.00", currency: "INR", payee: "Sharma Stores")
        XCTAssertEqual(ApproveMessages.respond("1700000000000", "apr_x", "approve", "47", pay), "1700000000000.apr_x.approve.47.pay:INR:1499.00:Sharma Stores")
        XCTAssertEqual(pay.text, "INR 1,499.00 to Sharma Stores")
        XCTAssertEqual(Approve.Payment(amount: "149999.00", currency: "INR", payee: "x").amountText, "INR 1,49,999.00")
        XCTAssertEqual(Approve.Payment(amount: "149999.00", currency: "USD", payee: "x").amountText, "USD 149,999.00")
        XCTAssertEqual(ApproveMessages.pushToken("1700000000000", "abc"), "1700000000000.token.abc")
    }

    /// The fixed SPKI header plus Apple's X9.63 point must be exactly the SPKI any other tool makes for the same key.
    func testSpkiMatchesCryptoKit() throws {
        let key = P256.Signing.PrivateKey()
        XCTAssertEqual(ApproveMessages.spki(fromX963: key.publicKey.x963Representation), key.publicKey.derRepresentation)
    }

    /// The same key as a SecKey, signed the way the SDK signs, verifies with CryptoKit: DER ECDSA over SHA-256.
    func testSecKeySignatureIsDer() throws {
        let ck = P256.Signing.PrivateKey()
        var error: Unmanaged<CFError>?
        let sec = SecKeyCreateWithData(ck.x963Representation as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, &error)!
        let msg = Data(ApproveMessages.pending("1700000000000").utf8)
        let sig = SecKeyCreateSignature(sec, .ecdsaSignatureMessageX962SHA256, msg as CFData, &error)! as Data
        XCTAssertTrue(ck.publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: msg))
    }

    func testReadsPendingRequests() {
        let r = Approve.parsePending(["data": [["id": "apr_1", "context": "Sign in from Chrome on Windows", "city": "Pune", "browser": NSNull(), "options": ["23", "47", "81"],
                                               "created_at": "2026-10-22T10:00:00.000Z", "expires_at": "2026-10-22T10:02:00.000Z"]]])
        XCTAssertEqual(r.count, 1); XCTAssertEqual(r[0].city, "Pune"); XCTAssertNil(r[0].browser); XCTAssertEqual(r[0].options, ["23", "47", "81"])
    }

    func testKnowsSignOpsPushes() {
        XCTAssertEqual(Approve.requestId(["signops": "approve", "approve_id": "apr_9"]), "apr_9")
        XCTAssertNil(Approve.requestId(["approve_id": "apr_9"]))
        XCTAssertEqual(Push.messageId(["signops_id": "msg_1"]), "msg_1")
        XCTAssertNil(Push.messageId(["signops_id": "x"]))
        XCTAssertEqual(SignOps.apnsToken(from: Data([0x0a, 0xff])), "0aff")
    }

    /// The whole round trip against the real API with a CryptoKit key standing in for the Secure Enclave.
    /// Runs when SIGNOPS_SK and SIGNOPS_PK (test keys of one app) are set.
    func testRoundTripAgainstTheApi() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let sk = env["SIGNOPS_SK"], let pk = env["SIGNOPS_PK"] else { throw XCTSkip("set SIGNOPS_SK and SIGNOPS_PK") }
        let base = URL(string: env["SIGNOPS_BASE"] ?? "https://api.signops.dev")!
        let server = SignOpsServerForTests(key: sk, base: base)
        let phone = SignOps(key: pk, baseURL: base)
        let key = P256.Signing.PrivateKey()
        func sign(_ m: String) throws -> String { Base64URL.encode(try key.signature(for: Data(m.utf8)).derRepresentation) }
        let user = "usr_ios_\(Int(Date().timeIntervalSince1970))"
        let token = try await server.post("/v1/approve/enroll-token", ["user_id": user])["token"] as! String
        let en = try await phone.post("/v1/approve/devices/enroll", ["token": token, "public_key": Base64URL.encode(ApproveMessages.spki(fromX963: key.publicKey.x963Representation)),
                                                                     "push_token": "ios-test-\(user)", "platform": "ios", "name": "XCTest"])
        let dev = en["device_id"] as! String
        let ch = try await server.post("/v1/approve", ["user_id": user, "context": "Sign in from Safari on a Mac"])
        let ts = Approve.timestamp()
        let pend = Approve.parsePending(try await phone.get("/v1/approve/pending", headers: ["signops-device": dev, "signops-timestamp": ts, "signops-signature": try sign(ApproveMessages.pending(ts))]))
        let r = try XCTUnwrap(pend.first { $0.id == ch["id"] as? String })
        let match = ch["match"] as! String
        XCTAssertTrue(r.options.contains(match))
        let t2 = Approve.timestamp()
        let ans = try await phone.post("/v1/approve/\(r.id)/respond", ["device_id": dev, "decision": "approve", "picked": match, "timestamp": Int64(t2)!, "signature": try sign(ApproveMessages.respond(t2, r.id, "approve", match))])
        XCTAssertEqual(ans["status"] as? String, "approved")
        _ = try await server.post("/v1/approve/devices/\(dev)/remove", [:])
    }
}

/// A secret-key caller for the test only: the SDK refuses secret keys by design.
struct SignOpsServerForTests {
    let key: String
    let base: URL
    func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("Bearer \(key)", forHTTPHeaderField: "authorization")
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, res) = try await URLSession.shared.data(for: req)
        let status = (res as! HTTPURLResponse).statusCode
        if status >= 400 { throw SignOpsError.from(status: status, data: data) }
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }
}

#if os(iOS)
/// On the iPhone Simulator: the real Approve class with a real Keychain key (the Simulator has no Secure Enclave), against
/// the live API. Needs a host app for Keychain access; without one it skips. Enrol, fetch, deny (no Face ID needed), move the push token, forget. Run with
/// TEST_RUNNER_SIGNOPS_SK=... TEST_RUNNER_SIGNOPS_PK=... xcodebuild test -scheme SignOps -destination 'platform=iOS Simulator,name=iPhone 17'
final class ApproveOnSimulatorTests: XCTestCase {
    func testRealKeyRoundTrip() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let sk = env["SIGNOPS_SK"], let pk = env["SIGNOPS_PK"] else { throw XCTSkip("set TEST_RUNNER_SIGNOPS_SK and TEST_RUNNER_SIGNOPS_PK") }
        let base = URL(string: env["SIGNOPS_BASE"] ?? "https://api.signops.dev")!
        let server = SignOpsServerForTests(key: sk, base: base)
        let signops = SignOps(key: pk, baseURL: base)
        let user = "usr_sim_\(Int(Date().timeIntervalSince1970))"
        let token = try await server.post("/v1/approve/enroll-token", ["user_id": user])["token"] as! String
        let enrolled: Approve.Enrolled
        do { enrolled = try await signops.approve.enroll(token: token, pushToken: "sim-\(user)", name: "Simulator") }
        catch let e as SignOpsError where e.message.contains("-34018") {
            // A test bundle with no host app has no Keychain access. The same flow runs in an app: packages/flutter's integration test does it.
            throw XCTSkip("The Keychain needs a host app (error -34018).")
        }
        XCTAssertEqual(enrolled.userId, user)
        XCTAssertTrue(signops.approve.isEnrolled)
        let ch = try await server.post("/v1/approve", ["user_id": user, "context": "Sign in from the simulator test"])
        let waiting = try await signops.approve.pending()
        let req = try XCTUnwrap(waiting.first { $0.id == ch["id"] as? String })
        let answer = try await signops.approve.deny(req)
        XCTAssertEqual(answer.status, "denied")
        try await signops.approve.updatePushToken("sim-new-\(user)")
        _ = try await server.post("/v1/approve/devices/\(enrolled.deviceId)/remove", [:])
        signops.approve.forget()
        XCTAssertFalse(signops.approve.isEnrolled)
    }
}
#endif
