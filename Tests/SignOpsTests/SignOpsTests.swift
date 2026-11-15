import XCTest
@testable import SignOps

final class SignOpsTests: XCTestCase {
    func testBase64URLRoundTrip() {
        let bytes = Data([0xfb, 0xff, 0x00, 0x10, 0x3e])
        XCTAssertEqual(Base64URL.encode(bytes), "-_8AED4")
        XCTAssertEqual(Base64URL.decode("-_8AED4"), bytes)
    }

    func testPublishableKeysOnly() {
        XCTAssertTrue(SignOps.isPublishable("pk_test_abc"))
        XCTAssertFalse(SignOps.isPublishable("sk_live_abc"))
    }

    func testReadsTheApiErrorShape() {
        let e = SignOpsError.from(status: 403, data: Data(#"{"error":{"code":"not_allowed","message":"No iOS app is added for passkeys."}}"#.utf8))
        XCTAssertEqual(e, SignOpsError(status: 403, code: "not_allowed", message: "No iOS app is added for passkeys."))
        XCTAssertEqual(SignOpsError.from(status: 502, data: Data("<html>".utf8)).message, "SignOps answered 502")
    }

    @available(iOS 16.0, macOS 13.0, *)
    func testBuildsAppleRequestsFromSignOpsOptions() throws {
        let reg = try Passkeys.registrationRequest(["challenge": "AAEC", "rp": ["id": "veritas.example", "name": "Veritas Solutions"], "user": ["id": "dXNy", "name": "meera@veritas.example", "displayName": "Meera"]])
        XCTAssertEqual(reg.relyingPartyIdentifier, "veritas.example")
        XCTAssertEqual(reg.challenge, Data([0, 1, 2]))
        XCTAssertEqual(reg.name, "meera@veritas.example")
        let sign = try Passkeys.assertionRequest(["challenge": "AAEC", "rpId": "veritas.example", "allowCredentials": [["id": "AQI", "type": "public-key"]]])
        XCTAssertEqual(sign.allowedCredentials.map(\.credentialID), [Data([1, 2])])
        XCTAssertThrowsError(try Passkeys.assertionRequest(["challenge": "AAEC"]))
    }
}

final class PaidFeatureTests: XCTestCase {
    func testActivityTokenHex() { XCTAssertEqual(Activities.hex(Data([0x0a, 0xff, 0x00])), "0aff00") }
    func testInboxPage() {
        let p = Inbox.parse(["data": [["id": "inb_1", "title": "Bill", "body": NSNull(), "data": ["a": "1"], "created_at": "2026-10-25T10:00:00.000Z", "read": false]], "unread": 1, "next": NSNull()])
        XCTAssertEqual(p.unread, 1); XCTAssertEqual(p.items.first?.title, "Bill"); XCTAssertNil(p.items.first?.body); XCTAssertEqual(p.items.first?.data["a"], "1"); XCTAssertNil(p.next)
    }
}
