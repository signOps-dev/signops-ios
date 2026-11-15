# SignOps for iOS

Approve, passkeys and push open reporting in an iOS app (iOS 16 and later). Approve keys are made in the Secure Enclave and never leave the phone. Passkeys go through AuthenticationServices; the same passkeys your website makes with `@signops/web` work here, synced through iCloud Keychain.

```swift
// Swift Package Manager: https://github.com/signOps-dev/signops-ios, from "0.4.0", product SignOps
import SignOps

let signops = SignOps(key: "pk_live_...")                 // the publishable key; secret keys stay on your server

// Make a passkey. The token comes from your server: POST /v1/passkeys/registration-token
let made = try await signops.passkeys.register(token: registrationToken, anchor: view.window!)

// Sign in. autofill: true offers the passkey in the keyboard on a field with textContentType = .username.
// Send r.signopsToken to your server, which checks it with POST /v1/passkeys/verify.
let r = try await signops.passkeys.signIn(anchor: view.window!, autofill: true)
```

## Approve

```swift
// After your own login. The token comes from your server: POST /v1/approve/enroll-token { user_id }.
try await signops.approve.enroll(token: enrolToken, pushToken: SignOps.apnsToken(from: deviceToken))   // or the FCM token

// When an approve push arrives, or the app opens: the ready-made screen
.sheet(item: $approveId) { id in ApproveView(signops: signops, requestId: id.value) { _ in approveId = nil } }

// Or your own screen
let req = try await signops.approve.pending().first!
try await signops.approve.approve(req, picked: "47")   // Face ID, Touch ID or passcode, then a signed answer
try await signops.approve.deny(req)

// When the token changes
try await signops.approve.updatePushToken(SignOps.apnsToken(from: deviceToken))
```

Add `NSFaceIDUsageDescription` to Info.plist. The Simulator has no Secure Enclave: there the key is a Keychain key, so the flow can be tested.

## Push opens

```swift
func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse) async {
    try? await signops.push.opened(userInfo: r.notification.request.content.userInfo, action: r.actionIdentifier)
}
```

Errors are `SignOpsError` with `code`: the API's codes, or `cancelled`, `no_passkey`, `passkey_error`, `not_enrolled`, `no_lock` (no passcode), `auth_failed`, `key_error`.

## Before it works

1. In the SignOps dashboard, Passkeys, Setup: add the Team ID and the bundle id.
2. Host the `apple-app-site-association` file the dashboard shows at `https://<your domain>/.well-known/apple-app-site-association`, as `application/json`, with no redirect.
3. In Xcode, Signing and Capabilities, Associated Domains: `webcredentials:<your domain>`.

## Build and test

`swift test` on macOS 13 or later; `xcodebuild -scheme SignOps -destination 'generic/platform=iOS Simulator' build` for the phone target. With `SIGNOPS_SK` and `SIGNOPS_PK` set, `testRoundTripAgainstTheApi` runs Approve against the real API with a CryptoKit key in the Secure Enclave's formats. Compiled and tested with Xcode 26.6 on 22 Oct 2026; not yet run on a phone.
