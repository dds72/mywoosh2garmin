# Garmin MFA login

The reported failure is an explicit rejection of every MFA challenge in
`garmin/sso.go`. The GUI has no way to provide the requested verification code.

Dependency path: upload action → serialized Garmin authentication → SSO cookies
and challenge CSRF → GUI code callback → verification → OAuth tokens → upload.

1. Complete the existing embedded SSO flow using a code callback, preserving
   cookies, Referer, query parameters, and the current challenge's CSRF token.
   Keep the existing non-MFA API working and limit rejected-code retries.
2. Present a Fyne form on the UI thread while the login worker waits. Support
   cancellation and stop batch uploads after authentication failure. Cache only
   successfully acquired tokens, never verification codes.
3. Add protocol and dialog regression tests, document usage, and build the fork.

Protocol reference: https://github.com/matin/garth/blob/0.5.20/src/garth/sso.py
This matches this repository's embedded SSO implementation. Current garth uses a
different mobile API; migrating protocols is outside this reported failure.

Verification uses synthetic HTTP responses, not a real Garmin account. A live
account sign-in remains a manual check. Build Go 1.24.13, matching go.mod.

User-requested extension: release native Darwin executables for Apple Silicon
and Intel. Add macOS runners to the build matrix, keep Linux dependency setup
conditional, document launching the executables, and publish all four platform
assets in a tagged GitHub release.
