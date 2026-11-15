# Tasks

## 1. Complete Garmin MFA authentication
Files: garmin/sso.go, garmin/client.go, garmin/sso_test.go
Acceptance: MFA submits the current CSRF and session cookies; success reaches
OAuth exchange; rejected codes can be retried; cancellation, malformed responses,
and exhausted retries return errors without caching tokens; non-MFA still works.
- [x] Protocol regression tests pass (13 synthetic login scenarios and cache/refresh checks).

## 2. Connect the GUI and uploads
Files: main.go, mfa.go, mfa_test.go
Acceptance: code prompt runs on the UI thread, validates empty input, permits
cancel, and resumes the waiting worker; authentication is serialized; a batch
stops after failed/cancelled login rather than prompting for every activity.
- [x] Dialog submit/cancel/validation tests pass.
- [x] Full tests and native build pass (checkpoint).

## 3. Deliver the public fork
Files: README.md, .github/workflows/release.yml
Acceptance: documentation explains 2FA and points downloads to this fork;
CI tests and builds Windows/Linux/macOS binaries; fixed source is pushed to the fork.
- [x] Review diff and run vet/race tests.
- [x] Push and verify GitHub build results (Apple Silicon, Windows, Linux passed).

## 4. Publish macOS executables (user-requested extension)
Files: .github/workflows/release.yml, README.md
Acceptance: the release includes Darwin arm64 plus Windows/Linux; documentation
explains launching the download. Intel was removed at the user's request.
- [x] Apple Silicon job passes tests, vet, and native build.
- [ ] Tagged release contains the three completed platform executables, reused
  from run 43704791261 as requested; application source is unchanged.
