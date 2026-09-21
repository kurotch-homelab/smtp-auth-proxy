# Distribution notices

Run `npm ci` in `web`, then `node tools/licenses/generate.mjs` at the repository root.
Commit both generated files in `internal/legal`. CI runs the same generator with
`--check` and fails when dependency versions, license text, or notices change.

The generator uses the Makefile's pinned `go-licenses` version, combines the
Linux/macOS amd64/arm64 dependency sets, and includes their LICENSE and NOTICE
files. It adds the Go standard library and its vendored library notices, runtime
npm dependencies, Tailwind's distributed CSS, and Vite/Rolldown's emitted browser helpers.
Development packages that do not contribute code to the distribution are excluded.
The generator, CI and release image pin Go 1.27.0 so the standard library entry
records the compiler's exact version. Update those pins and regenerate the
notices together when updating the release compiler.

For an npm package with no license text, review the exact release's official
upstream source. Add its text under `overrides/` and a version-specific entry in
`overrides.json` with the immutable source URL and SHA-256 of the original bytes.
Unknown license identifiers, missing texts, stale installations and incorrect
override hashes fail instead of silently omitting a dependency. A newly introduced
license identifier requires review before adding it to the allowlist.

`smtp-auth-proxy licenses` prints the embedded notices without loading configuration
or opening a database. `/licenses` serves those exact bytes without authentication;
`/licenses?download=1` supplies a download. The release archive includes the same
tracked text and the image stores it in
`/usr/share/licenses/smtp-auth-proxy/THIRD_PARTY_NOTICES.txt`.
The application's Apache-2.0 LICENSE and NOTICE remain intact.

Run collector regression tests with `node --test tools/licenses/npm.test.mjs`.
