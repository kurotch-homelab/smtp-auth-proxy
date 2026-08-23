# Contributing

Thanks for taking the time. This document covers the parts that are specific to this
project; everything else is ordinary GitHub flow.

## Getting set up

You need Go 1.25+, Node 22+ and Docker.

```bash
make tools
```

```bash
make lint test
```

`make help` lists every target. **CI runs the same `make` targets you do**, so a green
local run is a good predictor of a green PR.

## Before you open a pull request

- `make lint` — `gofumpt`, `golangci-lint`, ESLint, Prettier and `tsc`
- `make test` — Go and web unit tests, with per-package coverage thresholds from
  [`.coverage.yaml`](.coverage.yaml)
- `make test-e2e` — if you touched SMTP handling, the queue or a transport

## Things worth knowing

**Never log a token, client secret or password.** The proxy handles credentials for a
mail system; a debug line that dumps an XOAUTH2 string leaks a bearer token for a
mailbox. If you need to log around one, log its length or a hash.

**The XOAUTH2 string is byte-exact.** It is
`base64("user=" + mailbox + "\x01auth=Bearer " + token + "\x01\x01")`. The separators are
literal `0x01` bytes, not the two characters `^A`. Tests assert on the exact bytes;
please keep it that way.

**Exchange Online's limits are not advisory.** 30 messages/minute, 3 concurrent
connections and 10,000 recipients/day, per mailbox. Anything that increases concurrency
or send rate needs to respect the mailbox budget, or real deployments start seeing
`4.7.500 Server busy`.

**Migrations are written twice.** SQLite and PostgreSQL each have their own directory
under `internal/store/migrations/`. Both must apply cleanly up, down and up again, and
`TestDialectsHaveMatchingMigrations` fails if one dialect gains a migration the other
lacks. When you add a table, add it to `expectedTables` in
`internal/store/migrate_db_test.go` too — that list is what keeps the two schemas honest.

**Queries are written once.** There is no ORM and no code generation: statements use `?`
placeholders and are rebound to `$1, $2, ...` for PostgreSQL by the `Dialect`. The few
statements that genuinely differ between the engines go through `Dialect` methods rather
than being duplicated.

**To run the PostgreSQL tests locally:**

```bash
make postgres-up
```

Export the DSN it prints, run `make test`, then `make postgres-down`. Without the DSN
those tests skip rather than fail.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), e.g.
`fix(queue): stop re-leasing a message whose lease has not expired`. Release notes are
grouped from these prefixes.

## Reporting a security issue

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
