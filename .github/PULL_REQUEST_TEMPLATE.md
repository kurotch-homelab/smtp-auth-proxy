## What does this change?

<!-- One or two sentences. Link the issue it closes, if any. -->

Closes #

## Why?

<!-- The problem this solves. If it changes behavior visible to operators,
     say what an existing deployment will see after upgrading. -->

## How was it verified?

- [ ] `make lint`
- [ ] `make test`
- [ ] `make test-e2e` (if the SMTP path, queue or a transport changed)
- [ ] Manually exercised against a real Microsoft 365 tenant (if OAuth, XOAUTH2 or Graph changed)

## Operator impact

- [ ] No config change required
- [ ] Adds a new config key (documented in `docs/configuration.md` and the Helm `values.yaml`)
- [ ] Requires a database migration
- [ ] Requires new Microsoft 365 tenant permissions (documented in `docs/setup-m365.md`)
