# Documentation site

The Japanese usage guide is published at https://smtp-auth-proxy.pages.silver-vine.jp/.
Its Markdown source is in `docs/site/`; it is independent of the embedded admin UI.
Vite is overridden to 6.4.3 to include development-server security fixes missing
from VitePress 1.6.4's default Vite 5 dependency; recheck this when upgrading VitePress.

```sh
cd docs/site
npm ci
npm run dev
npm run build
npm run preview
```

VitePress checks internal links and produces `.vitepress/dist/`. Only that directory
is uploaded; configuration files, application data and local environment files are
not part of the site. The local search index is built with the pages.

`.github/workflows/pages.yml` builds pull requests and deploys changes on `main`
through `kurotch-homelab/sv-pages/.github/workflows/deploy.yml@v1`. It can also be
started with `workflow_dispatch` on `main`. GitHub OIDC uses project/role
`smtp-auth-proxy`, repository ID `1343645198` and `refs/heads/main`; the role is
registered in the operator repository's SeaweedFS IAM configuration. No persistent
S3 credential is needed. The deployed prefix is dedicated to this site.

When the UI changes, update the Japanese guide alongside the implementation,
especially diagnostic labels, queue states and role permissions. Use fictional
domains and values in public examples.
