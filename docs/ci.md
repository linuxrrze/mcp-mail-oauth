# CI, versioning and releases

`.github/workflows/ci.yml` runs on every pull request and every push to `main`
(docs-only changes are skipped).

```mermaid
flowchart LR
    trigger(["push to main<br/>or pull request"])

    subgraph gates["Run in parallel"]
        direction TB
        test["Tests<br/>Python 3.11 / 3.12 / 3.13"]
        repo["Trivy repository scan<br/>secrets, misconfig"]
        integration["Integration stack<br/>Keycloak + Postfix/Dovecot 2.3 / 2.4,<br/>with and without token exchange"]
        version["Next version<br/>from tags + commits"]
    end

    trigger --> test & repo & integration & version
    test & repo & integration & version --> build["Build image once<br/>(loaded locally)"]
    build --> scan["Trivy image scan<br/>fixable HIGH / CRITICAL"]
    scan --> smoke["Smoke test<br/>the container"]
    smoke --> decide{"main and<br/>new commits?"}
    decide -- "no (PR)" --> stop(["Stop: nothing published"])
    decide -- yes --> push["Push the scanned image"]
    push --> tag["Git tag vX.Y.Z"]
    tag --> release(["GitHub release"])
```

**An image is published only if all of these pass:** the full test suite on
three Python versions, Trivy's repository scan, the end-to-end checks against
the test stack with Dovecot 2.3 and 2.4 and with token exchange
([test-stack/README.md](../test-stack/README.md)),
Trivy's image scan, and a smoke test of the built container. The pushed image is byte-for-byte the one that
was scanned and smoke-tested: it is built once, loaded locally, then pushed,
never rebuilt (decisions.md D20).

## Versions

Git tags `vX.Y.Z` are the only place the version lives (D19). On each push to
`main`, `scripts/next_version.py` looks at the commits since the last tag:

| Commit message | Bump | Example |
|---|---|---|
| `BREAKING CHANGE` in the body, or `type!:` subject | major (minor while 0.x) | `refactor!: rename MAIL_* variables` |
| `feat:` / `feat(scope):` | minor | `feat(imap): add flag tools` |
| anything else | patch | `fix: ...`, `chore: ...`, or any free text |

- First release ever: `v0.1.0`.
- **0.x → 1.0.0** is never automatic. Run the workflow manually (*Actions → CI
  → Run workflow*) with `bump: major`. The manual trigger also forces a
  patch/minor/major bump, e.g. to release a base-image security update
  without a code change.
- The tag is created **after** the image is pushed, so a failed run never
  burns a version number. Runs on `main` are serialized, so two pushes can't
  compute the same version.

Inside the image, `mcp_mail.__version__`, the startup log line, the MCP
`serverInfo.version` and the OCI label `org.opencontainers.image.version` all
carry the release version. Non-release builds (PRs) get
`<next>.dev0+g<sha>`, which can't be mistaken for a release.

Image tags per release `vX.Y.Z`: `X.Y.Z`, `X.Y`, `X` (from 1.0 on), `latest`, `sha-<commit>`.

## Security scans

| Scan | Scope | Fails on |
|---|---|---|
| repository (`trivy fs`) | committed secrets; Dockerfile/compose misconfiguration | HIGH, CRITICAL |
| image (`trivy image`) | OS packages and Python libraries in the image; secrets in layers | **fixable** HIGH, CRITICAL |

Unfixed CVEs don't block, since nothing could unblock them. The Dockerfile
applies pending Debian updates, so most base-image findings are fixed by
simply re-running the build.

**Accepting a finding:** add its ID to `.trivyignore` with a comment (why it
doesn't apply, who accepted it, when to review). That file is the audit
trail. Don't lower the severity threshold instead.

Trivy itself (binary version) and every action are pinned (actions by commit
SHA). Update them deliberately, in their own PR.

## Setup

**GitHub (default: ghcr.io).** Nothing to configure. The workflow pushes to
`ghcr.io/<owner>/<repo>` with the built-in token. New packages on ghcr.io
start private: set the visibility under *Packages → mcp-mail-oauth → Package
settings* if needed.

**Other registry** (repository *Settings → Variables / Secrets*):

| Kind | Name | Example |
|---|---|---|
| variable | `REGISTRY` | `registry.example.com` |
| variable | `IMAGE_NAME` | `team/mcp-mail-oauth` |
| variable | `REGISTRY_USERNAME` | `ci-bot` |
| secret | `REGISTRY_PASSWORD` | token with push rights |

**Gitea Actions** runs this workflow too (it reads `.github/workflows`), with
the registry variables above pointing at Gitea's container registry. The
GitHub-release step is skipped there (`gh` targets GitHub only), and the
`vX.Y.Z` tag is still pushed. The build cache is best-effort, so an
unsupported cache backend doesn't fail the build. Your runner must provide
Docker (the smoke test runs the image) and resolve `uses:` against github.com.
