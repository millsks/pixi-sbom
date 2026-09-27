# Security policy

## Reporting a vulnerability

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/millsks/pixi-sbom/security/advisories/new)**
(Security → Advisories → Report a vulnerability). The report is visible only to the maintainers until an advisory
is published.

Please do not open a public issue for a security problem, and please do not disclose it elsewhere before a fix is
out. If GitHub's form is not available to you, open a public issue asking for a private channel — with no details
in it — and one will be arranged.

**What to include:** the version (`pixi sbom --version`), the platform, the command you ran, and the smallest input
that reproduces it. For anything involving a crafted file, attach the file. A crash needs a backtrace
(`RUST_BACKTRACE=1`).

## What to expect

| | |
|---|---|
| Acknowledgment | Within 3 business days. This is a small project with one maintainer; if you have heard nothing after that, assume the mail went astray and ping the advisory thread. |
| Assessment | Within 10 business days: whether it is in scope, how severe, and a rough fix timeline. |
| Fix and disclosure | A patch release, then a published GitHub Security Advisory with a CVE where one is warranted. |
| Credit | You are named in the advisory and the changelog unless you would rather not be. Say which you prefer. |

There is no bug bounty.

## Supported versions

**The latest release.** A fix ships in the next patch release from `main`; there are no maintenance branches, and
nothing is backported to an older minor. A report against an older version is checked against the current release
first, because the answer is often that it is already fixed.

There is one supported line and it is the newest one. No 2.0 exists, so there is no older line to have a policy
about; when one does, what happens to 1.x will be stated here with a date, before it is needed rather than when it is
asked for.

Practically: stay on the latest release. `pixi global update pixi-sbom` follows the conda-forge feedstock, and
`uses: millsks/pixi-sbom@v1` follows the newest 1.x.y release on its own.

## Scope

This tool's threat model is worth stating plainly, because it is less obvious than most. It reads input that an
attacker may control:

- **Lockfiles and manifests** — `pixi.lock`, `pixi.toml`, `pyproject.toml`, and existing SBOM documents fed to
  `--from-sbom`. YAML, TOML and JSON from a repository you may not have written.
- **Conda archives** — `.conda` (zip) and `.tar.bz2` (tar + bzip2) members, read from the local package cache or
  over HTTP byte ranges, and the `info/` files inside them.
- **Wheels** — zip archives, their `dist-info` metadata, and `Cargo.lock`-style audit data embedded in binaries.
- **HTTP responses** — from PyPI, conda channels, `conda-mapping.prefix.dev`, `api.osv.dev`, CISA's KEV catalog and
  `api.securityscorecards.dev`. A response is untrusted even when the host is.
- **Prefix directories** — `conda-meta/` records and the Python sources scanned for `--report phantom`.

**In scope**, from any of those:

- Memory unsafety, a panic, an unbounded allocation, or a hang. The shipped binary is
  `forbid(unsafe_code)` — the compiler holds that, not a convention — so a memory-safety finding would almost
  certainly be in a dependency. Report it here anyway.
- A path written outside the output path you asked for, from an archive member name or a package name. Archive
  extraction is the obvious place to look.
- A decompression bomb that exhausts memory or disk.
- Anything that causes a network request to a host you did not configure, or sends a credential, token or local
  path to a host that should not see it.
- A document that misrepresents what is installed in a way an attacker can arrange on purpose — a package or a
  hash that is silently dropped, or a component that claims a version it does not have. Accuracy is the product
  here, so an attacker-controlled inaccuracy is a vulnerability rather than a bug.
- Anything in the GitHub Action or the release workflow that would let a third party influence what a release
  contains.

**Out of scope:**

- **Vulnerabilities in the packages this tool reports on.** If `pixi sbom --report vuln` names a CVE in one of your
  dependencies, that is the tool working. Those belong to the package's maintainers, and to the advisory databases.
- A missing or wrong advisory in OSV, the KEV catalog or a scorecard. We report what those sources say; corrections
  go to them.
- An inaccurate license string that comes from the package's own metadata. Report it as a normal bug if you think
  we are reading the metadata wrong — that is worth fixing, but it is not a security issue.
- Anything requiring an attacker who already has write access to the machine or the output directory.
- Findings from a scanner with no demonstrated impact, and denial of service that needs the operator's own
  cooperation (pointing the tool at a gigantic lockfile on purpose).

## What the tool does not do

Two properties are worth knowing before you look:

- It never executes anything from a package. Archives are read, not installed; no build script, entry point or
  install hook runs, and nothing from a lockfile is passed to a shell.
- It writes exactly the output paths given on the command line, and nothing else outside the cache directory.

If you find a case where either is untrue, that is the report to send.

## Verifying a release

Every release archive from 0.11.0 onward carries a signed build-provenance attestation. To check a download really
came from this repository's release workflow, built from that release's tag on a GitHub-hosted runner (0.12.0 and
later):

```sh
gh attestation verify pixi-sbom-<version>-<platform>.tar.gz --repo millsks/pixi-sbom \
  --signer-workflow millsks/pixi-sbom/.github/workflows/release-artifacts.yml \
  --source-ref refs/tags/v<version> \
  --deny-self-hosted-runners
```

See [installation](https://millsks.github.io/pixi-sbom/latest/installation/#checking-where-a-binary-came-from) for
the offline form and why 0.11.0 only passes the plain `--repo` check.
