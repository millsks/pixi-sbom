# Training lab

A self-paced, hands-on course on pixi-sbom: seven modules, 60 to 90 minutes in all, on the real projects in the
repository's `examples/` directory. Each step gives a command, the output to look for, and a question to check you
understood what you saw. Tick the boxes as you go; your progress is kept in this browser.

It runs **offline**. The answers the online services gave (OSV, CISA KEV, FIRST EPSS, the PyPI index) were
recorded into `examples/lab-cache/` on 2026-10-09, so a classroom on a slow or locked-down network gets the same
results as everyone else, and so do you. Every expected output below is checked by a test against that cache.

## Before you start

You need pixi-sbom ([Installation](installation.md)) and a copy of the repository:

```sh
git clone https://github.com/millsks/pixi-sbom
cd pixi-sbom
export PIXI_SBOM_OFFLINE=1 PIXI_SBOM_CACHE_DIR="$PWD/examples/lab-cache"
```

On Windows PowerShell, set the two variables with `$env:PIXI_SBOM_OFFLINE = "1"` and
`$env:PIXI_SBOM_CACHE_DIR = "$PWD\examples\lab-cache"`.

The examples are locked for linux-64 and osx-arm64, so the commands name the platform (`-p linux-64`); they give
the same answer on any machine.

- [ ] I have the repository and the two variables set.

## 1. Your first document

A pixi workspace: Django on an old LTS, with an editable local package and one environment per dependency group.

```sh
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --report packages
```

```text
Summary: 66 packages, 9 declared by the workspace
```

Now write the document itself, in CycloneDX and then SPDX 3.0.1:

```sh
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --output lab.cdx.json
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --format spdx --spec-version 3.0 --output lab.spdx.json
```

??? question "The table lists Python and system libraries as well as Django. Why?"
    A conda environment ships the interpreter and the libraries it links against, so they are in the environment
    and in its SBOM. A scanner that only looks at PyPI packages misses vulnerabilities in them.

- [ ] I wrote `lab.cdx.json` and `lab.spdx.json`.

## 2. Not a pixi project

The same scenario, locked by uv and by pip-compile's format:

```sh
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/requirements/01-django/requirements-dev.txt --report packages
```

```text
Summary: 23 packages, 10 declared by the workspace
```

A `requirements.txt` with a range in it is not a lock, and is refused at the line that isn't one version:

```sh
pixi sbom --lockfile examples/projects/requirements-unpinned/01-loose-ranges/requirements.txt --output -   # exit 1
```

```text
line 3 of examples/projects/requirements-unpinned/01-loose-ranges/requirements.txt is not pinned to one version: Django>=4.2,<5
```

??? question "Why doesn't pixi-sbom just resolve the range to today's newest version?"
    Because the answer would change from day to day while the file stays the same. An SBOM has to describe what
    was installed, and only a lock says that. pixi-sbom reads locks and never resolves.

- [ ] I read a uv lock and a pinned requirements file, and saw an unpinned one refused.

## 3. Findings

`02-flask` is a 2021-era stack. Look its packages up, with CISA's known-exploited flags and FIRST's exploit
likelihood beside each finding:

```sh
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --kev --epss --report vulnerabilities
```

```text
Summary: 41 findings in 8 packages
high      17
medium    22
```

??? question "None of the findings is in the KEV catalog. Does that make them safe to leave?"
    No. KEV only lists what is being exploited now. The EPSS column ranks the rest by how likely exploitation is in
    the next 30 days, which is what to sort a backlog by.

- [ ] I found the finding with the highest EPSS score.

## 4. Gates and exit codes

A CI job reads the exit code. Fail on anything high or above; the document is still written:

```sh
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --fail-on-severity high --output lab-flask.cdx.json   # exit 4
```

```text
Gate failed: vulnerabilities (17). Exiting 4.
```

A license policy. `html2text` is GPL-3.0 but declares it as free text, which a deny list of SPDX identifiers
cannot match; `--require-license` makes that a violation too:

```sh
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock -p linux-64 --fetch-licenses --deny-license GPL-3.0-only --require-license --output -   # exit 3
```

```text
html2text 2020.1.16: license is not an SPDX expression (GNU GPL 3 (unknown term: 'GNU'))
pyopenssl 26.4.0: license is not an SPDX expression (Apache License, Version 2.0 (unknown term: 'License'))
Gate failed: license policy (3). Exiting 3.
```

It caught more than html2text: pyopenssl and twisted declare `Apache License, Version 2.0` and `MIT License`,
which are free text too. Neither is a license you would forbid, but neither is one a policy can evaluate either, and
that is what `--require-license` reports. Accept them by name once you have checked them
([`--ignore-license`](cli.md#enforcing-a-license-policy)).

??? question "Two gates trip in one run. Which exit code does CI see?"
    The first in a fixed order: license policy (3), vulnerabilities (4), then the others. stderr lists every gate
    that tripped, so nothing is hidden by the order. See [Exit codes and errors](cli.md#exit-codes-and-errors).

- [ ] I saw exit 4 and exit 3, and know what each means.

## 5. Before and after an upgrade

`14-django-upgraded` is `01-django` moved to Django 4.2 LTS:

```sh
pixi sbom --lockfile examples/projects/uv/14-django-upgraded/uv.lock -p linux-64 --report diff --against examples/projects/uv/01-django/uv.lock
```

```text
8 added, 4 removed, 9 version changes, 0 license changes, 14 unchanged
```

??? question "The diff counts nine version changes. Which one matters most for security?"
    Django itself, from 3.2.12 to a 4.2 LTS release: run module 3's command on both lockfiles and compare the summaries. The
    diff says what changed; the vulnerability report says what the change fixed.

- [ ] I can say which packages the upgrade added, removed and changed.

## 6. Someone else's SBOM

Treat a document as if a vendor had sent it. First make one, then grade it before trusting it:

```sh
pixi sbom --lockfile examples/projects/requirements/12-aws-cloud/requirements.txt --output vendor.cdx.json
pixi sbom --from-sbom vendor.cdx.json --report quality
```

```text
Quality: 77 of 100 for 24 packages (NTIA minimum elements: 85 of 100)
```

Apply a vendor's VEX. This one says the Flask service is not affected by one finding in requests, so the
medium count drops from 22 to 21 and the finding moves to *Ignored*, with the file it came from:

```sh
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --vex-in examples/lab/vendor.openvex.json --report vulnerabilities
```

```text
medium    21
Ignored (1):
  GHSA-j8r2-6x86-q33q (not_affected, from vendor.openvex.json): The service never configures a proxy, so no Proxy-Authorization header is ever sent.
```

Merge your document and the vendor's into one for the product:

```sh
pixi sbom --from-sbom lab.cdx.json --from-sbom vendor.cdx.json --root-name product --report packages
```

??? question "The quality report scores the author element 0. What does that mean, and does it matter?"
    The document names no author, only the tool that generated it. NTIA counts the author as a minimum element; a
    vendor document should say who produced it. It does not affect a vulnerability lookup, but the purl coverage
    (*unique identifier*) does.

- [ ] I graded a document, applied a VEX, and merged two documents.

## 7. Where a fact came from

`internal-utils` is a local package installed in editable mode:

```sh
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --explain internal-utils
```

??? question "Why is internal-utils never looked up on PyPI?"
    It was installed from a local path, so a package of the same name on PyPI would be someone else's project.
    pixi-sbom gives it a `pkg:generic` purl and leaves the index out of it.

- [ ] I can read an `--explain` table.

## Next

- The [field manual](field-manual/index.md) turns each of these into a playbook for a real pipeline.
- Unset `PIXI_SBOM_OFFLINE` to ask the live services: the counts will have moved since the cache was recorded,
  and that is the tool working.
