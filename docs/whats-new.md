# What's new since 1.0

1.0.0 froze the command line, the configuration keys, the exit codes and the `pixi:*` names
([what 1.0 freezes](stability.md)). Nothing on that list has changed since. Every release below
adds to it, and none removes or renames anything, so a pipeline written for 1.0 still runs
unchanged.

This page says what each release means for someone using the tool. The [changelog](changelog.md)
has every commit.

## The short version

Since 1.0, pixi-sbom has:

- **Stopped needing pixi.** It reads `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`,
  `conda-lock.yml`, explicit conda specs, pinned `requirements.txt` files and plain venvs. It
  installs from PyPI (`uvx pixi-sbom`) and runs as a pre-commit hook.
- **Learned to take in other people's SBOMs.** It can grade a vendor document before trusting it,
  apply the vendor's VEX, and merge several documents into one.
- **Learned to prioritise findings.** FIRST EPSS exploit-likelihood scores sit next to the CISA
  KEV flags, and either one can fail a build.
- **Learned to work on restricted networks.** Every upstream can point at a mirror, pixi's own
  credentials are used, and `--doctor` says which host is the problem.
- **Learned tab completion** in bash, zsh, fish and PowerShell, for `pixi-sbom` and `pixi sbom`.

## Unreleased

**pixi-sbom is back under millsks.** The repository is now [millsks/pixi-sbom](https://github.com/millsks/pixi-sbom),
the action `uses: millsks/pixi-sbom-action@v1`, the pre-commit hooks `https://github.com/millsks/pixi-sbom-pre-commit`,
and the docs [millsks.github.io/pixi-sbom](https://millsks.github.io/pixi-sbom/). GitHub redirects the old
`aesir-oss/` names, so existing workflows and hook configs keep working, but update them when convenient. Releases
from 1.13.2 to 1.15.1-rc.1 were signed as `aesir-oss/pixi-sbom`;
[Installation](installation.md#checking-where-a-binary-came-from) shows how to verify them.

**A CA bundle from before the eMudhra distrust is called out.** On 2026-10-20 browsers and certifi stopped trusting
emSign ECC Root CA - G3, whose intermediates had trivially weak keys
([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)). A bundle given by `--ca-bundle`,
`PIXI_SBOM_CA_BUNDLE` or `SSL_CERT_FILE` replaces the operating system's trust store, so an older certifi
`cacert.pem` keeps trusting that root. pixi-sbom now warns when the bundle it loads still contains it, matched by
fingerprint, so certifi 2026.10.19, which keeps eMudhra's other roots, passes quietly. The run, its output and its exit
code are unchanged. With no bundle set, the platform store is used and the operating system's update covers it.
[When a root is distrusted](cli.md#when-a-root-is-distrusted) says what to do in either case.

**TLS rejects the eight compromised emSign intermediates.** rustls-webpki 0.103.16 refuses any certificate path through
them, whatever the trust anchors say (RUSTSEC-2026-0382), so a stale bundle no longer lets them through. That covers
every connection with a bundle, and every connection on Linux. On macOS and Windows the platform verifier uses the
system's own verification, and the system update covers it. The `webpki-roots` crate in the dependency tree moves to
1.0.10, which drops emSign ECC Root CA - G3 (RUSTSEC-2026-0381). pixi-sbom never trusts those built-in roots.

**Reading a `.conda` archive uses a patched zstd.** pixi-sbom decompresses a `.conda` file's `info` member when it reads
an archive. zstd-safe 8.2.0 no longer exposes uninitialised memory when a legacy frame fails part way
(RUSTSEC-2026-0403); zstd 0.14.3, zstd-sys 2.1.2 and ctutils 0.4.6 fix the rest of the batch (RUSTSEC-2026-0391,
RUSTSEC-2026-0398, RUSTSEC-2026-0410, RUSTSEC-2026-0385), none of which pixi-sbom's own use reaches.

**`--primary-purl pypi` names a conda package after its PyPI project.** Grype matches a Python package by name, not
purl, so `nbconvert-core` with purl `pkg:pypi/nbconvert` never met nbconvert's advisories, and neither did
`brotli-python`, `matplotlib-base` or `pytorch`. With `--primary-purl pypi` they are now named `nbconvert`, `brotli`,
`matplotlib` and `torch`, and `pixi:conda-name` keeps the conda name. Without the flag nothing changes.

**setuptools no longer takes a vendored project's identity.** With `--prefix`, a conda package's PyPI purl was read
from the first `dist-info` it installed, and setuptools installs only an egg-info of its own beside the dist-infos of
what it vendors, so it was given `pkg:pypi/autocommand`. Only a dist-info directly in `site-packages` counts now, and
a package with none is read from its own `egg-info`, so setuptools is `pkg:pypi/setuptools` and meets its advisories.

## 1.15.0

**`--version-details` gives each proxy setting its own line.** `offline`, `proxy` and `no-proxy` used to share one
line, which wrapped once a real proxy URL and `NO_PROXY` list were in it; each now has a line of its own, aligned with
the rest.

**A plain `pyproject.toml` is pointed at `pylock.toml`.** Given as `--lockfile` with no `[tool.*]` table naming its
tool, it now gets the standard route first: `uv pip compile pyproject.toml -o pylock.toml` or `pip lock .` (pip
25.1+) writes a PEP 751 lock pixi-sbom reads; `uv lock`, `poetry lock` and `pdm lock` follow.

**Why an SBOM comes from a lock.** [It never resolves](without-pixi.md#it-never-resolves) now says what an SBOM
written from ranges would lose (exact versions, the transitive graph, hashes and sources) and what the manifest beside
a lock still adds.

**TLS is on rustls 0.23.46**, which fixes four advisories published against 0.23.45 (RUSTSEC-2026-0346 to 0349),
among them one where an unauthenticated server could steer later connections to the same host onto classical key
exchange.

## 1.14.0

**YAML is read by a parser written in safe Rust.** `conda-lock.yml`, `environment.yml`, `pnpm-lock.yaml`,
`pnpm-workspace.yaml` and yarn berry's `yarn.lock` are now parsed with
[serde-saphyr](https://crates.io/crates/serde-saphyr) instead of `serde_yaml`, which is deprecated and built on an
unmaintained C translation (RUSTSEC-2024-0449). The SBOMs it writes are unchanged. **Building from source now needs
Rust 1.89** (it was 1.88); the binaries, wheels and conda package are not affected.

**Every release is downloadable from aesir-oss/pixi-sbom.** Releases first made in millsks/pixi-sbom (up to 1.11.x) and
aesir-oss/pixi-ext-contrib (1.12.0 to 1.13.1) were copied to its releases page with all their files, and the GitHub
Action now installs every version from there, so pinning an old `version` keeps working whatever happens to those
repositories. Their provenance still names the repository that built them; [Installation](installation.md) shows how to
check it offline.

## 1.13.2

**pixi-sbom has its own repository again,
[aesir-oss/pixi-sbom](https://github.com/aesir-oss/pixi-sbom),** with its documentation at
[aesir-oss.github.io/pixi-sbom](https://aesir-oss.github.io/pixi-sbom/). Releases are tagged `vX.Y.Z` there, as they
were before 1.12.0. Nothing about installing or running it changes: `pixi global install pixi-sbom`,
`uv tool install pixi-sbom` and `uses: aesir-oss/pixi-sbom-action@v1` find the new releases on their own. To check a
release's provenance, pass `--repo aesir-oss/pixi-sbom`; releases 1.12.0 to 1.13.1 stay in
aesir-oss/pixi-ext-contrib, and still verify there.

## 1.13.1

**No longer on crates.io.** pixi-sbom is not published to crates.io after 1.13.0: `cargo install pixi-sbom` and
`cargo binstall pixi-sbom` stay at 1.13.0. Every other way to install it is unchanged and gets new releases as
before: `pixi global install pixi-sbom` (conda-forge), `uv tool install pixi-sbom` or `pip install pixi-sbom` (PyPI),
and the release archives.

**The docs have moved.** pixi-sbom's documentation is now at
[aesir-oss.github.io/pixi-ext-contrib/pixi-sbom/](https://aesir-oss.github.io/pixi-ext-contrib/pixi-sbom/), one site
per extension beside [pixi-policy](https://aesir-oss.github.io/pixi-ext-contrib/pixi-policy/)'s, with a switcher
between them. Old links (`/pixi-ext-contrib/latest/cli/`) still land on the same page. `--help` and the SARIF report's
`informationUri` point at the new address.

**Nothing else changes for you.** The license verdict, the lockfile reader and the terminal styling now live in code
pixi-sbom shares with pixi-policy, so the two tools give the same license verdict on the same package. The output of
every command is the same as 1.13.0's.

## 1.13.0

**Every environment in a container image, in one command.** `--scan` now finds installed environments as well as
lockfiles: a conda environment, a venv or a Python installation anywhere under the directory, each named by its path
(`/opt/conda/envs/app`). Unpack an image and scan it, and every conda environment and venv in it is one document:
`docker export … | tar -x -C rootfs`, then `pixi sbom --scan rootfs --merge`. A project's own `.pixi/envs` and
`.venv` are left to its lockfile, so a source tree lists nothing twice, and `--skip-input installed` turns it off.
The image's operating system packages are still syft's.

**A JavaScript project with no lockfile.** When a project has a `package.json` and an installed `node_modules` but
no `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`, pixi-sbom now reads what is installed: every package, the
dependency graph as Node resolves it and development scope from `devDependencies`, whether npm, yarn or pnpm installed
it. It joins a pixi workspace's document like a lockfile would; a lockfile, when there is one, still wins.

## 1.12.0

pixi-sbom has a new home, [aesir-oss/pixi-ext-contrib](https://github.com/aesir-oss/pixi-ext-contrib), a
workspace for pixi extensions it now shares with the tools to come. Nothing about running it changes.

- **Releases** come from the new repository, tagged `pixi-sbom-v1.12.0` and so on. The archive names, the
  PyPI and crates.io packages and the conda-forge package are unchanged.
- **The tool URL in every SBOM** (CycloneDX `metadata.tools`, SPDX 3 `Tool`, the GitHub dependency
  snapshot's detector) now points at the new repository.
- **The docs** live at [aesir-oss.github.io/pixi-ext-contrib](https://aesir-oss.github.io/pixi-ext-contrib/).
- **pre-commit**: point `repo:` at `https://github.com/aesir-oss/pixi-sbom-pre-commit`. The old mirror
  keeps its existing tags.
- **The GitHub Action** moves to its own repository: `uses: aesir-oss/pixi-sbom-action@v1`. It installs releases
  from either repository, and `uses: millsks/pixi-sbom@v1` keeps working.

It also reads more out of an installed environment (`--prefix`):

- **Native libraries bundled in wheels and packages.** With `--embedded-sboms`, the copies of openssl, libwebp,
  zlib, sqlite, libcurl, libxml2, expat, libpng and libjpeg-turbo that wheels carry in `<dist>.libs/` or
  `.dylibs/` are listed under the package that ships them, with their versions read out of the binaries and a CPE
  a scanner can match. The libwebp inside Pillow 10.0.0's wheels now gets Grype's CVE-2023-4863 finding. Like vendored
  copies, they are not installs, so `--report diff` leaves them out.
  ([Bundled native libraries](output-format.md#bundled-native-libraries))
- **Where each component was found.** CycloneDX `evidence.occurrences` gives the path inside the environment:
  the conda-meta record, the dist-info, the binary. ([Installed environments](output-format.md#installed-environments))

And JavaScript projects:

- **`package-lock.json`, `pnpm-lock.yaml` and `yarn.lock`** are inputs of their own: `pkg:npm` components with the
  dependency graph, SHA-512 hashes from `integrity`, workspace members, and development dependencies marked as such.
  Found beside a pixi or Python lockfile, by the upward search or `--scan`, they join that lockfile's document;
  `--skip-input` leaves out any lockfile, so `--skip-input javascript` gives the workspace alone and
  `--skip-input pixi` the JavaScript project alone. ([Reading JavaScript lockfiles](cli.md#reading-javascript-lockfiles))

Fixed:

- **A closed pipe is not an error.** `pixi sbom --doctor | head -12`, or any document or report piped into a reader
  that stops early, no longer ends with `Broken pipe` and exit 1: the rest of the output is dropped quietly and the
  exit code is the run's own. ([Exit codes and errors](cli.md#exit-codes-and-errors))
- **A path or editable package is no longer drift.** pixi locks one with no version and the installed environment
  knows it, so `--prefix --against pixi.lock` reported a version change for a package that had not changed. A version
  one side does not know is now no change, as an unknown license already was.
  ([Does this venv still match its lock?](cli.md#does-this-venv-still-match-its-lock))

## 1.11.0

1.11.0 looks past Python inside a conda environment. R packages, the Go modules compiled into Go programs and the
npm packages under `node_modules` now get identities an advisory database can match. The Grype comparison CI runs
now covers six environments, Go and JavaScript among them, and for each, Grype finds nothing from syft's document
that it misses from pixi-sbom's.

**R packages carry their CRAN identity, so OSV finds their advisories.** An `r-*` conda package had only a
`pkg:conda` purl, which no advisory database indexes. Each one that is on CRAN now also has a `pkg:cran` purl, named
and versioned as CRAN spells it (`r-rcpp` 1.0.13_1 is `pkg:cran/Rcpp@1.0.13-1`). The name comes from the package's own
`DESCRIPTION` file, in the environment or in the package cache, and from a generated table otherwise.
`--vulnerabilities osv` then reports, for example, RSEC-2023-8 against commonmark 1.8.0. Bioconductor, GitHub and
base-R packages get none. Grype has no CRAN advisories, so for R this is OSV's and osv-scanner's. See
[CRAN identities for R packages](output-format.md#cran-identities-for-r-packages).

**The Go modules inside a conda environment's Go programs are listed.** conda-forge builds `gh`, `go-yq`,
`terraform` and the rest from source, so the conda record names the package and nothing in it. With `--prefix` and
`--embedded-sboms`, each Go binary's build information is read, the list `go version -m` prints, and every module
becomes a `pkg:golang` component under the package that ships it, with the Go standard library as
`pkg:golang/stdlib`. The `16-go-tools` example (`go-yq` and `gh`) gives 186 modules, the ones `go version -m` lists,
and Grype finds the same Go advisories in it as in syft's document. See
[Go modules inside a binary](output-format.md#go-modules-inside-a-binary).

**`--prefix` lists the npm packages installed in a conda environment.** `nodejs` brings npm and the packages npm
itself depends on, and a JavaScript tool such as `configurable-http-proxy` brings its own; none of them was in the
document. Every package under the environment's `node_modules` is now a `pkg:npm` component under the conda package
that installed it, with its dependencies and license, so OSV and Grype check them. The `17-node-tools` example gives
220 releases, exactly the ones syft lists with its installed-package cataloger on. By default, syft reads only
JavaScript lockfiles in a directory and lists none of them. See
[npm packages in an environment](output-format.md#npm-packages-in-an-environment).

**Three new examples to try these on.** `examples/projects/pixi/15-r-analysis`, `16-go-tools` and `17-node-tools`,
also locked by conda-lock and as explicit specs, are conda environments with R, Go and JavaScript packages in them.
Install one and point `--prefix` at it; see [Try it on the examples](try-the-examples.md).

**A worked example of submitting to GitHub's dependency graph.** This repository now submits its own pixi
environments with the Action's `dependency-submission` input on every push that changes the lockfile:
[`dependency-graph.yml`](https://github.com/millsks/pixi-sbom/blob/main/.github/workflows/dependency-graph.yml),
linked from [the Action's Dependabot section](github-action.md#dependabot-alerts).

## 1.10.0

1.10.0 is about what a scanner can do with pixi-sbom's documents. Describing an installed environment offline,
pixi-sbom now gives Grype everything syft's document does and more: on the installed Django example, with
`--primary-purl pypi`, Grype finds 94 advisories against 82 from syft's document of the same directory. CI checks
this on four environments on every change to identity code; [pixi-sbom and syft](syft.md) has the comparison.

### What a scanner finds

**Native conda packages carry a CPE, so Grype finds their advisories.** openssl, libtiff, sqlite, python and about
eighty other native libraries from a conda channel have only a `pkg:conda` purl, which no advisory database
indexes, so a CPE-matching scanner reported nothing for them. They now carry the CPE NVD uses, from a curated table,
in CycloneDX, SPDX 2.3 and SPDX 3.0.1, by default. On the Django example, Grype's findings from the default
document went from 0 to 36. A package that is not in the table gets no CPE: one is never guessed from a name.
`--explain` shows where a CPE came from. See [CPEs for native conda packages](output-format.md#cpes-for-native-conda-packages).

**`--prefix` reads a conda package's PyPI identity from what it installed, offline.** A conda-installed Django,
Pillow or sqlparse had only its `pkg:conda` purl unless `--pypi-mapping prefix` downloaded the name mapping. The
`dist-info` the package put in site-packages already names the PyPI project and version, and the conda record says
which package installed it, so the identity is now read from disk.

**pixi-sbom says when a scanner would miss packages.** Grype and other scanners read only a package's primary purl,
and by default a conda-installed Python package's primary purl is `pkg:conda`: on the Django example Grype found
none of django's 27 vulnerabilities. A run that writes a CycloneDX or SPDX document now warns once when that applies,
naming `--primary-purl pypi` and the `primary-purl` configuration key; setting either, to `pypi` or `conda`,
silences it. `--report quality` counts the same packages in a new **PyPI identity** row, and native packages a
scanner cannot match in a **scanner identity** row; neither is scored, so `--min-quality` results do not move. The
CI recipes have a [Scanning with Grype](ci-recipes.md#scanning-with-grype) section. The default changes in 2.0 (#478).

**A plain Python installation lists its interpreter.** `--prefix` on a container's `/usr/local` listed only what
pip installed, though most advisories against such an image are against Python itself. The interpreter is now a
`python` component at its full version, with CPython's CPE. On `python:3.12-slim`, Grype finds 8 CPython
vulnerabilities in the document that it found none of before.

**`--embedded-sboms` finds Python distributions vendored inside packages.** setuptools ships packaging, wheel and a
dozen more in `setuptools/_vendor/`, and a vendored copy can lag the installed one. With `--prefix`, each is now a
component under the package that ships it, with its own PyPI identity, so scanners check it too. `--report diff`
does not count them as installs.

### New checks

**`--verify-files` checks an installed conda environment against itself.** conda-meta records the SHA-256 of every
file a package installed; with `--prefix`, `--verify-files` hashes each one and records modified and missing files on
the package (`pixi:modified-files`, `pixi:missing-files`), and `--report files` lists them. Either ends the run with
the new exit code 11. `.pyc` files Python regenerated are counted but never fail it. It is offline and opt-in: the
Django example's 13,241 files take about 0.3 s.

**`--format github` puts a pixi environment in GitHub's dependency graph.** It writes GitHub's dependency
submission snapshot, so an environment's packages show up in the dependency graph and get Dependabot alerts,
without syft in the pipeline. Conda packages with a PyPI identity are submitted by it, since that is where GitHub's
advisories are. The Action submits it with `dependency-submission: "true"`.

### Licenses and grading

**A bare license name is no longer given a version.** A package declaring `LGPL`, `GPL`, `AGPL` or `BSD` was written
as `LGPL-2.0-only`, `GPL-2.0-only`, `AGPL-3.0` or `BSD-2-Clause`, versions and clause counts the package never
stated, which a license policy then judged as if they were real. Bare family names are now kept as free text, and
`MIT License` is now `MIT`. **This can change a license gate's result:** with `--require-license` or an allow list,
a package declaring a bare `BSD` is now a violation where it passed as `BSD-2-Clause` before.

**`--report quality` grades other tools' documents on the same terms.** A syft SBOM's suppliers (`Person: ...` in
SPDX, `author` in CycloneDX) and CPEs were not read, so its supplier and identifier scores were 0 and a document that
did identify its packages looked as if it did not. They are read now, and a CPE counts as the unique identifier
alongside a purl, as the NTIA minimum elements allow (the purl count is still shown). Read with `--from-sbom` and
written again, those suppliers and CPEs are kept.

### Installed environments

**`--prefix` lists each pip-installed package once in a conda-forge environment.** conda-forge's Python ships a
`lib/python3.1` symlink to `lib/python3.11`, and packages installed with pip or uv were read through both, so each
appeared twice with the same `bom-ref` or SPDXID. That made the document invalid CycloneDX and SPDX. Site-packages
is now read once, through the real directory.

**`--prefix` records the scanned environment's platform, not the scanning machine's.** A Python installation with
only pure-Python packages, such as a container's `/usr/local`, named no platform, so the document took the platform
of the machine doing the scan: a Linux image scanned on a Mac said `osx-arm64`. The platform now comes from the
interpreter's or standard library's compiled files first. `pixi:python-version` is the full `X.Y.Z` where the
installation ships its headers, and `3.12` is no longer taken as older than `3.9`.

**An installed environment's document no longer names paths on the machine that made it.** `--prefix` recorded a
pip package's `file:///…/site-packages/…dist-info` as its location, and each conda package's extraction directory
as a full path into the user's cache (`/Users/<name>/Library/Caches/rattler/…`). The first is dropped, the second
keeps only the directory's name in the package cache (`pixi:extracted-package-dir` keeps its name), and an editable
install's `pixi:direct-url` is relative to the project (`./libs/utils`), as the lockfile writes it. The same
environment at two paths now gives the same document.

### The command line

**`--help` groups its flags.** The 70-odd flags were one list; they are now in sections (General, Input,
Configuration, Output, Environment and platform, Enrichment, Filtering, License policy, Quality gates,
Vulnerabilities, Reports, Network and cache, Diagnostics). Each section opens with a rule, `── INPUT ────…`, set
apart by blank lines and coloured in a terminal, so a new one is plain even with colour off. The
[CLI reference](cli.md#options) follows the same grouping.

**Tab completion lists flags alphabetically.** It offered them in the order they are declared in the code, so in
zsh `--fail-on-yanked` sat far from `--fail-on-kev` and a half-remembered name meant reading all of them. Every shell
now gets flags and their values in alphabetical order.

## 1.9.0

**Tab completion.** Flags, the values they take (`--report <TAB>` lists the report kinds,
`--format <TAB>` the formats) and file paths complete after one line in your shell's startup file:
bash (including macOS's own bash 3.2), zsh, fish, PowerShell 7, Windows PowerShell 5.1 and elvish.
See [shell completion](installation.md#shell-completion). Pressing Tab reads no lockfile and makes
no request, so it answers at once even behind a slow proxy.

**`pixi sbom` with a space completes too, through a short snippet.** pixi doesn't yet hand an
extension's arguments to the extension ([prefix-dev/pixi#7225](https://github.com/prefix-dev/pixi/issues/7225)
asks it to). Until it does, the installation page has a snippet for bash, zsh, fish and PowerShell.
CI runs every snippet in a real shell on Linux, macOS and Windows. pixi-sbom's completion already
uses the mechanism pixi would forward to, so when pixi does, `pixi sbom` completes with no snippet.

## 1.8.2

**Merging SBOMs no longer flags two files of one PyPI release as a conflict.** A bare
`pkg:pypi/six@1.17.0` stands for every file of that release, so one document recording the wheel's
hash and another recording the sdist's describe the same package. `--from-sbom` merges used to log a
warning and record a `pixi:merge-conflict` for that. Now hashes count as a disagreement only when the
purl names one file: a conda build, or a `file_name` qualifier. A license disagreement is still a
conflict, as before.

**New in the docs:** a [field manual](field-manual/index.md) of task-based playbooks, a hands-on
[training lab](lab.md) that runs offline on the repository's examples, a
[Try it on the examples](try-the-examples.md) tour, and this page.

## 1.8.1

**`--report outdated` no longer stops counting at 50.** prefix.dev, the default conda index, returns
versions 50 to a page. Only the first page was read, so a package more than 50 releases behind was
reported as exactly 50 behind: django 3.2.12 on conda-forge showed 50 instead of 83. The later pages
are now read. The newest version and the major/minor/patch step were always right.

## 1.8.0

### Someone else's SBOM

A vendor ships an SBOM, and a pipeline gates on it. 1.8 makes that safe to do:

- **Grade it first.** `--report quality` scores a document from 0 to 100 on the NTIA minimum
  elements plus license and hash coverage, and `--min-quality <N>` fails the run (exit 10) below a
  threshold. A document without purls or a dependency graph passes a vulnerability gate by having
  nothing to match; this catches it. See
  [How complete the document is](cli.md#how-complete-the-document-is).
- **Apply their VEX.** `--vex-in` reads CycloneDX or OpenVEX statements and applies them before the
  gate. `not_affected`, `false_positive` and `resolved` clear a finding; `exploitable` and
  `in_triage` are recorded but leave it open. The report says which file each statement came
  from. See [Applying a vendor's VEX](cli.md#applying-a-vendors-vex).
- **Merge documents.** Give `--from-sbom` more than once, or add `--merge` to `--scan`, and you get
  one document: packages deduplicated by purl, each input's root kept under a new one, and any
  disagreement about a license or hash recorded rather than silently settled. See
  [Merging documents](cli.md#merging-documents).
- **Report on purls alone.** `--report outdated` and `--scorecard` work on a document that
  carries nothing but purls, such as one from syft.

### Which findings to fix first

`--epss` adds FIRST's Exploit Prediction Scoring System: for each finding with a CVE alias, the
probability of exploitation in the next 30 days and its percentile. KEV says what is already
exploited; EPSS ranks the rest. `--fail-on-epss <P>` joins the vulnerability gate (exit 4). See
[Exploit likelihood (FIRST EPSS)](cli.md#exploit-likelihood-first-epss).

### More inputs, better diagnostics

- **A fully pinned `requirements.txt` is read directly,** with its graph taken from the `# via`
  comments pip-compile and uv write. A file with ranges is refused, naming the first line that is
  not pinned. Give it with `--lockfile`; see
  [Reading a pinned requirements.txt](cli.md#reading-a-pinned-requirementstxt).
- **A manifest given where a lock was expected names the command that locks it,** for example
  "pyproject.toml is a Poetry project's manifest: run `poetry lock` beside it".
- **PyPI project URLs supply the repository** for Poetry and PDM packages, so `--scorecard` finds
  more of them.

### Fixes worth knowing about

- A PyPI package installed from git, a path or a URL is no longer looked up on PyPI by name. The
  index would describe an unrelated project. `--report outdated` lists such packages under
  *Not checked*.
- A requirements file compiled by `uv pip compile` is evaluated for the Python and platform it was
  compiled for, not the machine reading it.
- A Poetry lockfile that gives a package one marker per dependency group is read. Poetry 2 writes
  this when the groups need the package in different places.

### Examples

`examples/projects` now has pixi workspaces, pinned and unpinned `requirements.txt` projects, and the
other readers' projects, more than a hundred in all, each written by the tool that owns its format.
They're the fastest way to try any of the above.

## 1.7.0

**pixi-sbom no longer needs pixi.**

- **Other lockfiles.** It reads `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml` (PEP 751),
  `conda-lock.yml` and explicit conda spec files, and the upward search and `--scan` find all of
  them. The manifest beside the lockfile says which packages the project declared, and dependency
  groups and extras become CycloneDX `scope` and SPDX dev/optional relationships. See
  [Using pixi-sbom without pixi](without-pixi.md).
- **Plain venvs.** `--prefix` describes a plain venv or site-packages, not only conda
  environments. `--infer-extras` labels the extras it infers there.
- **Comparing a venv with its lock.** `--against` accepts every supported lockfile, so
  `--prefix .venv --against uv.lock --report diff` answers "does the venv still match its lock?".
- **Distribution.** Python wheels on PyPI (`uvx pixi-sbom`, `pip install pixi-sbom`), and
  [pre-commit hooks](ci-recipes.md#pre-commit) that write the SBOM and enforce the license policy.
  The action gained `prefix` and `from-sbom` inputs.

**Upgrading:** a package installed from git, a path or an editable checkout no longer claims a
`pkg:pypi` purl. That purl named a release that may not exist, or that holds other code. If you
match those purls downstream, expect them to change.

## 1.6.0

**prefix.dev is the default conda index** for `--report outdated`, which batches its questions and
reports each build's own date. anaconda.org stays one flag away
(`--conda-index-kind anaconda`) or one configuration key away.

**Upgrading:** if your network blocks `prefix.dev`, set `conda-index-kind = "anaconda"` in a
configuration file. `--doctor` shows which index a run uses. The two indexes can legitimately
disagree for a release in its first hour; see
[How far behind the environment is](cli.md#how-far-behind-the-environment-is).

VEX output also gained machine-readable `not_affected` justifications and `analysis.response`.

## 1.5.0

**Large workspaces on slow networks.**

- `--concurrency` (and `PIXI_SBOM_CONCURRENCY`, and a configuration key) sets how many requests are
  in flight. It no longer follows the core count, so a CPU-limited container stops asking one
  thing at a time.
- A rate limit is retried rather than reported as a missing upstream
  ([A rate-limited run](troubleshooting.md#a-rate-limited-run)).
- One HTTP agent is shared so connections are reused, and prefix.dev is asked about ten packages
  per request.
- The cache counts are honest: a fetch is counted as a fetch, not a cache hit.

## 1.4.0

**The configuration can choose the conda index,** and the configuration is read from pixi's own
system and user directories as well as the project's. See
[Configuration file](cli.md#configuration-file). A package from a mirrored channel is now matched to
the channel it was mirrored from by its hash, not its name.

## 1.3.0

**Private channels.** The credentials pixi already keeps (`pixi auth login`, `RATTLER_AUTH_FILE`,
`~/.netrc`) are used for the requests that need them, and the trace log says which credentials a
request carried. See
[A channel that needs credentials](troubleshooting.md#a-channel-that-needs-credentials).

## 1.2.0

**A second conda index.** `--conda-index-kind prefix` asks prefix.dev instead of anaconda.org, and a
named index is asked about every channel the lockfile uses, not only anaconda.org's. In 1.6 it became
the default.

## 1.1.0

**Restricted networks.** Every upstream can be pointed at a mirror, conda and wheel archive hosts
included. `--doctor` on its own probes every upstream the build knows about, including the archive
hosts the lockfile names. See [Every upstream it can reach](cli.md#every-upstream-it-can-reach) and
[A blocked host](troubleshooting.md#a-blocked-host).
