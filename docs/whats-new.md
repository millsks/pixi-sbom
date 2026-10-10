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

## Unreleased

**Tab completion for `pixi-sbom`.** Flags, the values they take and file paths complete in bash,
zsh, fish, PowerShell and elvish after one line in the shell's startup file
([shell completion](installation.md#shell-completion)). pixi itself doesn't yet hand an
extension's arguments to the extension (that has been asked for), so `pixi sbom` with a space
completes through a short snippet per shell from the same page, which CI runs in each shell.

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
