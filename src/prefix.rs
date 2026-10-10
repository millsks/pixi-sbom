//! `--prefix <DIR>`: describe an installed environment that has no lockfile: a `pixi global`
//! environment, a conda / mamba / micromamba environment, a venv, a Python installation inside a
//! container. Conda packages come from `conda-meta/<name>-<version>-<build>.json` (the same
//! fields as a lock record), pip-installed packages from `site-packages/*.dist-info` (`METADATA`,
//! and in a conda environment `INSTALLER` to leave the ones conda put there to their conda
//! package). The layout decides which: see [`Layout`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use pep508_rs::{ExtraName, Requirement, VerbatimUrl};
use serde::Deserialize;

use crate::lock::{DeclaredDeps, link_dependencies};
use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl::{self, CondaPurl};
use crate::wheel;

/// Why a prefix could not be read.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PrefixError {
    #[error(
        "{path} is not an environment: looked for conda-meta/, pyvenv.cfg, lib/python3.*/site-packages and \
         Lib/site-packages, found {found}"
    )]
    #[diagnostic(
        code(pixi_sbom::prefix::not_an_environment),
        help(
            "--prefix takes the top directory of an environment: a conda or pixi environment (~/.pixi/envs/<name>), \
             a venv (the directory holding pyvenv.cfg), or a Python installation (the directory holding lib/)"
        )
    )]
    NotAnEnvironment {
        path: PathBuf,
        /// What the directory holds instead, or why there is nothing to look at.
        found: String,
    },
    #[error("cannot read {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::prefix::read),
        help(
            "--prefix reads conda-meta and site-packages under a conda environment directory; check that the \
             path is one of those and that it is readable"
        )
    )]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse the conda-meta record {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::prefix::record),
        help(
            "the message names the conda-meta record that failed; reinstall that package into the environment, \
             or leave it out with --exclude"
        )
    )]
    Record {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// The fields of a `conda-meta` record this tool reads.
#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    version: String,
    build: String,
    #[serde(default)]
    build_number: Option<u64>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    subdir: Option<String>,
    #[serde(default, rename = "fn")]
    file_name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    license_family: Option<String>,
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    noarch: Option<serde_json::Value>,
    #[serde(default)]
    extracted_package_dir: Option<String>,
    /// What the package installed, relative to the prefix.
    #[serde(default)]
    files: Vec<String>,
}

/// What `pixi:declared-in` says of a package the user asked for by name: a dist-info with a
/// PEP 376 `REQUESTED` file, or a conda spec the environment's `conda-meta/history` records.
pub const REQUESTED: &str = "requested";

/// The conda package names the user asked for, from `conda-meta/history`: every `# update specs`
/// line adds its specs' names, every `# remove specs` line takes them away again.
fn requested_conda(prefix: &Path) -> std::collections::BTreeSet<String> {
    let text = std::fs::read_to_string(prefix.join("conda-meta").join("history")).unwrap_or_default();
    let mut requested = std::collections::BTreeSet::new();
    for line in text.lines() {
        let (add, specs) = if let Some(specs) = line.strip_prefix("# update specs:") {
            (true, specs)
        } else if let Some(specs) = line.strip_prefix("# remove specs:") {
            (false, specs)
        } else {
            continue;
        };
        let names = specs
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .filter_map(|spec| {
                let spec = spec.trim().trim_matches(['\'', '"']);
                // `conda-forge::numpy>=2` or `conda-forge/linux-64::numpy`: the name after the channel.
                let spec = spec.rsplit("::").next().unwrap_or(spec);
                let name: String = spec
                    .chars()
                    .take_while(|c| !matches!(c, '=' | '<' | '>' | '!' | '~' | ' ' | '['))
                    .collect();
                (!name.is_empty()).then(|| name.to_lowercase())
            });
        for name in names {
            if add {
                requested.insert(name);
            } else {
                requested.remove(&name);
            }
        }
    }
    requested
}

/// Mark `package` as asked for by the user.
fn mark_requested(package: &mut Package) {
    package
        .properties
        .insert(crate::manifest::DIRECT_PROPERTY.into(), "true".into());
    package
        .properties
        .insert(crate::manifest::DECLARED_IN_PROPERTY.into(), REQUESTED.into());
}

/// `true` on a package whose `pixi:python-extras` was inferred by `--infer-extras`, not read.
pub const EXTRAS_INFERRED_PROPERTY: &str = "pixi:python-extras-inferred";
/// What an inference rests on: each extra and the installed packages it requires,
/// `socks: pysocks; security: cryptography, pyopenssl`.
pub const EXTRAS_EVIDENCE_PROPERTY: &str = "pixi:python-extras-evidence";

/// `--infer-extras`: an installed environment does not record which extras a package was
/// installed with, so guess them. An extra counts as active when it gates at least one
/// requirement whose other markers hold for this interpreter and platform, and every such
/// requirement is installed. It can be wrong (the packages may be there for another reason),
/// which is why it is opt-in and labelled with [`EXTRAS_INFERRED_PROPERTY`].
pub fn infer_extras(prefix: &Path, sbom: &mut Sbom) {
    let Some(python) = crate::pyversion::interpreter(sbom) else {
        tracing::warn!("--infer-extras: no interpreter version known for this environment; nothing inferred");
        return;
    };
    let env = match crate::pylock::marker_environment(&sbom.platform, &python.to_string()) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(platform = %sbom.platform, %err, "--infer-extras: cannot evaluate markers; nothing inferred");
            return;
        }
    };
    let installed: std::collections::BTreeSet<String> = sbom
        .packages
        .iter()
        .map(|p| purl::normalize_pypi_name(&p.name))
        .collect();
    let mut inferred: BTreeMap<String, Vec<(String, Vec<String>)>> = BTreeMap::new();
    for dist_info in dist_infos(prefix) {
        let Ok(metadata) = std::fs::read_to_string(dist_info.join("METADATA")) else {
            continue;
        };
        let headers = wheel::parse_headers(&metadata);
        let Some(name) = headers.get("name").and_then(|v| v.first()) else {
            continue;
        };
        let mut by_extra: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for text in headers.get("requires-dist").into_iter().flatten() {
            let Ok(requirement) = Requirement::<VerbatimUrl>::from_str(text) else {
                tracing::debug!(package = %name, requirement = %text, "--infer-extras: unparsable requirement");
                continue;
            };
            if requirement.marker.evaluate(&env, &[]) {
                continue;
            }
            for extra in crate::extras::gating_extras(&requirement.marker.try_to_string().unwrap_or_default()) {
                let Ok(extra_name) = ExtraName::from_str(&extra) else {
                    continue;
                };
                if requirement.marker.evaluate(&env, std::slice::from_ref(&extra_name)) {
                    by_extra
                        .entry(extra)
                        .or_default()
                        .push(purl::normalize_pypi_name(requirement.name.as_ref()));
                }
            }
        }
        let active: Vec<(String, Vec<String>)> = by_extra
            .into_iter()
            .filter(|(_, needs)| needs.iter().all(|n| installed.contains(n)))
            .map(|(extra, mut needs)| {
                needs.sort();
                needs.dedup();
                (extra, needs)
            })
            .collect();
        if !active.is_empty() {
            inferred.insert(purl::normalize_pypi_name(name), active);
        }
    }
    for package in sbom.packages.iter_mut().filter(|p| p.kind == PackageKind::Pypi) {
        let Some(active) = inferred.get(&purl::normalize_pypi_name(&package.name)) else {
            continue;
        };
        if package.properties.contains_key(crate::extras::PYTHON_EXTRAS_PROPERTY) {
            continue;
        }
        let extras: Vec<&str> = active.iter().map(|(extra, _)| extra.as_str()).collect();
        let evidence: Vec<String> = active
            .iter()
            .map(|(extra, needs)| format!("{extra}: {}", needs.join(", ")))
            .collect();
        package
            .properties
            .insert(crate::extras::PYTHON_EXTRAS_PROPERTY.into(), extras.join(","));
        package
            .properties
            .insert(EXTRAS_INFERRED_PROPERTY.into(), "true".into());
        package
            .properties
            .insert(EXTRAS_EVIDENCE_PROPERTY.into(), evidence.join("; "));
    }
}

/// Property naming the directory the package was extracted from, for `--fetch-licenses`.
pub const EXTRACTED_DIR_PROPERTY: &str = "pixi:extracted-package-dir";

/// The environment's name: the directory's file name.
pub fn environment_name(prefix: &Path) -> String {
    prefix
        .canonicalize()
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .or_else(|| prefix.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "prefix".into())
}

/// What kind of environment a directory is, by what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `conda-meta/`: conda records, plus whatever pip installed beside them.
    Conda,
    /// `pyvenv.cfg` and no `conda-meta/`: a venv, whose packages are all in site-packages.
    Venv,
    /// Neither, but a site-packages directory: a plain Python installation.
    Python,
}

/// The layout of the directory at `prefix`, or `None` when it is not an environment.
pub fn layout(prefix: &Path) -> Option<Layout> {
    if prefix.join("conda-meta").is_dir() {
        Some(Layout::Conda)
    } else if prefix.join("pyvenv.cfg").is_file() {
        Some(Layout::Venv)
    } else if site_packages(prefix).iter().any(|dir| dir.is_dir()) {
        Some(Layout::Python)
    } else {
        None
    }
}

/// What a directory that is not an environment holds, for the error.
fn found(prefix: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(prefix) else {
        return if prefix.exists() {
            "a file, not a directory".into()
        } else {
            "nothing: it does not exist".into()
        };
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_dir() { format!("{name}/") } else { name }
        })
        .collect();
    names.sort();
    match names.len() {
        0 => "an empty directory".into(),
        n if n > 8 => format!("{} and {} more", names[..8].join(", "), n - 8),
        _ => names.join(", "),
    }
}

/// The Python version an environment without conda records was made with: `version` or
/// `version_info` in `pyvenv.cfg`, else the `pythonX.Y` of its site-packages path, made `X.Y.Z`
/// by `include/pythonX.Y/patchlevel.h` where the installation ships its headers.
fn interpreter(prefix: &Path) -> Option<String> {
    let config = std::fs::read_to_string(prefix.join("pyvenv.cfg")).unwrap_or_default();
    let from_config = config.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        matches!(key.trim(), "version" | "version_info").then(|| {
            // `3.13.5.final.0` from uv: the release, without the level and serial.
            value.trim().split('.').take(3).collect::<Vec<_>>().join(".")
        })
    });
    from_config.filter(|v| !v.is_empty()).or_else(|| {
        // conda-forge's `python3.1 -> python3.11` is not a version; and 3.12 is newer than 3.9.
        let mut versions: Vec<(Vec<u32>, String)> = std::fs::read_dir(prefix.join("lib"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| !e.path().is_symlink() && e.path().join("site-packages").is_dir())
            .filter_map(|e| {
                let version = e.file_name().to_str()?.strip_prefix("python")?.to_string();
                let key = version
                    .split('.')
                    .map(|part| part.parse().ok())
                    .collect::<Option<Vec<u32>>>()?;
                Some((key, version))
            })
            .collect();
        versions.sort();
        let (_, short) = versions.pop()?;
        Some(patchlevel(prefix, &short).unwrap_or(short))
    })
}

/// `PY_VERSION` from `include/pythonX.Y/patchlevel.h`: the full version of an installation built
/// from source, such as the official container images' `/usr/local`.
fn patchlevel(prefix: &Path, short: &str) -> Option<String> {
    let header = std::fs::read_to_string(
        prefix
            .join("include")
            .join(format!("python{short}"))
            .join("patchlevel.h"),
    )
    .ok()?;
    let version = header.lines().find_map(|line| {
        let rest = line
            .trim()
            .strip_prefix("#define")?
            .trim()
            .strip_prefix("PY_VERSION")?
            .trim();
        Some(rest.trim_matches('"').trim().to_string())
    })?;
    // `3.12.15`, or `3.13.0rc2` for a candidate: kept only when it is this installation's X.Y.
    version.starts_with(&format!("{short}.")).then_some(version)
}

/// The conda platform a wheel's platform tag was built for, when it names one.
fn tag_platform(tag: &str) -> Option<&'static str> {
    let platform = tag.rsplit('-').next()?;
    let arm = platform.contains("aarch64") || platform.contains("arm64");
    if platform.starts_with("manylinux") || platform.starts_with("musllinux") || platform.starts_with("linux") {
        Some(if arm { "linux-aarch64" } else { "linux-64" })
    } else if platform.starts_with("macosx") {
        // A universal2 wheel runs on both; it says nothing.
        (!platform.contains("universal")).then_some(if arm { "osx-arm64" } else { "osx-64" })
    } else if platform.starts_with("win") {
        Some(if arm { "win-arm64" } else { "win-64" })
    } else {
        None
    }
}

/// The conda platform a compiled file was built for, from its format and architecture. A universal
/// (fat) Mach-O file names more than one, so it names none.
fn object_platform(bytes: &[u8]) -> Option<&'static str> {
    use object::{Architecture, BinaryFormat, Object};
    let file = object::File::parse(bytes).ok()?;
    Some(match (file.format(), file.architecture()) {
        (BinaryFormat::Elf, Architecture::X86_64) => "linux-64",
        (BinaryFormat::Elf, Architecture::Aarch64) => "linux-aarch64",
        (BinaryFormat::Elf, Architecture::PowerPc64) if file.is_little_endian() => "linux-ppc64le",
        (BinaryFormat::MachO, Architecture::X86_64) => "osx-64",
        (BinaryFormat::MachO, Architecture::Aarch64) => "osx-arm64",
        (BinaryFormat::Pe, Architecture::X86_64) => "win-64",
        (BinaryFormat::Pe, Architecture::Aarch64) => "win-arm64",
        _ => return None,
    })
}

/// The platform the interpreter, or the standard library's compiled modules, were built for: what
/// a Python installation scanned from another machine (a container's root filesystem) is for,
/// rather than the machine doing the scanning.
fn binary_platform(prefix: &Path) -> Option<String> {
    let entries = |dir: PathBuf, keep: &dyn Fn(&Path) -> bool| -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| keep(p))
            .collect();
        found.sort();
        found
    };
    let named = |p: &Path, test: &dyn Fn(&str) -> bool| p.file_name().is_some_and(|n| test(&n.to_string_lossy()));
    let mut candidates = vec![prefix.join("python.exe")];
    candidates.extend(entries(prefix.join("bin"), &|p| named(p, &|n| n.starts_with("python"))));
    candidates.extend(entries(prefix.join("DLLs"), &|p| named(p, &|n| n.ends_with(".pyd"))));
    for lib in entries(prefix.join("lib"), &|p| named(p, &|n| n.starts_with("python"))) {
        let modules = entries(lib.join("lib-dynload"), &|p| named(p, &|n| n.ends_with(".so")));
        candidates.extend(modules.into_iter().take(8));
    }
    candidates.iter().find_map(|path| {
        // A real interpreter is small (it links libpython); anything huge is not worth reading.
        if std::fs::metadata(path).ok()?.len() > 64 << 20 {
            return None;
        }
        object_platform(&std::fs::read(path).ok()?).map(str::to_string)
    })
}

/// The platform the installed wheels were built for, by majority of their `WHEEL` tags.
fn wheel_platform(dist_infos: &[PathBuf]) -> Option<String> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for dist_info in dist_infos {
        let text = std::fs::read_to_string(dist_info.join("WHEEL")).unwrap_or_default();
        let platforms: std::collections::BTreeSet<&'static str> = text
            .lines()
            .filter_map(|line| line.strip_prefix("Tag:"))
            .filter_map(|tag| tag_platform(tag.trim()))
            .collect();
        for platform in platforms {
            *counts.entry(platform).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(p, _)| p.to_string())
}

/// Read the environment at `prefix` into a model. `platform` overrides the one the records
/// name.
pub fn build_sbom(prefix: &Path, root: Root, platform: Option<&str>) -> Result<Sbom, PrefixError> {
    let Some(layout) = layout(prefix) else {
        return Err(PrefixError::NotAnEnvironment {
            path: prefix.to_path_buf(),
            found: found(prefix),
        });
    };
    let mut packages = Vec::new();
    let mut declared = Vec::new();
    let mut subdirs: BTreeMap<String, usize> = BTreeMap::new();
    let meta = prefix.join("conda-meta");
    let requested = requested_conda(prefix);
    let records: Vec<PathBuf> = if layout == Layout::Conda {
        std::fs::read_dir(&meta)
            .map_err(|source| PrefixError::Read {
                path: meta.clone(),
                source,
            })?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect()
    } else {
        Vec::new()
    };
    let mut entries = records;
    entries.sort();
    for path in entries {
        let text = std::fs::read_to_string(&path).map_err(|source| PrefixError::Read {
            path: path.clone(),
            source,
        })?;
        let record: Record = serde_json::from_str(&text).map_err(|source| PrefixError::Record {
            path: path.clone(),
            source,
        })?;
        if let Some(subdir) = record.subdir.as_deref().filter(|s| *s != "noarch") {
            *subdirs.entry(subdir.to_string()).or_default() += 1;
        }
        let mut package = conda_package(&record)?;
        if let Some((purl, dist_info)) = installed_pypi_identity(prefix, &record) {
            if !package.extra_purls.contains(&purl) {
                package.extra_purls.push(purl);
            }
            // What is on disk outranks a downloaded name mapping, which then leaves it alone.
            package.purls_from_lock = true;
            package
                .properties
                .insert(crate::mapping::MAPPING_PROPERTY.to_string(), "dist-info".into());
            package.properties.insert(DIST_INFO_PROPERTY.to_string(), dist_info);
        }
        if requested.contains(&package.name.to_lowercase()) {
            mark_requested(&mut package);
        }
        packages.push(package);
        declared.push(DeclaredDeps::Conda(record.depends));
    }

    let dist_infos = dist_infos(prefix);
    for dist_info in &dist_infos {
        // Without conda records, nothing else lists what conda installed: every dist-info counts.
        let Some((package, requires)) = pypi_package(dist_info, layout == Layout::Conda)? else {
            continue;
        };
        packages.push(package);
        declared.push(DeclaredDeps::Pypi(requires));
    }
    // A plain installation (a container's /usr/local) has no package that is the interpreter,
    // though the interpreter is what most advisories against it name. A venv's is outside it,
    // and a conda environment lists its `python` package.
    if layout == Layout::Python
        && let Some(version) = interpreter(prefix)
        && let Ok(purl) = purl::generic("python", &version)
    {
        packages.push(Package {
            id: purl.clone(),
            name: "python".into(),
            version: Some(version),
            kind: PackageKind::External,
            purl,
            supplier: None,
            extra_purls: Vec::new(),
            purls_from_lock: false,
            location: String::new(),
            sha256: None,
            md5: None,
            license: None,
            license_files: Vec::new(),
            description: Some("The Python interpreter of this installation".into()),
            homepage: None,
            repository: None,
            documentation: None,
            yanked: None,
            properties: BTreeMap::from([(INTERPRETER_PROPERTY.to_string(), "true".to_string())]),
            dependencies: Vec::new(),
        });
        declared.push(DeclaredDeps::Pypi(Vec::new()));
    }

    link_dependencies(&mut packages, &declared);
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    let platform = platform
        .map(str::to_string)
        .or_else(|| {
            subdirs
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(subdir, _)| subdir)
        })
        .or_else(|| binary_platform(prefix))
        .or_else(|| wheel_platform(&dist_infos))
        .or_else(|| {
            prefix
                .join("Lib")
                .join("site-packages")
                .is_dir()
                .then(|| "win-64".to_string())
        })
        .or_else(|| rattler_conda_types::Platform::current().map(|p| p.to_string()))
        .unwrap_or_else(|| "unknown".into());
    // What the user asked for, when the environment recorded it, is what the root depends on.
    let declared_roots = packages
        .iter()
        .any(|p| p.properties.contains_key(crate::manifest::DIRECT_PROPERTY));
    Ok(Sbom {
        root,
        environment: environment_name(prefix),
        platform,
        lockfile: String::new(),
        prefix: Some(environment_name(prefix)),
        document: None,
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
        lifecycles: vec![crate::model::PHASE_INSTALLED.into()],
        declared_roots,
        scopes: std::collections::BTreeMap::new(),
        interpreter: if layout == Layout::Conda {
            None
        } else {
            interpreter(prefix)
        },
    })
}

fn conda_package(record: &Record) -> Result<Package, PrefixError> {
    let mut properties = BTreeMap::new();
    let channel_url = record.channel.clone();
    let channel = channel_url
        .as_deref()
        .and_then(purl::channel_name_from_url)
        .map(str::to_string)
        // A bare channel name (`conda-forge`) is what older records carry.
        .or_else(|| channel_url.clone().filter(|c| !c.contains("://")));
    if let Some(url) = channel_url.as_deref().filter(|c| c.contains("://")) {
        properties.insert("pixi:channel-url".into(), url.to_string());
    }
    if let Some(channel) = &channel {
        properties.insert("pixi:channel".into(), channel.clone());
    }
    if let Some(subdir) = &record.subdir {
        properties.insert("pixi:subdir".into(), subdir.clone());
    }
    properties.insert("pixi:build".into(), record.build.clone());
    if let Some(number) = record.build_number {
        properties.insert("pixi:build-number".into(), number.to_string());
    }
    if let Some(family) = &record.license_family {
        properties.insert("pixi:license-family".into(), family.clone());
    }
    if let Some(size) = record.size {
        properties.insert("pixi:size".into(), size.to_string());
    }
    if record
        .noarch
        .as_ref()
        .is_some_and(|n| !n.is_null() && n.as_bool() != Some(false))
    {
        properties.insert("pixi:noarch".into(), "true".into());
    }
    let file_name = record
        .file_name
        .clone()
        .or_else(|| {
            record
                .url
                .as_deref()
                .and_then(|u| u.rsplit('/').next())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{}-{}-{}.conda", record.name, record.version, record.build));
    let archive_type = purl::archive_type_from_file_name(&file_name).map(str::to_string);
    properties.insert("pixi:file-name".into(), file_name.clone());
    if let Some(dir) = &record.extracted_package_dir {
        properties.insert(EXTRACTED_DIR_PROPERTY.into(), dir.clone());
    }
    let purl = purl::conda(CondaPurl {
        name: &record.name,
        version: Some(&record.version),
        build: Some(&record.build),
        channel: channel.as_deref(),
        subdir: record.subdir.as_deref(),
        archive_type: archive_type.as_deref(),
    })?;
    let location = record
        .url
        .clone()
        .unwrap_or_else(|| match (&channel_url, &record.subdir) {
            (Some(channel), Some(subdir)) if channel.contains("://") => {
                format!("{}/{subdir}/{file_name}", channel.trim_end_matches('/'))
            }
            _ => file_name.clone(),
        });
    Ok(Package {
        id: purl.clone(),
        name: record.name.clone(),
        version: Some(record.version.clone()),
        kind: PackageKind::CondaBinary,
        purl,
        supplier: channel.as_ref().map(|name| Supplier {
            name: name.clone(),
            url: channel_url.clone().filter(|c| c.contains("://")),
        }),
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location,
        sha256: record.sha256.clone(),
        md5: record.md5.clone(),
        license: record.license.clone().filter(|l| !l.trim().is_empty()),
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties,
        dependencies: Vec::new(),
    })
}

/// Marks the component a plain Python installation's interpreter is described by.
pub const INTERPRETER_PROPERTY: &str = "pixi:interpreter";

/// The installed dist-info a conda package's PyPI identity was read from, relative to the prefix.
pub const DIST_INFO_PROPERTY: &str = "pixi:pypi-dist-info";

/// A conda package's PyPI identity from the `dist-info` it installed: the record's `files` name
/// the `METADATA`, and its `Name` and `Version` are the PyPI project's. No network, and no name
/// mapping that could be out of date. Returns the purl and the dist-info directory.
fn installed_pypi_identity(prefix: &Path, record: &Record) -> Option<(String, String)> {
    let mut metadata: Vec<&String> = record
        .files
        .iter()
        .filter(|file| {
            let file = file.replace('\\', "/");
            file.ends_with(".dist-info/METADATA") && file.contains("site-packages/")
        })
        .collect();
    metadata.sort();
    let file = metadata.first()?;
    let text = std::fs::read_to_string(prefix.join(file)).ok()?;
    let headers = wheel::parse_headers(&text);
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let purl = purl::pypi(&first("name")?, &first("version")?).ok()?;
    let dist_info = file.replace('\\', "/").trim_end_matches("/METADATA").to_string();
    Some((purl, dist_info))
}

/// Take the machine out of an installed environment's document, once nothing more reads the
/// files: the same environment at two paths, or on two machines, gives the same document. A pip
/// package's location (its `dist-info` directory) is dropped, since a local directory is not a
/// download location, and `pixi:extracted-package-dir` keeps only the directory's name in the
/// package cache. A local `pixi:direct-url` (an editable checkout, a wheel file) becomes relative to
/// the project, as a lockfile writes it (`./libs/utils`), or is dropped when it lies outside.
pub fn make_portable(sbom: &mut Sbom, prefix: &Path) {
    let canonical = prefix.canonicalize().unwrap_or_else(|_| prefix.to_path_buf());
    // `--prefix .pixi/envs/default`, run in the workspace, is relative: its project would be the
    // empty path, which every path starts with.
    let absolute = std::path::absolute(prefix).unwrap_or_else(|_| prefix.to_path_buf());
    let local = |location: &str| -> Option<std::path::PathBuf> {
        let path = location.strip_prefix("file://")?;
        Some(Path::new(path.strip_prefix('/').filter(|p| p.contains(':')).unwrap_or(path)).to_path_buf())
    };
    let inside = |location: &str| {
        local(location).is_some_and(|path| path.starts_with(&absolute) || path.starts_with(&canonical))
    };
    let projects: Vec<std::path::PathBuf> = [project_of(&absolute), project_of(&canonical)]
        .into_iter()
        .filter(|project| project.is_absolute() && project.parent().is_some())
        .collect();
    for package in &mut sbom.packages {
        if inside(&package.location) {
            package.location.clear();
        }
        if let Some(path) = package.properties.get(DIRECT_URL_PROPERTY).and_then(|url| local(url)) {
            let relative = projects
                .iter()
                .find_map(|project| path.strip_prefix(project).ok())
                .map(|rest| format!("./{}", rest.to_string_lossy().replace('\\', "/")));
            match relative {
                Some(relative) => package.properties.insert(DIRECT_URL_PROPERTY.into(), relative),
                None => package.properties.remove(DIRECT_URL_PROPERTY),
            };
        }
        if let Some(dir) = package.properties.get_mut(EXTRACTED_DIR_PROPERTY)
            && let Some(name) = Path::new(dir.as_str())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        {
            *dir = name;
        }
    }
}

/// PEP 610's direct URL of a pip install: where it came from when not from an index.
const DIRECT_URL_PROPERTY: &str = "pixi:direct-url";

/// The project an environment belongs to: the workspace of a pixi environment
/// (`<workspace>/.pixi/envs/<name>`), else the directory that holds it (a venv's project).
fn project_of(prefix: &Path) -> std::path::PathBuf {
    let parent = prefix.parent().unwrap_or(prefix);
    let is = |dir: Option<&Path>, name: &str| dir.and_then(Path::file_name).is_some_and(|n| n == name);
    if is(Some(parent), "envs") && is(parent.parent(), ".pixi") {
        parent.parent().and_then(Path::parent).unwrap_or(parent).to_path_buf()
    } else {
        parent.to_path_buf()
    }
}

/// What [`attach_vendored`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VendoredOutcome {
    /// Vendored distributions added as components.
    pub added: usize,
    /// Copies of one already added, vendored by another package.
    pub merged: usize,
}

/// Where a vendored distribution was found, in `pixi:embedded-sbom`: `vendored:<dir>`.
const VENDORED_SOURCE: &str = "vendored";

/// The id suffix that keeps a vendored copy apart from an installed distribution of the same
/// name and version: the two are different copies of the code.
pub const VENDORED_ID_SUFFIX: &str = "#vendored";

/// Python distributions a package ships inside itself (`setuptools/_vendor/packaging-26.0.dist-info`),
/// attached as [`PackageKind::Embedded`] components under the package that owns the directory, the
/// way [`crate::auditable`] attaches the crates in a binary. A vendored copy can lag the installed
/// one, and an advisory against it is a finding in the environment.
pub fn attach_vendored(sbom: &mut Sbom, prefix: &Path) -> VendoredOutcome {
    let mut outcome = VendoredOutcome::default();
    let owners = vendor_owners(sbom, prefix);
    let mut by_id: BTreeMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.id.ends_with(VENDORED_ID_SUFFIX))
        .map(|(i, p)| (p.id.clone(), i))
        .collect();
    for root in site_packages(prefix) {
        let Ok(tops) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut tops: Vec<PathBuf> = tops.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        tops.sort();
        for top in tops {
            let Some(top_name) = top.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            if top_name.ends_with(".dist-info") {
                continue;
            }
            for vendor in ["_vendor", "vendor"] {
                let dir = top.join(vendor);
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut dists: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && p.extension().is_some_and(|e| e == "dist-info"))
                    .collect();
                dists.sort();
                let source = format!("{VENDORED_SOURCE}:{top_name}/{vendor}");
                for dist in dists {
                    let Some((name, version)) = name_and_version(&dist) else {
                        continue;
                    };
                    let Ok(purl) = purl::pypi(&name, &version) else {
                        continue;
                    };
                    let id = format!("{purl}{VENDORED_ID_SUFFIX}");
                    let index = match by_id.get(&id) {
                        Some(&index) => {
                            let value = sbom.packages[index]
                                .properties
                                .entry(crate::embedded::SOURCE_PROPERTY.to_string())
                                .or_default();
                            if !value.split(';').any(|s| s == source) {
                                value.push(';');
                                value.push_str(&source);
                            }
                            outcome.merged += 1;
                            index
                        }
                        None => {
                            sbom.packages
                                .push(vendored_package(&id, &purl, &name, &version, &source));
                            by_id.insert(id.clone(), sbom.packages.len() - 1);
                            outcome.added += 1;
                            sbom.packages.len() - 1
                        }
                    };
                    let id = sbom.packages[index].id.clone();
                    if let Some(&owner) = owners.get(&top_name) {
                        let deps = &mut sbom.packages[owner].dependencies;
                        if !deps.contains(&id) {
                            deps.push(id);
                            deps.sort();
                        }
                    }
                }
            }
        }
    }
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    outcome
}

/// `Name` and `Version` from a dist-info's `METADATA`.
fn name_and_version(dist_info: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(dist_info.join("METADATA")).ok()?;
    let headers = wheel::parse_headers(&text);
    let first = |key: &str| {
        headers
            .get(key)
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Some((first("name")?, first("version")?))
}

/// The package that owns each top-level directory in site-packages: from the files a conda record
/// lists, and from the `RECORD` of a pip-installed dist-info. Indexes into `sbom.packages`.
fn vendor_owners(sbom: &Sbom, prefix: &Path) -> BTreeMap<String, usize> {
    let mut owners = BTreeMap::new();
    let top_of = |file: &str| -> Option<String> {
        let file = file.replace('\\', "/");
        let rest = file.split("site-packages/").nth(1).unwrap_or(&file);
        let top = rest.split('/').next()?;
        (!top.is_empty() && !top.ends_with(".dist-info") && rest.contains('/')).then(|| top.to_string())
    };
    let find = |kind: PackageKind, name: &str| {
        sbom.packages
            .iter()
            .position(|p| p.kind == kind && purl::normalize_pypi_name(&p.name) == purl::normalize_pypi_name(name))
    };
    if let Ok(records) = std::fs::read_dir(prefix.join("conda-meta")) {
        for path in records.flatten().map(|e| e.path()) {
            let Some(record) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Record>(&text).ok())
            else {
                continue;
            };
            let Some(index) = find(PackageKind::CondaBinary, &record.name) else {
                continue;
            };
            for file in record.files.iter().filter(|f| f.contains("site-packages/")) {
                if let Some(top) = top_of(file) {
                    owners.entry(top).or_insert(index);
                }
            }
        }
    }
    for dist_info in dist_infos(prefix) {
        let Some((name, _)) = name_and_version(&dist_info) else {
            continue;
        };
        let Some(index) = find(PackageKind::Pypi, &name) else {
            continue;
        };
        let record = std::fs::read_to_string(dist_info.join("RECORD")).unwrap_or_default();
        for line in record.lines() {
            if let Some(top) = line.split(',').next().and_then(top_of) {
                owners.entry(top).or_insert(index);
            }
        }
    }
    owners
}

fn vendored_package(id: &str, purl: &str, name: &str, version: &str, source: &str) -> Package {
    Package {
        id: id.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        kind: PackageKind::Embedded,
        purl: purl.to_string(),
        supplier: None,
        extra_purls: Vec::new(),
        // The dist-info on disk is the authority on what was vendored.
        purls_from_lock: true,
        location: String::new(),
        sha256: None,
        md5: None,
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties: BTreeMap::from([(crate::embedded::SOURCE_PROPERTY.to_string(), source.to_string())]),
        dependencies: Vec::new(),
    }
}

/// Every `*.dist-info` directory under the environment's site-packages, whichever layout the
/// platform uses.
pub fn dist_infos(prefix: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in site_packages(prefix) {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.extension().is_some_and(|e| e == "dist-info") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The site-packages directories an environment may have, whichever layout the platform uses:
/// `Lib/site-packages` on Windows, `lib/python3.X/site-packages` elsewhere. Each directory once:
/// conda-forge's Python ships `lib/python3.1 -> python3.11`, and reading through both would list
/// every pip-installed package twice. The real path is kept over a symlink to it.
fn site_packages(prefix: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![prefix.join("Lib").join("site-packages")];
    if let Ok(lib) = std::fs::read_dir(prefix.join("lib")) {
        let mut pythons: Vec<_> = lib
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("python"))
            .map(|entry| (entry.path().is_symlink(), entry.path()))
            .collect();
        pythons.sort();
        candidates.extend(pythons.into_iter().map(|(_, dir)| dir.join("site-packages")));
    }
    let mut seen = std::collections::HashSet::new();
    candidates
        .into_iter()
        .filter(|root| root.canonicalize().map_or(true, |real| seen.insert(real)))
        .collect()
}

/// A pip-installed package from its `dist-info`; `None` when the metadata is unusable, or when
/// `conda_records` lists what conda installed and conda installed this (its conda package is
/// already listed).
fn pypi_package(dist_info: &Path, conda_records: bool) -> Result<Option<(Package, Vec<String>)>, PrefixError> {
    let installer = std::fs::read_to_string(dist_info.join("INSTALLER")).unwrap_or_default();
    if conda_records && installer.trim().eq_ignore_ascii_case("conda") {
        return Ok(None);
    }
    let metadata = match std::fs::read_to_string(dist_info.join("METADATA")) {
        Ok(text) => text,
        Err(err) => {
            tracing::warn!(path = %dist_info.display(), %err, "dist-info without a readable METADATA; skipped");
            return Ok(None);
        }
    };
    let headers = wheel::parse_headers(&metadata);
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let (Some(name), Some(version)) = (first("name"), first("version")) else {
        tracing::warn!(path = %dist_info.display(), "dist-info METADATA without Name and Version; skipped");
        return Ok(None);
    };
    let purl = purl::pypi(&name, &version)?;
    let info = wheel::info_from_metadata(&metadata);
    let mut properties = BTreeMap::new();
    if let Some(python) = first("requires-python") {
        properties.insert("pixi:requires-python".into(), python);
    }
    if !installer.trim().is_empty() {
        properties.insert("pixi:installer".into(), installer.trim().to_string());
    }
    let mut location = format!(
        "file://{}",
        dist_info
            .display()
            .to_string()
            .replace('\\', "/")
            .trim_start_matches('/')
    );
    if !location.starts_with("file:///") {
        location = location.replacen("file://", "file:///", 1);
    }
    // PEP 610: where pip got it from, when it was a direct URL or VCS install.
    if let Ok(text) = std::fs::read_to_string(dist_info.join("direct_url.json"))
        && let Ok(direct) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(url) = direct.get("url").and_then(|u| u.as_str())
    {
        properties.insert(DIRECT_URL_PROPERTY.into(), url.to_string());
        if direct
            .pointer("/dir_info/editable")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            properties.insert("pixi:editable".into(), "true".into());
        }
        if let Some(vcs) = direct.get("vcs_info") {
            if let Some(commit) = vcs.get("commit_id").and_then(|c| c.as_str()) {
                properties.insert("pixi:source-rev".into(), commit.to_string());
            }
            location = format!("{}+{url}", vcs.get("vcs").and_then(|v| v.as_str()).unwrap_or("git"));
        }
    }
    let requires = headers
        .get("requires-dist")
        .into_iter()
        .flatten()
        .filter_map(|req| requirement_name(req))
        .collect();
    let license = info.license_expression.or(info.license);
    let mut package = Package {
        id: purl.clone(),
        name,
        version: Some(version),
        kind: PackageKind::Pypi,
        purl,
        supplier: None,
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location,
        sha256: None,
        md5: None,
        license,
        license_files: Vec::new(),
        description: info.summary,
        homepage: info.homepage,
        repository: info.repository,
        documentation: info.documentation,
        yanked: None,
        properties,
        dependencies: Vec::new(),
    };
    purl::identify_pypi_source(&mut package)?;
    // PEP 376: pip and uv leave an empty REQUESTED file in what was asked for by name.
    if dist_info.join("REQUESTED").exists() {
        mark_requested(&mut package);
    }
    Ok(Some((package, requires)))
}

/// The project name at the front of a PEP 508 requirement string.
fn requirement_name(requirement: &str) -> Option<String> {
    let name: String = requirement
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefix")
    }

    /// A local direct URL says where the project is on this machine: relative to the project it
    /// reads as the lockfile writes it, and outside it is dropped. A remote one is left alone.
    #[test]
    fn a_local_direct_url_becomes_relative_to_the_project() {
        // Real absolute paths, so the test means the same on Windows (`C:\\...`) as elsewhere.
        let root = std::env::temp_dir().join("pixi-sbom-portable");
        let url = |path: &Path| {
            format!(
                "file:///{}",
                path.display().to_string().replace('\\', "/").trim_start_matches('/')
            )
        };
        let mut sbom = crate::format::testing::sample_sbom();
        let urls = [
            url(&root.join("app/libs/utils")),
            url(&root.join("elsewhere/wheels/x-1.0-py3-none-any.whl")),
            "https://example.com/x-1.0.tar.gz".to_string(),
            url(&root.join("venv-project/src/pkg")),
        ];
        for (package, url) in sbom.packages.iter_mut().zip(urls) {
            package.properties.insert(DIRECT_URL_PROPERTY.into(), url);
        }
        let direct = |sbom: &Sbom, i: usize| sbom.packages[i].properties.get(DIRECT_URL_PROPERTY).cloned();
        let mut pixi = sbom.clone();
        make_portable(&mut pixi, &root.join("app/.pixi/envs/default"));
        assert_eq!(direct(&pixi, 0).as_deref(), Some("./libs/utils"), "a pixi workspace");
        assert_eq!(direct(&pixi, 1), None, "outside the project");
        assert_eq!(direct(&pixi, 2).as_deref(), Some("https://example.com/x-1.0.tar.gz"));
        make_portable(&mut sbom, &root.join("venv-project/.venv"));
        assert_eq!(
            direct(&sbom, 3).as_deref(),
            Some("./src/pkg"),
            "a venv's project is its directory"
        );
        assert_eq!(project_of(&root.join("app/.pixi/envs/default")), root.join("app"));
        assert_eq!(project_of(Path::new("/opt/conda")), Path::new("/opt"));
    }

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        let bad_record = serde_json::from_str::<Record>("{}").expect_err("a record needs a name");
        for err in [
            PrefixError::NotAnEnvironment {
                path: PathBuf::from("/opt/somewhere"),
                found: "README.md, src/".into(),
            },
            PrefixError::Read {
                path: PathBuf::from("/opt/env/conda-meta"),
                source: std::io::Error::other("permission denied"),
            },
            PrefixError::Record {
                path: PathBuf::from("/opt/env/conda-meta/zlib-1.3.2-h0.json"),
                source: bad_record,
            },
            PrefixError::Purl(purl::sample_error()),
        ] {
            crate::assert_actionable(&err);
        }
    }

    #[test]
    fn reads_conda_meta_and_dist_info_and_links_them() {
        let sbom = build_sbom(&fixture(), Root::default(), None).unwrap();
        assert_eq!(sbom.environment, "prefix");
        assert_eq!(sbom.prefix.as_deref(), Some("prefix"));
        assert_eq!(sbom.platform, "linux-64", "the records' subdir, noarch ignored");
        assert_eq!(sbom.lockfile, "");
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["libzlib", "python", "tzdata", "six"],
            "conda first, then pypi; ruamel's dist-info skipped"
        );

        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(python.kind, PackageKind::CondaBinary);
        assert_eq!(
            python.purl,
            "pkg:conda/python@3.12.14?build=h5f976f7_3_cpython&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(python.supplier.as_ref().unwrap().name, "conda-forge");
        assert_eq!(python.license.as_deref(), Some("Python-2.0"));
        assert_eq!(python.properties["pixi:build-number"], "3");
        assert_eq!(
            python.properties["pixi:file-name"],
            "python-3.12.14-h5f976f7_3_cpython.conda"
        );
        assert_eq!(
            python.properties[EXTRACTED_DIR_PROPERTY],
            "/opt/pkgs/python-3.12.14-h5f976f7_3_cpython"
        );
        assert!(
            python
                .location
                .starts_with("https://conda.anaconda.org/conda-forge/linux-64/")
        );
        assert_eq!(
            python.dependencies,
            [
                "pkg:conda/libzlib@1.3.2?build=h25fd6f3_3&channel=conda-forge&subdir=linux-64&type=conda",
                "pkg:conda/tzdata@2026b?build=h78e105d_0&channel=conda-forge&subdir=noarch&type=conda"
            ]
        );
        let tzdata = sbom.packages.iter().find(|p| p.name == "tzdata").unwrap();
        assert_eq!(tzdata.properties["pixi:noarch"], "true");

        let six = sbom.packages.iter().find(|p| p.name == "six").unwrap();
        assert_eq!(six.kind, PackageKind::Pypi);
        assert_eq!(six.purl, "pkg:pypi/six@1.17.0");
        assert_eq!(six.license.as_deref(), Some("MIT"));
        assert_eq!(
            six.description.as_deref(),
            Some("Python 2 and 3 compatibility utilities")
        );
        assert_eq!(six.properties["pixi:installer"], "pip");
        assert!(six.location.starts_with("file:///"), "{}", six.location);
        assert!(six.location.ends_with("six-1.17.0.dist-info"));
        assert_eq!(
            six.dependencies,
            std::slice::from_ref(&python.id),
            "wheels hang off python"
        );
    }

    fn compiled(format: object::BinaryFormat, architecture: object::Architecture) -> Vec<u8> {
        object::write::Object::new(format, architecture, object::Endianness::Little)
            .write()
            .unwrap()
    }

    #[test]
    fn compiled_files_name_the_platform_they_were_built_for() {
        use object::{Architecture, BinaryFormat};
        assert_eq!(
            object_platform(&compiled(BinaryFormat::Elf, Architecture::X86_64)),
            Some("linux-64")
        );
        assert_eq!(
            object_platform(&compiled(BinaryFormat::Elf, Architecture::Aarch64)),
            Some("linux-aarch64")
        );
        assert_eq!(
            object_platform(&compiled(BinaryFormat::MachO, Architecture::Aarch64)),
            Some("osx-arm64")
        );
        assert_eq!(
            object_platform(&compiled(BinaryFormat::MachO, Architecture::X86_64)),
            Some("osx-64")
        );
        assert_eq!(object_platform(b"#!/bin/sh\n"), None);
    }

    fn dist_info(dir: &Path, name: &str, version: &str, record: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("RECORD"),
            record.iter().map(|f| format!("{f},,\n")).collect::<String>(),
        )
        .unwrap();
    }

    /// Distributions a package vendors are components under it, apart from the installed copy of
    /// the same project; two packages vendoring the same release share one component; and a diff
    /// does not take a vendored copy for an install.
    #[test]
    fn vendored_distributions_are_components_under_the_package_that_ships_them() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path();
        let site = env.join("lib/python3.12/site-packages");
        std::fs::create_dir_all(env.join("conda-meta")).unwrap();
        let record = serde_json::json!({
            "name": "setuptools", "version": "80.0.0", "build": "pyh0", "subdir": "noarch",
            "files": ["lib/python3.12/site-packages/setuptools/__init__.py", "lib/python3.12/site-packages/pkg_resources/__init__.py"],
        });
        std::fs::write(env.join("conda-meta/setuptools-80.0.0-pyh0.json"), record.to_string()).unwrap();
        dist_info(
            &site.join("setuptools/_vendor/packaging-26.0.dist-info"),
            "packaging",
            "26.0",
            &[],
        );
        dist_info(
            &site.join("setuptools/_vendor/wheel-0.46.3.dist-info"),
            "wheel",
            "0.46.3",
            &[],
        );
        dist_info(
            &site.join("pkg_resources/_vendor/packaging-26.0.dist-info"),
            "packaging",
            "26.0",
            &[],
        );
        dist_info(
            &site.join("packaging-26.3.dist-info"),
            "packaging",
            "26.3",
            &["packaging/__init__.py"],
        );
        dist_info(
            &site.join("bleach-6.0.0.dist-info"),
            "bleach",
            "6.0.0",
            &["bleach/__init__.py"],
        );
        dist_info(
            &site.join("bleach/_vendor/html5lib-1.1.dist-info"),
            "html5lib",
            "1.1",
            &[],
        );

        let mut sbom = build_sbom(env, Root::default(), None).unwrap();
        let before = crate::diff::previous_from_sbom(&sbom);
        let outcome = attach_vendored(&mut sbom, env);
        assert_eq!(outcome, VendoredOutcome { added: 3, merged: 1 });

        let find = |id: &str| {
            sbom.packages
                .iter()
                .find(|p| p.id == id)
                .unwrap_or_else(|| panic!("{id}"))
        };
        let vendored = find("pkg:pypi/packaging@26.0#vendored");
        assert_eq!(vendored.kind, PackageKind::Embedded);
        assert_eq!(vendored.purl, "pkg:pypi/packaging@26.0");
        assert_eq!(
            vendored.properties[crate::embedded::SOURCE_PROPERTY],
            "vendored:pkg_resources/_vendor;vendored:setuptools/_vendor"
        );
        assert_eq!(
            find("pkg:pypi/packaging@26.3").kind,
            PackageKind::Pypi,
            "the installed copy is its own"
        );
        let setuptools = sbom.packages.iter().find(|p| p.name == "setuptools").unwrap();
        assert!(
            setuptools
                .dependencies
                .contains(&"pkg:pypi/packaging@26.0#vendored".to_string())
        );
        assert!(
            setuptools
                .dependencies
                .contains(&"pkg:pypi/wheel@0.46.3#vendored".to_string())
        );
        let bleach = find("pkg:pypi/bleach@6.0.0");
        assert_eq!(
            bleach.dependencies,
            ["pkg:pypi/html5lib@1.1#vendored"],
            "owned through the pip RECORD"
        );

        let diff = crate::diff::compare(&sbom, &before, Path::new("before"));
        assert!(diff.is_empty(), "vendored copies are not installs: {diff:?}");
    }

    /// A Python package conda installed carries its PyPI identity from the dist-info it put in
    /// site-packages: no network, no mapping. The dist-info is not listed again as a PyPI package.
    #[test]
    fn a_conda_python_package_gets_its_pypi_identity_from_its_installed_dist_info() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path();
        std::fs::create_dir_all(env.join("conda-meta")).unwrap();
        let dist = "lib/python3.12/site-packages/Django-3.2.12.dist-info";
        std::fs::create_dir_all(env.join(dist)).unwrap();
        std::fs::write(
            env.join(dist).join("METADATA"),
            "Metadata-Version: 2.1\nName: Django\nVersion: 3.2.12\n",
        )
        .unwrap();
        std::fs::write(env.join(dist).join("INSTALLER"), "conda\n").unwrap();
        let record = serde_json::json!({
            "name": "django", "version": "3.2.12", "build": "pyhd8ed1ab_0", "subdir": "noarch",
            "channel": "https://conda.anaconda.org/conda-forge",
            "files": [format!("{dist}/INSTALLER"), format!("{dist}/METADATA"), "lib/python3.12/site-packages/django/__init__.py"],
        });
        std::fs::write(
            env.join("conda-meta/django-3.2.12-pyhd8ed1ab_0.json"),
            record.to_string(),
        )
        .unwrap();
        let record = serde_json::json!({"name": "zlib", "version": "1.3.1", "build": "h0", "subdir": "linux-64",
            "files": ["lib/libz.so.1"]});
        std::fs::write(env.join("conda-meta/zlib-1.3.1-h0.json"), record.to_string()).unwrap();

        let sbom = build_sbom(env, Root::default(), None).unwrap();
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names.iter().filter(|n| n.eq_ignore_ascii_case("django")).count(),
            1,
            "{names:?}"
        );
        let django = sbom.packages.iter().find(|p| p.name == "django").unwrap();
        assert_eq!(django.extra_purls, ["pkg:pypi/django@3.2.12"]);
        assert_eq!(django.properties[crate::mapping::MAPPING_PROPERTY], "dist-info");
        assert_eq!(django.properties[DIST_INFO_PROPERTY], dist);
        let explained = crate::explain::facts(django, &sbom, crate::explain::Context::default());
        let other = explained.iter().find(|f| f.label == "other purls").unwrap();
        assert_eq!(
            other.source.as_deref(),
            Some(format!("the installed dist-info ({dist})").as_str())
        );

        let zlib = sbom.packages.iter().find(|p| p.name == "zlib").unwrap();
        assert!(zlib.extra_purls.is_empty(), "no dist-info, no PyPI identity");
        assert!(!zlib.purls_from_lock, "so a mapping may still answer for it");
    }

    /// A Linux arm64 container's `/usr/local`, scanned from any machine: the platform is the
    /// interpreter's, not the scanner's, and the version is the full one its headers state.
    #[test]
    fn a_python_installation_is_described_for_its_own_platform_and_full_version() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path();
        std::fs::create_dir_all(local.join("bin")).unwrap();
        std::fs::write(
            local.join("bin/python3.12"),
            compiled(object::BinaryFormat::Elf, object::Architecture::Aarch64),
        )
        .unwrap();
        let pip = local.join("lib/python3.12/site-packages/pip-25.0.1.dist-info");
        std::fs::create_dir_all(&pip).unwrap();
        std::fs::write(
            pip.join("METADATA"),
            "Metadata-Version: 2.1\nName: pip\nVersion: 25.0.1\n",
        )
        .unwrap();
        std::fs::write(pip.join("WHEEL"), "Wheel-Version: 1.0\nTag: py3-none-any\n").unwrap();
        std::fs::create_dir_all(local.join("lib/python3.9/site-packages")).unwrap();
        std::fs::create_dir_all(local.join("include/python3.12")).unwrap();
        std::fs::write(
            local.join("include/python3.12/patchlevel.h"),
            "#define PY_MINOR_VERSION 12\n#define PY_VERSION \"3.12.15\"\n",
        )
        .unwrap();

        let sbom = build_sbom(local, Root::default(), None).unwrap();
        assert_eq!(sbom.platform, "linux-aarch64", "from bin/python3.12, not this machine");
        assert_eq!(
            sbom.interpreter.as_deref(),
            Some("3.12.15"),
            "3.12 over 3.9, then patchlevel.h"
        );
        let python = sbom
            .packages
            .iter()
            .find(|p| p.name == "python")
            .expect("the interpreter is listed");
        assert_eq!(python.purl, "pkg:generic/python@3.12.15");
        assert_eq!(python.kind, PackageKind::External);
        assert_eq!(
            crate::cpe::for_package(python).as_deref(),
            Some("cpe:2.3:a:python:python:3.12.15:*:*:*:*:*:*:*")
        );
        let explained = crate::explain::facts(python, &sbom, crate::explain::Context::default());
        let cpe = explained.iter().find(|f| f.label == "cpe").unwrap();
        assert!(cpe.source.as_deref().unwrap().contains("CPython"), "{cpe:?}");

        std::fs::remove_file(local.join("include/python3.12/patchlevel.h")).unwrap();
        let sbom = build_sbom(local, Root::default(), None).unwrap();
        assert_eq!(
            sbom.interpreter.as_deref(),
            Some("3.12"),
            "without headers, the directory's X.Y"
        );
        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(python.purl, "pkg:generic/python@3.12");
        assert_eq!(crate::cpe::for_package(python), None, "no CPE for a bare X.Y");
    }

    #[test]
    fn platform_override_and_errors() {
        let sbom = build_sbom(&fixture(), Root::default(), Some("osx-arm64")).unwrap();
        assert_eq!(sbom.platform, "osx-arm64");
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            build_sbom(dir.path(), Root::default(), None).unwrap_err(),
            PrefixError::NotAnEnvironment { .. }
        ));
        std::fs::create_dir_all(dir.path().join("conda-meta")).unwrap();
        std::fs::write(dir.path().join("conda-meta/bad-1.0-0.json"), "{").unwrap();
        assert!(matches!(
            build_sbom(dir.path(), Root::default(), None).unwrap_err(),
            PrefixError::Record { .. }
        ));
    }

    fn fixtures(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
    }

    /// conda-forge's Python ships `lib/python3.1 -> python3.11`; site-packages is read once,
    /// through the real directory.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_python_directory_is_read_once_through_the_real_one() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("lib/python3.11/site-packages/six-1.17.0.dist-info");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink("python3.11", dir.path().join("lib/python3.1")).unwrap();
        let roots: Vec<_> = site_packages(dir.path())
            .into_iter()
            .filter(|root| root.is_dir())
            .collect();
        assert_eq!(roots, [dir.path().join("lib/python3.11/site-packages")]);
        assert_eq!(dist_infos(dir.path()), [real]);
    }

    #[test]
    fn venvs_and_plain_installations_are_their_site_packages() {
        assert_eq!(layout(&fixture()), Some(Layout::Conda));
        assert_eq!(layout(&fixtures("venv-posix")), Some(Layout::Venv));
        assert_eq!(layout(&fixtures("venv-windows")), Some(Layout::Venv));
        assert_eq!(layout(&fixtures("site-packages")), Some(Layout::Python));

        let posix = build_sbom(&fixtures("venv-posix"), Root::default(), None).unwrap();
        assert_eq!(posix.packages.len(), 6);
        assert_eq!(posix.interpreter.as_deref(), Some("3.12.7"));
        assert_eq!(posix.platform, "linux-64", "from charset_normalizer's manylinux tag");
        let requests = posix.packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.dependencies.len(), 4, "no python package to hang off");

        let windows = build_sbom(&fixtures("venv-windows"), Root::default(), None).unwrap();
        assert_eq!(windows.interpreter.as_deref(), Some("3.13.5"), "uv's version_info");
        assert_eq!(windows.platform, "win-64");

        let plain = build_sbom(&fixtures("site-packages"), Root::default(), None).unwrap();
        let names: Vec<&str> = plain.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["numpy", "six", "python"],
            "INSTALLER conda decides nothing without conda records; the interpreter is listed"
        );
        assert_eq!(
            posix.packages.iter().filter(|p| p.name == "python").count(),
            0,
            "a venv's interpreter is outside it: its version is in pixi:python-version"
        );
        assert_eq!(
            plain.interpreter.as_deref(),
            Some("3.11"),
            "from the site-packages path"
        );
        assert_eq!(plain.platform, "osx-arm64");

        let conda = build_sbom(&fixture(), Root::default(), None).unwrap();
        assert_eq!(conda.interpreter, None, "a conda environment lists python itself");
    }

    #[test]
    fn what_the_user_asked_for_is_direct_and_the_root_depends_on_it_alone() {
        use crate::manifest::{DECLARED_IN_PROPERTY, DIRECT_PROPERTY};
        let venv = build_sbom(&fixtures("venv-posix"), Root::default(), None).unwrap();
        let direct: Vec<&str> = venv
            .packages
            .iter()
            .filter(|p| p.properties.contains_key(DIRECT_PROPERTY))
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(direct, ["requests"], "only its dist-info has REQUESTED");
        assert!(venv.declared_roots);
        assert_eq!(crate::format::top_level_ids(&venv), ["pkg:pypi/requests@2.34.2"]);
        let requests = venv.packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.properties[DECLARED_IN_PROPERTY], REQUESTED);

        // Nothing recorded: the graph-root heuristic, as before.
        let windows = build_sbom(&fixtures("venv-windows"), Root::default(), None).unwrap();
        assert!(!windows.declared_roots);

        // A conda environment's history: specs added, then one removed again.
        let dir = tempfile::tempdir().unwrap();
        for entry in std::fs::read_dir(fixture().join("conda-meta")).unwrap().flatten() {
            std::fs::create_dir_all(dir.path().join("conda-meta")).unwrap();
            std::fs::copy(entry.path(), dir.path().join("conda-meta").join(entry.file_name())).unwrap();
        }
        std::fs::write(
            dir.path().join("conda-meta/history"),
            "==> 2026-01-01 10:00:00 <==\n# cmd: conda create -p x python=3.12 tzdata\n\
             # update specs: ['conda-forge::python=3.12', \"tzdata\"]\n\
             ==> 2026-01-02 10:00:00 <==\n# update specs: ['libzlib >=1.3']\n\
             ==> 2026-01-03 10:00:00 <==\n# remove specs: ['tzdata']\n",
        )
        .unwrap();
        let conda = build_sbom(dir.path(), Root::default(), None).unwrap();
        let direct: Vec<&str> = conda
            .packages
            .iter()
            .filter(|p| p.properties.contains_key(DIRECT_PROPERTY))
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(direct, ["libzlib", "python"]);
        assert!(conda.declared_roots);
        assert!(
            !build_sbom(&fixture(), Root::default(), None).unwrap().declared_roots,
            "a history without specs changes nothing"
        );
    }

    #[test]
    fn extras_are_inferred_only_when_asked_and_only_when_all_they_need_is_there() {
        let extras = |sbom: &Sbom, key: &str| {
            sbom.packages
                .iter()
                .find(|p| p.name == "requests")
                .and_then(|p| p.properties.get(key).cloned())
        };
        let mut sbom = build_sbom(&fixtures("venv-extras"), Root::default(), None).unwrap();
        assert_eq!(
            extras(&sbom, crate::extras::PYTHON_EXTRAS_PROPERTY),
            None,
            "off by default"
        );
        infer_extras(&fixtures("venv-extras"), &mut sbom);
        // socks: pysocks is installed, and win-inet-pton is for win32 only, so it does not count.
        // use-chardet-on-py3: chardet is not installed.
        assert_eq!(
            extras(&sbom, crate::extras::PYTHON_EXTRAS_PROPERTY).as_deref(),
            Some("socks")
        );
        assert_eq!(extras(&sbom, EXTRAS_INFERRED_PROPERTY).as_deref(), Some("true"));
        assert_eq!(
            extras(&sbom, EXTRAS_EVIDENCE_PROPERTY).as_deref(),
            Some("socks: pysocks")
        );

        // On Windows the win32-only requirement counts too, and it is missing.
        let mut windows = build_sbom(&fixtures("venv-extras"), Root::default(), Some("win-64")).unwrap();
        infer_extras(&fixtures("venv-extras"), &mut windows);
        assert_eq!(extras(&windows, crate::extras::PYTHON_EXTRAS_PROPERTY), None);

        // No interpreter known, or a platform markers cannot be evaluated for: nothing inferred.
        let mut unknown = build_sbom(&fixtures("venv-extras"), Root::default(), None).unwrap();
        unknown.interpreter = None;
        infer_extras(&fixtures("venv-extras"), &mut unknown);
        assert_eq!(extras(&unknown, crate::extras::PYTHON_EXTRAS_PROPERTY), None);
        let mut odd = build_sbom(&fixtures("venv-extras"), Root::default(), Some("emscripten-wasm32")).unwrap();
        infer_extras(&fixtures("venv-extras"), &mut odd);
        assert_eq!(extras(&odd, crate::extras::PYTHON_EXTRAS_PROPERTY), None);
    }

    #[test]
    fn wheel_tags_name_platforms() {
        assert_eq!(
            tag_platform("cp312-cp312-manylinux_2_17_aarch64"),
            Some("linux-aarch64")
        );
        assert_eq!(tag_platform("cp312-cp312-musllinux_1_2_x86_64"), Some("linux-64"));
        assert_eq!(tag_platform("cp312-cp312-macosx_11_0_x86_64"), Some("osx-64"));
        assert_eq!(tag_platform("cp312-cp312-macosx_10_13_universal2"), None);
        assert_eq!(tag_platform("cp312-cp312-win_arm64"), Some("win-arm64"));
        assert_eq!(tag_platform("py3-none-any"), None);
        assert_eq!(wheel_platform(&[]), None);
    }

    #[test]
    fn not_an_environment_says_what_it_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(found(dir.path()), "an empty directory");
        assert_eq!(found(&dir.path().join("missing")), "nothing: it does not exist");
        std::fs::write(dir.path().join("README.md"), "").unwrap();
        assert_eq!(found(&dir.path().join("README.md")), "a file, not a directory");
        std::fs::create_dir(dir.path().join("src")).unwrap();
        assert_eq!(found(dir.path()), "README.md, src/");
        for i in 0..9 {
            std::fs::write(dir.path().join(format!("f{i}")), "").unwrap();
        }
        assert!(found(dir.path()).ends_with("and 3 more"));
        let err = build_sbom(&dir.path().join("src"), Root::default(), None).unwrap_err();
        assert!(err.to_string().contains("found an empty directory"), "{err}");
    }

    #[test]
    fn requirement_names() {
        assert_eq!(requirement_name("requests>=2,<3").as_deref(), Some("requests"));
        assert_eq!(
            requirement_name("charset_normalizer ; extra == 'x'").as_deref(),
            Some("charset_normalizer")
        );
        assert_eq!(
            requirement_name("ruamel.yaml[jinja2] (>=0.17)").as_deref(),
            Some("ruamel.yaml")
        );
        assert_eq!(requirement_name("  "), None);
    }
}
