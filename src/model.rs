//! Format-agnostic representation of an SBOM built from one lock environment/platform.
//!
//! Both the CycloneDX and SPDX writers consume this model, so all lockfile
//! interpretation happens exactly once, in [`crate::lock`].

use std::collections::BTreeMap;

/// The complete SBOM content for a single environment and platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sbom {
    /// The workspace the lockfile belongs to.
    pub root: Root,
    /// Name of the lock environment that was described.
    pub environment: String,
    /// Platform within that environment (e.g. `linux-64`).
    pub platform: String,
    /// Path of the lockfile the SBOM was generated from, as given on the command line.
    pub lockfile: String,
    /// Packages sorted by kind, then name, then version. Order is stable across runs.
    pub packages: Vec<Package>,
}

/// The workspace described by the SBOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// Workspace name from the manifest, or the lockfile directory name as a fallback.
    pub name: String,
    /// Workspace version from the manifest, if present.
    pub version: Option<String>,
}

/// How a package is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageKind {
    /// A prebuilt `.conda` / `.tar.bz2` archive from a channel.
    CondaBinary,
    /// A pixi-build source package (path or git).
    CondaSource,
    /// A PyPI wheel or sdist.
    Pypi,
}

/// A single locked package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Stable identifier, unique within one [`Sbom`]. Currently the purl.
    pub id: String,
    /// Package name as spelled in the lockfile.
    pub name: String,
    /// Package version string. Absent only for pixi-build source packages whose metadata
    /// has not been evaluated yet.
    pub version: Option<String>,
    /// Delivery mechanism.
    pub kind: PackageKind,
    /// Package URL for this package.
    pub purl: String,
    /// Additional purls the channel declares for the package (e.g. a conda package's PyPI purl).
    pub extra_purls: Vec<String>,
    /// Download URL or filesystem path.
    pub location: String,
    /// Hex-encoded SHA-256 of the archive, if known.
    pub sha256: Option<String>,
    /// Hex-encoded MD5 of the archive, if known.
    pub md5: Option<String>,
    /// License string as declared by the package. Not guaranteed to be an SPDX expression.
    pub license: Option<String>,
    /// Extra facts that have no first-class field in the SBOM specs
    /// (channel, subdir, build string, ...). Keys are prefixed `pixi:`.
    pub properties: BTreeMap<String, String>,
    /// Ids of packages in the same [`Sbom`] this package depends on. Sorted, deduplicated.
    pub dependencies: Vec<String>,
}

impl Package {
    /// Sort key that keeps output deterministic.
    pub fn sort_key(&self) -> (PackageKind, &str, Option<&str>) {
        (self.kind, &self.name, self.version.as_deref())
    }
}
