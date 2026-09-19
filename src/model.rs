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
    /// Name of the lockfile the SBOM was generated from, relative to the workspace root
    /// (normally `pixi.lock`). Never an absolute path, so documents do not depend on where
    /// they were generated.
    pub lockfile: String,
    /// Packages sorted by kind, then name, then version. Order is stable across runs.
    pub packages: Vec<Package>,
}

/// The workspace described by the SBOM.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Root {
    /// Workspace name from the manifest, or the lockfile directory name as a fallback.
    pub name: String,
    /// Workspace version from the manifest, if present.
    pub version: Option<String>,
    /// Workspace authors from the manifest; they are recorded as the SBOM's authors.
    pub authors: Vec<Author>,
    /// Workspace license from the manifest, if present. Not guaranteed to be an SPDX expression.
    pub license: Option<String>,
    /// Workspace homepage URL, if present.
    pub homepage: Option<String>,
    /// Workspace source repository URL, if present.
    pub repository: Option<String>,
}

/// A person named in the manifest's author list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    /// Display name.
    pub name: String,
    /// Email address, if given.
    pub email: Option<String>,
}

impl Author {
    /// Parse the `Name <email>` spelling pixi manifests use; without angle brackets the whole
    /// string is the name.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        match text.rsplit_once('<') {
            Some((name, rest)) if rest.ends_with('>') => {
                let email = rest.trim_end_matches('>').trim();
                let name = name.trim();
                Some(Self {
                    name: if name.is_empty() {
                        email.to_string()
                    } else {
                        name.to_string()
                    },
                    email: (!email.is_empty()).then(|| email.to_string()),
                })
            }
            _ => Some(Self {
                name: text.to_string(),
                email: None,
            }),
        }
    }
}

/// The organization a package was obtained from: a conda channel or a PyPI index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supplier {
    /// Short name, e.g. `conda-forge` or `pypi.org`.
    pub name: String,
    /// The channel or index URL.
    pub url: Option<String>,
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
    /// Where the package was obtained from, if it came from a channel or index.
    pub supplier: Option<Supplier>,
    /// Additional purls for the package (e.g. a conda package's PyPI purl), from the lockfile
    /// or from PyPI identity enrichment.
    pub extra_purls: Vec<String>,
    /// Whether the lockfile itself states the package's purls (`purls:` present, even if
    /// empty). When true the lockfile's answer is authoritative and enrichment leaves it alone.
    pub purls_from_lock: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn author_parses_name_and_email() {
        let author = Author::parse("Ada Lovelace <ada@example.org>").unwrap();
        assert_eq!(author.name, "Ada Lovelace");
        assert_eq!(author.email.as_deref(), Some("ada@example.org"));
    }

    #[test]
    fn author_without_email_or_with_only_email() {
        assert_eq!(
            Author::parse("  Ada Lovelace  ").unwrap(),
            Author {
                name: "Ada Lovelace".into(),
                email: None
            }
        );
        assert_eq!(
            Author::parse("<ada@example.org>").unwrap(),
            Author {
                name: "ada@example.org".into(),
                email: Some("ada@example.org".into())
            }
        );
        assert_eq!(
            Author::parse("Ada <>").unwrap(),
            Author {
                name: "Ada".into(),
                email: None
            }
        );
        assert_eq!(
            Author::parse("Ada < not an address").unwrap().name,
            "Ada < not an address"
        );
        assert_eq!(Author::parse("   "), None);
    }
}
