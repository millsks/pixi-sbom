# Troubleshooting: results on one network, none on another

The same command, the same `pixi.lock`, a different network — and the vulnerability table is empty, or every
license is missing. Nothing in the output says why, because from the tool's point of view nothing went wrong: it
asked, it did not get an answer, it carried on and wrote a document.

This page is the order to check things in. Every step is a command you can paste.

## 1. Ask the tool what it sees

```console
$ pixi sbom --doctor --fetch-licenses --vulnerabilities osv
Configuration
  offline    false
  proxy      HTTPS_PROXY=http://user:***@proxy.corp:8080
  no-proxy   NO_PROXY=.corp,localhost
  TLS roots  the platform verifier (the operating system trust store)
  timeout    120s
  cache      /home/u/.cache/rattler/pixi-sbom (exists)

Upstreams
  PyPI index         https://pypi.org/pypi            ok 200, 184 ms
  OSV                https://api.osv.dev              failed: io: invalid peer certificate: UnknownIssuer
  package archives   each package's own download URL  ok 200, 96 ms

1 of 3 upstream(s) could not be reached: OSV.
```

`--doctor` needs no lockfile and no workspace. Give it the flags of the run you are diagnosing, so it probes the
same upstreams that run would. It exits 1 when anything is unreachable, which makes it usable as a CI pre-flight.

The three lines that answer most questions are `proxy`, `TLS roots` and the failure text beside each upstream.
`pixi sbom --version-details` prints the same configuration plus what the binary was built with.

## 2. The three usual causes

| Symptom in `--doctor` | Cause | Fix |
|---|---|---|
| `failed: io: invalid peer certificate: UnknownIssuer` | A TLS-intercepting appliance re-signs traffic with a CA the tool does not trust | Install the CA system-wide, or point `--ca-bundle` at it (below) |
| `failed: io: Connection refused` / a timeout, with `proxy none` | The network needs a proxy and none is configured | Set `HTTPS_PROXY` (and `NO_PROXY` for internal hosts) |
| `failed: ...` with a `socks5://` proxy set | — | Supported; if it still fails, check `pixi sbom --version-details` says `socks-proxy` |
| `ok 200` for everything, but the report is still empty | Nothing was asked, rather than nothing found | See [when something comes back empty](cli.md#when-something-comes-back-empty) |

### Proxies

Every request honours `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (either case), including
`socks5://` and `socks5h://` addresses. On Windows, a proxy configured only in the system settings, with no
environment variable at all, is used as well.

The configuration block prints the variable in effect with the password replaced, so it is safe to paste into an
issue — internal host names are not, so read it first.

### A private certificate authority

Trust comes from the operating system's store by default, which is right wherever the appliance's CA is installed
system-wide. Where it is not — a container, a CI image, a machine where only Python was ever configured — point
the tool at the bundle:

```sh
pixi sbom --ca-bundle /etc/ssl/certs/corp-ca.pem --vulnerabilities osv
export PIXI_SBOM_CA_BUNDLE=/etc/ssl/certs/corp-ca.pem     # the same, for a CI job
```

`SSL_CERT_FILE` is honoured when neither is given, which is the variable the rest of the Python and conda world
already sets in such an image, so a correctly configured container usually needs nothing at all.

The trust anchors are resolved once, before the first request, and the first of these that is set wins:

1. `--ca-bundle <FILE>`
2. `PIXI_SBOM_CA_BUNDLE`
3. `SSL_CERT_FILE`
4. the platform verifier — the operating system's own trust store, which is the default when none of the three
   is set, and which is what every earlier release used

`--doctor` and `pixi sbom --version-details` both print which one is in play, as the `TLS roots` line. Nothing is
compiled into the binary: there is no vendored root store to go stale.

The file must be PEM; a bundle that is missing or holds no certificate is
reported before the first request, naming the file and the flag that gave it, rather than arriving later as a
handshake failure:

```console
$ pixi sbom --ca-bundle ./corp.der --fetch-licenses
Error: pixi_sbom::http::ca_bundle

  × no certificate in the CA bundle at ./corp.der
  help: the file given by --ca-bundle must be PEM, with at least one -----BEGIN CERTIFICATE----- block;
        a DER file must be converted first (openssl x509 -inform der -in ca.der -out ca.pem)
```

### A blocked host

Where the host itself is unreachable and no proxy or CA will change that, point the tool at whatever the network
does allow:

| Variable | What it replaces |
|---|---|
| `PIXI_SBOM_PYPI_URL` | The PyPI JSON API — a devpi or Artifactory mirror |
| `PIXI_SBOM_OSV_URL` | The OSV API |
| `PIXI_SBOM_ANACONDA_URL` | The anaconda.org API used by `--report outdated` |
| `PIXI_SBOM_SCORECARD_URL` | The OpenSSF Scorecard API |
| `PIXI_SBOM_KEV_URL` | The CISA KEV catalog |

`--pypi-mapping-file <FILE>` takes the conda → PyPI name mapping from disk instead of downloading it, which is
the one download an air-gapped run of `--vulnerabilities osv` over conda packages cannot do without.

## 3. Read the requests

```sh
RUST_LOG=pixi_sbom::http=debug,pixi_sbom=info pixi sbom --vulnerabilities osv
```

Every request is logged with its URL, status, size and elapsed time, and every failure with its **whole error
chain** — `invalid peer certificate`, `Connection refused`, the proxy's own message — rather than only the
outermost "request failed". [What the log says](cli.md#what-the-log-says-and-how-to-narrow-it) has the module
targets and three worked recipes.

## 4. Work from the cache

An unreachable upstream does not have to stop a run:

```sh
PIXI_SBOM_OFFLINE=1 pixi sbom --fetch-licenses --vulnerabilities osv
```

Nothing is requested; every cache is used where it has an answer and every skipped request is logged. Warm the
caches on a machine that can reach the network, copy `PIXI_SBOM_CACHE_DIR` across, and the restricted machine
produces the same document.

What such a run could **not** finish is recorded in the document itself — `pixi:incomplete`,
`pixi:incomplete-detail` and `pixi:stale-cache` (see
[incomplete enrichment](output-format.md#incomplete-enrichment)) — so an SBOM built on a restricted network does
not read as "no known vulnerabilities" months later.

## Reporting it

If none of this explains it, open an issue with the output of `pixi sbom --version-details`, the command, and the
same command with `-vv`. The bug report form asks for exactly those three.
