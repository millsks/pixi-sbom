# Archive fixtures

Real archives read by the offline `--fetch-licenses` tests through `file://` URLs.

| File | Origin |
|---|---|
| `zlib-1.3.2-h25fd6f3_3.conda` | conda-forge, unchanged |
| `zlib-1.3.2-h25fd6f3_3.tar.bz2` | Built from the `.conda` above: its `info/{index,about,paths}.json`, `info/licenses/LICENSE` and a placeholder `lib/` file, packed as `tar --format=ustar` and `bzip2 -9` (4762 bytes, sha256 `d4b0036253168923ee9056a5198f1fc55c7e65cf8f826a4ba8e8afd94a72c97f`) |
| `six-1.17.0-py2.py3-none-any.whl` | PyPI, unchanged |
| `six-1.17.0-py2.py3-none-any.sbom.whl` | The six wheel with a PEP 770 `six-1.17.0.dist-info/sboms/` directory added |
