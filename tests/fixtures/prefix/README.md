# prefix fixture

A minimal installed environment for `--prefix`: three `conda-meta` records (two linux-64, one noarch; `python`
depends on the other two and names a virtual package, sizes and hashes are illustrative) and two `dist-info`
directories under `lib/python3.12/site-packages`: `six`, installed by pip, and `ruamel.yaml` with
`INSTALLER: conda`, which is skipped because the conda package that installed it is what the environment lists.
