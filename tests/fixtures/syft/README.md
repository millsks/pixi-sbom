# syft documents

What [syft](https://github.com/anchore/syft) 1.54.1 writes for a Python virtualenv, in both its formats, for
`--from-sbom` on a document another tool wrote (#335):

```sh
python -m venv app && app/bin/pip install requests==2.32.3 django==5.2.7
syft scan dir:app -o cyclonedx-json=app.cdx.json -o spdx-json=app.spdx.json
```

The scan ran in a scratch directory; its path was replaced with `/work` and nothing else was edited. Of note:
syft gives PyPI packages no VCS reference, homepage or download location, so their repositories, and with them
their scorecards, come from the PyPI JSON lookup. The CycloneDX document also lists the files it read
(`"type": "file"`), which have no purl.
