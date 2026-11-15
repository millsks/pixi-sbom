"""Tests for actions/pixi-sbom/action-version.sh, which picks the binary the GitHub Action installs.

Run with `pixi run action-test`. The GitHub API is replaced by fixture files served over `file://`, so what a
floating `@v0` resolves to is checked without a network or a real tag.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCRIPT = Path(__file__).resolve().parent.parent / "actions" / "pixi-sbom" / "action-version.sh"

RELEASES = [
    {"tag_name": "v1.0.0-rc.1"},
    {"tag_name": "v1.0.0"},
    {"tag_name": "v0.12.0"},
    {"tag_name": "v0.9.5"},
    {"tag_name": "v0.10.1"},
    {"tag_name": "v0.13.0-rc.1"},
]


class ActionVersionTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        # curl drops the `?per_page=100` query from a file:// URL, so this is what the list request reads.
        (root / "releases").write_text(json.dumps(RELEASES, indent=2))
        self.api = f"file://{root}/releases"

    def resolve(self, **env: str) -> subprocess.CompletedProcess[str]:
        full = {"PATH": os.environ["PATH"], "RELEASES_API": self.api, **env}
        return subprocess.run(["bash", str(SCRIPT)], env=full, capture_output=True, text=True, check=False)

    def version(self, **env: str) -> str:
        result = self.resolve(**env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_input_wins_over_ref(self) -> None:
        self.assertEqual(self.version(INPUT_VERSION="v0.9.5", ACTION_REF="v0"), "0.9.5")

    def test_exact_tag_pins_that_release(self) -> None:
        self.assertEqual(self.version(ACTION_REF="v0.12.0"), "0.12.0")

    def test_major_tag_resolves_within_its_major(self) -> None:
        # Newest by version, not by list order, and never a pre-release or a v1.
        self.assertEqual(self.version(ACTION_REF="v0"), "0.12.0")

    def test_the_next_major_tag_resolves_within_its_own_major(self) -> None:
        # The case that matters once 1.0 ships: `@v1` must follow 1.x and not fall back to the
        # newest release overall, which is how a v1 user would end up with a v2 binary behind v1's
        # inputs. Nothing in the script is hardcoded to a major, and this is what says so.
        self.assertEqual(self.version(ACTION_REF="v1"), "1.0.0")

    def test_prefixed_exact_tag_pins_that_release(self) -> None:
        # Releases from the workspace repository are tagged pixi-sbom-vX.Y.Z.
        self.assertEqual(self.version(ACTION_REF="pixi-sbom-v0.12.0"), "0.12.0")

    def test_prefixed_input_is_accepted(self) -> None:
        self.assertEqual(self.version(INPUT_VERSION="pixi-sbom-v0.9.5"), "0.9.5")

    def test_prefixed_major_tag_resolves_within_its_major(self) -> None:
        self.assertEqual(self.version(ACTION_REF="pixi-sbom-v0"), "0.12.0")

    def test_every_release_is_read_from_one_repository(self) -> None:
        # millsks/pixi-sbom holds every release as vX.Y.Z, those first made in the original repository (now
        # millsks/pixi-sbom.org) and aesir-oss/pixi-ext-contrib included, so one list answers for every era.
        root = Path(self.api.removeprefix("file://")).parent
        (root / "all").write_text(
            json.dumps([{"tag_name": t} for t in ["v1.14.0-rc.1", "v1.13.2", "v1.13.1", "v1.12.0", "v1.11.0", "v0.12.0"]])
        )
        one = f"file://{root}/all"
        self.assertEqual(self.version(RELEASES_API=one), "1.13.2")
        self.assertEqual(self.version(RELEASES_API=one, ACTION_REF="v1"), "1.13.2")
        self.assertEqual(self.version(RELEASES_API=one, ACTION_REF="v1.12.0"), "1.12.0")
        self.assertEqual(self.version(RELEASES_API=one, INPUT_VERSION="pixi-sbom-v1.13.1"), "1.13.1")
        self.assertEqual(self.version(RELEASES_API=one, ACTION_REF="v0"), "0.12.0")

    def test_the_default_list_is_millsks_pixi_sbom_only(self) -> None:
        text = SCRIPT.read_text()
        self.assertIn('RELEASES_API:-https://api.github.com/repos/millsks/pixi-sbom/releases}"', text)
        self.assertEqual(text.count("api.github.com/repos/"), 1)
        self.assertNotIn("api.github.com/repos/aesir-oss", text)
        self.assertNotIn("api.github.com/repos/millsks/pixi-sbom.org", text)
        action = (SCRIPT.parent / "action.yml").read_text()
        self.assertIn('base="https://github.com/millsks/pixi-sbom/releases/download/v${VERSION}"', action)
        self.assertNotIn("releases/download/pixi-sbom-v", action)

    def test_branch_takes_latest(self) -> None:
        self.assertEqual(self.version(ACTION_REF="main"), "1.0.0")

    def test_local_action_takes_latest(self) -> None:
        self.assertEqual(self.version(), "1.0.0")

    def test_major_without_a_release_falls_back_to_latest(self) -> None:
        self.assertEqual(self.version(ACTION_REF="v7"), "1.0.0")

    def test_unreachable_api_is_an_error(self) -> None:
        result = self.resolve(ACTION_REF="main", RELEASES_API="file:///nonexistent/releases")
        self.assertNotEqual(result.returncode, 0)


    def test_every_page_of_releases_is_read(self) -> None:
        # The repository's own pixi-ext-contrib-YYYY.MM.N releases (#49) fill the first page sooner; a release on the
        # second page is still found by following the Link header, and the repository tags are never taken for one.
        pages = {
            1: [{"tag_name": f"pixi-ext-contrib-2026.10.{n}"} for n in range(1, 100)] + [{"tag_name": "pixi-sbom-v1.1.0"}],
            2: [{"tag_name": "pixi-sbom-v1.4.0"}, {"tag_name": "pixi-ext-contrib-2026.09.1"}],
        }
        seen: list[str] = []

        class Releases(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - the handler's required name
                seen.append(self.path)
                page = int(parse_qs(urlparse(self.path).query).get("page", ["1"])[0])
                body = json.dumps(pages[page], indent=2).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if page < len(pages):
                    port = self.server.server_address[1]
                    self.send_header("Link", f'<http://127.0.0.1:{port}/releases?per_page=100&page={page + 1}>; rel="next"')
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Releases)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        api = f"http://127.0.0.1:{server.server_address[1]}/releases"
        self.assertEqual(self.version(RELEASES_API=api), "1.4.0")
        self.assertEqual(self.version(RELEASES_API=api, ACTION_REF="pixi-sbom-v1"), "1.4.0")
        self.assertEqual(len(seen), 4, seen)


if __name__ == "__main__":
    unittest.main()
