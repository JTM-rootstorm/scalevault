from __future__ import annotations

import subprocess
from pathlib import Path


def test_private_seed_material_is_ignored_but_warning_readme_remains_trackable() -> None:
    repository = Path(__file__).resolve().parents[3]
    private_bundle = repository / "seeds" / "kivra-private" / "private-bundle.json"
    readme = repository / "seeds" / "kivra-private" / "README.md"

    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", str(private_bundle)],
        cwd=repository,
        check=False,
    )
    readme_ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", str(readme)],
        cwd=repository,
        check=False,
    )

    assert ignored.returncode == 0
    assert readme_ignored.returncode == 1
    assert readme.read_text(encoding="utf-8").startswith("# Private Kivra seed\n")

    tracked = subprocess.run(
        ["git", "ls-files", "--", "seeds/kivra-private"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked.stdout.splitlines() == ["seeds/kivra-private/README.md"]
