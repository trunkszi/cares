import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("port", "function"),
    (("uarch", "ensure_uarch_port"), ("uring", "ensure_uring_port"), ("c-ares", "ensure_c_ares_single_thread_port")),
)
def test_existing_overlay_is_preserved(tmp_path, port, function):
    overlay = tmp_path / "overlay"
    destination = overlay / port
    destination.mkdir(parents=True)
    sentinel = destination / "custom.json"
    sentinel.write_text("preserve-local-port\n")
    script = Path(__file__).resolve().parents[3] / ".github" / "scripts" / "setup-ci-deps.sh"
    subprocess.run(
        ["bash", "-c", 'source "$1"; "$2" "$3"', "bash", str(script), function, str(overlay)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert sorted(path.name for path in destination.iterdir()) == ["custom.json"]
    assert sentinel.read_text() == "preserve-local-port\n"
