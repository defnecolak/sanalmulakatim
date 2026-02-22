import subprocess
import sys
from pathlib import Path


def test_smoke_critical_flows_help() -> None:
    script = Path(__file__).resolve().parents[1] / "smoke_critical_flows.py"
    r = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert r.returncode == 0
    assert "Critical-flow smoke" in (r.stdout + r.stderr)
