"""Isolated fork probes for inherited locks and child-local reinitialization."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork()")

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("case", ["safety", "robots", "robots_authority", "session", "fetcher", "browser"])
def test_fork_while_parent_holds_lock_is_bounded_and_fail_fast(case: str) -> None:
    process = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fork_probe.py"), case],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert process.returncode == 0, (
        f"{case}: stdout={process.stdout!r} stderr={process.stderr!r}"
    )
    assert "OK" in process.stdout
