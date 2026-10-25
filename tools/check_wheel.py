"""Build first, then verify the wheel in an isolated environment away from source."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
wheels = list((root / "dist").glob("*.whl"))
if len(wheels) != 1:
    raise SystemExit("Expected exactly one wheel in dist")
config = json.loads((root / "tools" / "smoke.json").read_text(encoding="utf-8"))
with tempfile.TemporaryDirectory(prefix=".wheel-smoke-", dir=root) as folder:
    base = Path(folder)
    venv = base / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
        cwd=base,
        env=env,
        check=True,
    )
    args = [str(root / a[1:]) if a.startswith("@") else a for a in config["args"]]
    result = subprocess.run(
        [str(python), "-I", "-m", config["module"], *args],
        cwd=base,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != config["exit"]:
        raise SystemExit(f"Unexpected exit {result.returncode}: {result.stderr}")
    if config["contains"] not in result.stdout:
        raise SystemExit(f"Missing expected result: {result.stdout}")
    print("Isolated wheel installation and example passed")
