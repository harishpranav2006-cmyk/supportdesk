"""Build static assets and optionally bootstrap the database during a one-time deployment."""
import os
import subprocess
import sys
from pathlib import Path
from shutil import copytree

root = Path(__file__).resolve().parents[1]

if os.environ.get("SUPPORTDESK_BOOTSTRAP_ON_BUILD") == "true":
    # Install the pinned dependencies into the build environment before importing app.seed.
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(root / "requirements.txt")],
        cwd=root,
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "app.seed"],
        cwd=root,
        check=True,
    )

copytree(root / "app/static", root / "public/static", dirs_exist_ok=True)
