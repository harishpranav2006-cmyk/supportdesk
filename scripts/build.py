"""Publish static assets for the Vercel CDN without copying secrets."""
from pathlib import Path
from shutil import copytree
root = Path(__file__).resolve().parents[1]
copytree(root / 'app/static', root / 'public/static', dirs_exist_ok=True)
