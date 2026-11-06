"""Convert the generated .pptx to PDF with LibreOffice.

LibreOffice is found on PATH as `soffice` or `libreoffice`. Set SOFFICE_CMD to
override, e.g. on macOS:
    export SOFFICE_CMD="/Applications/LibreOffice.app/Contents/MacOS/soffice"
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


def find_soffice() -> list[str]:
    cmd = os.environ.get("SOFFICE_CMD")
    if cmd:
        return shlex.split(cmd)
    for name in ("soffice", "libreoffice"):
        path = shutil.which(name)
        if path:
            return [path]
    raise RuntimeError(
        "LibreOffice not found. Install it, or set SOFFICE_CMD to the soffice executable."
    )


def export_pdf(pptx_path: str | Path, out_dir: str | Path | None = None, timeout: int = 180) -> str:
    pptx_path = Path(pptx_path).resolve()
    out_dir = Path(out_dir or pptx_path.parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    # A throwaway profile avoids clashes with a LibreOffice window the user has open.
    with tempfile.TemporaryDirectory(prefix="lo_profile_") as profile:
        args = find_soffice() + [
            f"-env:UserInstallation={Path(profile).as_uri()}",
            "--headless", "--convert-to", "pdf", "--outdir", str(out_dir), str(pptx_path),
        ]
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    pdf_path = out_dir / (pptx_path.stem + ".pdf")
    if result.returncode != 0 or not pdf_path.exists():
        raise RuntimeError(f"PDF export failed: {result.stderr.strip() or result.stdout.strip()}")
    return str(pdf_path)
