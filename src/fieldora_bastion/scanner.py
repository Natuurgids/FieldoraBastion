"""Bounded malware scanning adapter for quarantined Bastion payloads."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_MAX_FILES = 10_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
_MAX_VERSION_TEXT = 2_048
_SCAN_TIMEOUT_SECONDS = 60 * 60


class ScanError(RuntimeError):
    """Raised when a quarantine payload cannot be safely scanned."""


def _preflight(root: Path, max_total_bytes: int) -> int:
    if root.is_symlink():
        raise ScanError("scan source root must not be a symlink")
    root = root.resolve()
    if not root.is_dir():
        raise ScanError("scan source root must be a directory")
    files = sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())
    if not files:
        raise ScanError("scan source contains no files")
    if len(files) > _MAX_FILES:
        raise ScanError("scan source contains too many files")
    total = 0
    for path in files:
        if path.is_symlink():
            raise ScanError("scan source must not contain symlinks")
        try:
            path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise ScanError("scan source file escapes source root") from exc
        total += path.stat().st_size
        if total > max_total_bytes:
            raise ScanError("scan source exceeds configured maximum total size")
    return len(files)


def scan_with_clamav(
    source_root: Path,
    report_path: Path,
    *,
    database_dir: Path,
    max_total_bytes: int = _MAX_TOTAL_BYTES,
) -> dict[str, object]:
    """Scan a bounded quarantine tree and write a machine-readable attestation.

    ClamAV definitions are supplied from a read-only directory. The adapter does
    not update definitions and never invokes a shell.
    """
    file_count = _preflight(source_root, max_total_bytes)
    executable = shutil.which("clamscan")
    if not executable:
        raise ScanError("clamscan is unavailable")
    if database_dir.is_symlink() or not database_dir.is_dir():
        raise ScanError("ClamAV database directory is unavailable")
    try:
        version_run = subprocess.run(
            [executable, f"--database={database_dir}", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError("ClamAV version check failed") from exc
    version_text = (version_run.stdout or version_run.stderr or "").strip()
    if version_run.returncode != 0 or not version_text:
        raise ScanError("ClamAV definitions are unavailable or invalid")
    version_text = version_text[:_MAX_VERSION_TEXT]
    try:
        run = subprocess.run(
            [
                executable,
                f"--database={database_dir}",
                "--recursive",
                "--infected",
                "--no-summary",
                str(source_root.resolve()),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError("ClamAV scan failed to complete") from exc
    result = {0: "clean", 1: "infected"}.get(run.returncode, "error")
    report: dict[str, object] = {
        "result": result,
        "scanner": "clamav",
        "scanner_version": version_text,
        "definitions": version_text,
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "file_count": file_count,
    }
    report_path = report_path.resolve()
    source = source_root.resolve()
    try:
        report_path.relative_to(source)
    except ValueError:
        pass
    else:
        raise ScanError("scan report must be written outside the scanned payload")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    if result != "clean":
        raise ScanError(f"ClamAV scan result is {result}")
    return report
