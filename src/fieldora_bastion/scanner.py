"""Bounded malware scanning adapter for quarantined Bastion payloads."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

_MAX_FILES = 10_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
_MAX_VERSION_TEXT = 2_048
_SCAN_TIMEOUT_SECONDS = 60 * 60


class ScanError(RuntimeError):
    """Raised when a quarantine payload cannot be safely scanned."""


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_tree_sha256(entries: list[tuple[str, int, str]]) -> str:
    """Digest canonical path/size/content-hash tuples for scan/build binding."""
    digest = hashlib.sha256()
    for path, size, sha256 in sorted(entries):
        digest.update(f"{path}\0{size}\0{sha256}\n".encode())
    return digest.hexdigest()


def _preflight(root: Path, max_total_bytes: int) -> tuple[int, str]:
    if max_total_bytes <= 0:
        raise ScanError("maximum scan size must be positive")
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
    entries: list[tuple[str, int, str]] = []
    for path in files:
        if path.is_symlink():
            raise ScanError("scan source must not contain symlinks")
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(root).as_posix()
        except (OSError, ValueError) as exc:
            raise ScanError("scan source file escapes source root") from exc
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise ScanError("scan source exceeds configured maximum total size")
        entries.append((relative, size, _file_sha256(path)))
    return len(files), _payload_tree_sha256(entries)


def _safe_report_path(report_path: Path, source_root: Path) -> Path:
    """Resolve an output path without allowing a pre-existing symlink escape."""
    if report_path.is_symlink():
        raise ScanError("scan report path must not be a symlink")
    parent = report_path.parent
    if parent.is_symlink():
        raise ScanError("scan report parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise ScanError("scan report parent is unavailable") from exc
    resolved = resolved_parent / report_path.name
    source = source_root.resolve()
    try:
        resolved.relative_to(source)
    except ValueError:
        return resolved
    raise ScanError("scan report must be written outside the scanned payload")


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
    file_count, payload_sha256 = _preflight(source_root, max_total_bytes)
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
        "scanned_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "file_count": file_count,
        "payload_sha256": payload_sha256,
    }
    destination = _safe_report_path(report_path, source_root)
    destination.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    if result != "clean":
        raise ScanError(f"ClamAV scan result is {result}")
    return report
