from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from fieldora_bastion import scanner
from fieldora_bastion.scanner import ScanError, scan_with_clamav


def test_clean_clamav_scan_writes_bounded_attestation(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.gguf").write_bytes(b"model")
    database = tmp_path / "db"
    database.mkdir()
    report = tmp_path / "approved" / "scan.json"
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/clamscan")

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout="ClamAV 1.4.0/12345/Mon Aug 24\n")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    result = scan_with_clamav(source, report, database_dir=database)

    assert result["result"] == "clean"
    assert result["file_count"] == 1
    stored = json.loads(report.read_text(encoding="utf-8"))
    assert stored["scanner"] == "clamav"
    assert stored["definitions"].startswith("ClamAV 1.4.0")
    assert calls[1][0] == "/usr/bin/clamscan"
    assert "--recursive" in calls[1]
    assert all("shell" not in str(call) for call in calls)


def test_infected_scan_fails_after_writing_attestation(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.gguf").write_bytes(b"model")
    database = tmp_path / "db"
    database.mkdir()
    report = tmp_path / "scan.json"
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/clamscan")

    def fake_run(args, **_kwargs):
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout="ClamAV 1.4.0/12345/test\n")
        return subprocess.CompletedProcess(args, 1, stdout="model.gguf: Test FOUND\n")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    with pytest.raises(ScanError, match="infected"):
        scan_with_clamav(source, report, database_dir=database)
    assert json.loads(report.read_text(encoding="utf-8"))["result"] == "infected"


def test_scan_rejects_symlink_and_report_inside_payload(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "model.gguf"
    target.write_bytes(b"model")
    link = source / "model.gguf"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    database = tmp_path / "db"
    database.mkdir()

    with pytest.raises(ScanError, match="symlinks"):
        scan_with_clamav(source, tmp_path / "scan.json", database_dir=database)

    link.unlink()
    (source / "model.gguf").write_bytes(b"model")
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/clamscan")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(
            args, 0, stdout="ClamAV 1.4.0/12345/test\n" if "--version" in args else ""
        ),
    )
    with pytest.raises(ScanError, match="outside"):
        scan_with_clamav(source, source / "scan.json", database_dir=database)
