"""Build Fieldora-compatible offline map bundles from pre-vetted files."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from fieldora_bastion.model_bundle import (
    BundleBuildError,
    _clean_scan_attestation,
    _metadata,
    _sha256,
    _sign_manifest,
    _token,
)

_MAP_EXTENSIONS = {
    ".mbtiles",
    ".pmtiles",
    ".gpkg",
    ".pbf",
    ".geojson",
    ".json",
    ".style",
    ".yaml",
    ".yml",
    ".txt",
    ".md",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".svg",
}
_FORBIDDEN_EXTENSIONS = {
    ".py",
    ".pyc",
    ".pyo",
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".bin",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
}
_MAX_FILES = 50_000
_MAX_TOTAL_BYTES = 256 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class BuiltMapBundle:
    root: Path
    map_id: str
    version: str
    total_bytes: int
    file_count: int
    signing_key_id: str = ""


def build_map_bundle(
    source_root: Path,
    output_root: Path,
    *,
    map_id: str,
    version: str,
    source: str = "fieldora-bastion",
    license_id: str = "unspecified",
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    signing_key: Path | None = None,
    scan_report: Path | None = None,
) -> BuiltMapBundle:
    """Copy data-only map payloads and emit a signed Fieldora transfer manifest."""
    if max_total_bytes <= 0:
        raise BundleBuildError("maximum bundle size must be positive")
    if source_root.is_symlink():
        raise BundleBuildError("source root must not be a symlink")
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise BundleBuildError("source root must be a directory")
    map_id = _token(map_id, "map_id")
    version = _token(version, "version")
    provenance = _metadata(source, "source", "fieldora-bastion")
    license_name = _metadata(license_id, "license_id", "unspecified")

    files = sorted(path for path in source_root.rglob("*") if path.is_file() or path.is_symlink())
    if not files:
        raise BundleBuildError("source contains no files")
    if len(files) > _MAX_FILES:
        raise BundleBuildError("source contains too many files")

    manifest_files: list[dict[str, object]] = []
    total = 0
    primary_map_files = 0
    for path in files:
        if path.is_symlink():
            raise BundleBuildError("source must not contain symlinks")
        resolved = path.resolve(strict=True)
        try:
            relative = PurePosixPath(resolved.relative_to(source_root).as_posix())
        except ValueError as exc:
            raise BundleBuildError("source file escapes source root") from exc
        suffix = relative.suffix.lower()
        if suffix in _FORBIDDEN_EXTENSIONS or suffix not in _MAP_EXTENSIONS:
            raise BundleBuildError(f"unsupported or executable map file: {relative.as_posix()}")
        if suffix in {".mbtiles", ".pmtiles", ".gpkg", ".pbf"}:
            primary_map_files += 1
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise BundleBuildError("map bundle exceeds configured maximum total size")
        manifest_files.append(
            {"path": relative.as_posix(), "sha256": _sha256(path), "size_bytes": size}
        )
    if primary_map_files == 0:
        raise BundleBuildError("source contains no supported primary map artifact")

    malware_scan = None if scan_report is None else _clean_scan_attestation(scan_report, manifest_files)
    if scan_report is not None and signing_key is None:
        raise BundleBuildError("scan attestation requires a signing key")

    destination = output_root.resolve() / f"{map_id}-{version}"
    if destination.exists():
        raise BundleBuildError("bundle destination already exists")
    destination.mkdir(parents=True)
    try:
        for entry in manifest_files:
            relative = PurePosixPath(str(entry["path"]))
            source_path = source_root.joinpath(*relative.parts)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, target, follow_symlinks=False)
        manifest: dict[str, object] = {
            "package_class": "map",
            "map_id": map_id,
            "version": version,
            "source": provenance,
            "license_id": license_name,
            "files": manifest_files,
            "artifact_total_bytes": total,
        }
        if malware_scan is not None:
            manifest["malware_scan"] = malware_scan
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        signing_key_id = ""
        if signing_key is not None:
            signing_key_id, signature = _sign_manifest(manifest_bytes, signing_key)
            manifest["signature"] = {"algorithm": "ed25519", "key_id": signing_key_id}
            manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            _, signature = _sign_manifest(manifest_bytes, signing_key)
            (destination / "manifest.sig").write_text(signature + "\n", encoding="ascii")
        (destination / "manifest.json").write_bytes(manifest_bytes)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return BuiltMapBundle(destination, map_id, version, total, len(manifest_files), signing_key_id)
