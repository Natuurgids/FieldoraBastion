"""Build Fieldora-compatible offline model bundles from pre-vetted files."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_MODEL_EXTENSIONS = {".safetensors", ".onnx", ".gguf"}
_SUPPORT_EXTENSIONS = {
    ".json",
    ".txt",
    ".md",
    ".model",
    ".vocab",
    ".merges",
    ".yaml",
    ".yml",
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
_MAX_FILES = 10_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
_MAX_METADATA_TEXT = 2_048


class BundleBuildError(ValueError):
    """Raised when source material cannot safely form a Fieldora model bundle."""


@dataclass(frozen=True, slots=True)
class BuiltModelBundle:
    root: Path
    model_id: str
    version: str
    total_bytes: int
    file_count: int


def _token(value: str, field: str) -> str:
    token = value.strip()
    if not token or token in {".", ".."} or not all(
        character.isalnum() or character in "._-" for character in token
    ):
        raise BundleBuildError(f"{field} must be a non-empty path-safe token")
    return token


def _metadata(value: str, field: str, default: str) -> str:
    text = (value or default).strip() or default
    if len(text) > _MAX_METADATA_TEXT:
        raise BundleBuildError(f"{field} is too long")
    return text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_model_bundle(
    source_root: Path,
    output_root: Path,
    *,
    model_id: str,
    version: str,
    source: str = "fieldora-bastion",
    license_id: str = "unspecified",
    max_total_bytes: int = _MAX_TOTAL_BYTES,
) -> BuiltModelBundle:
    """Copy pre-vetted model files and emit the trusted-side manifest contract.

    This function does not download, execute, or malware-scan content. Acquisition
    and scanning must complete before this builder is called.
    """
    if source_root.is_symlink():
        raise BundleBuildError("source root must not be a symlink")
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise BundleBuildError("source root must be a directory")
    model_id = _token(model_id, "model_id")
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
    model_artifacts = 0
    for path in files:
        if path.is_symlink():
            raise BundleBuildError("source must not contain symlinks")
        resolved = path.resolve(strict=True)
        try:
            relative = PurePosixPath(resolved.relative_to(source_root).as_posix())
        except ValueError as exc:
            raise BundleBuildError("source file escapes source root") from exc
        suffix = relative.suffix.lower()
        if suffix in _FORBIDDEN_EXTENSIONS or suffix not in _MODEL_EXTENSIONS | _SUPPORT_EXTENSIONS:
            raise BundleBuildError(f"unsupported or executable model file: {relative.as_posix()}")
        if suffix in _MODEL_EXTENSIONS:
            model_artifacts += 1
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise BundleBuildError("model bundle exceeds configured maximum total size")
        manifest_files.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256(path),
                "size_bytes": size,
            }
        )
    if model_artifacts == 0:
        raise BundleBuildError("source contains no supported model artifact")

    destination = output_root.resolve() / f"{model_id}-{version}"
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
        manifest = {
            "model_id": model_id,
            "version": version,
            "source": provenance,
            "license_id": license_name,
            "files": manifest_files,
        }
        (destination / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return BuiltModelBundle(destination, model_id, version, total, len(manifest_files))
