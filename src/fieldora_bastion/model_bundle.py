"""Build Fieldora-compatible offline model bundles from pre-vetted files."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    signing_key_id: str = ""


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


def _sign_manifest(manifest_bytes: bytes, signing_key: Path) -> tuple[str, str]:
    if signing_key.is_symlink() or not signing_key.is_file():
        raise BundleBuildError("signing key must be a regular non-symlink file")
    try:
        key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise BundleBuildError("signing key is unreadable or invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleBuildError("signing key must be an Ed25519 private key")
    public = key.public_key()
    public_der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(public_der).hexdigest()[:32]
    signature = base64.b64encode(key.sign(manifest_bytes)).decode("ascii")
    return key_id, signature


def build_model_bundle(
    source_root: Path,
    output_root: Path,
    *,
    model_id: str,
    version: str,
    source: str = "fieldora-bastion",
    license_id: str = "unspecified",
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    signing_key: Path | None = None,
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
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        (destination / "manifest.json").write_bytes(manifest_bytes)
        signing_key_id = ""
        if signing_key is not None:
            signing_key_id, signature = _sign_manifest(manifest_bytes, signing_key)
            (destination / "manifest.sig").write_text(
                json.dumps(
                    {
                        "algorithm": "ed25519",
                        "key_id": signing_key_id,
                        "signature": signature,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return BuiltModelBundle(
        destination,
        model_id,
        version,
        total,
        len(manifest_files),
        signing_key_id,
    )
