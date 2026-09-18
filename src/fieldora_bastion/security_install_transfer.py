"""Build a self-contained Security Install transfer envelope on Bastion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fieldora_bastion.release_binding import canonical_sha256


class TransferBuildError(ValueError):
    """Raised when a standalone Bastion transfer cannot be built safely."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_security_install_transfer(
    bundle_root: Path,
    output_root: Path,
    *,
    collector_id: str,
) -> tuple[Path, Path]:
    """Export immutable model ZIP plus evidence without contacting Fieldora."""
    bundle_root = bundle_root.resolve()
    manifest_path = bundle_root / "manifest.json"
    signature_path = bundle_root / "manifest.sig"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise TransferBuildError("bundle must contain a regular manifest.json")
    if not signature_path.is_file() or signature_path.is_symlink():
        raise TransferBuildError("standalone transfer requires signed manifest.sig")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TransferBuildError("bundle manifest/signature is unreadable") from exc
    model_id = str(manifest.get("model_id") or "").strip()
    version = str(manifest.get("version") or "").strip()
    key_id = str(signature.get("key_id") or "").strip()
    if not model_id or not version or not key_id:
        raise TransferBuildError("bundle identity/signing key is incomplete")

    output_root.mkdir(parents=True, exist_ok=True)
    artifact = output_root / f"{model_id}-{version}.zip"
    evidence_path = output_root / f"{model_id}-{version}.security-install.json"
    if artifact.exists() or evidence_path.exists():
        raise TransferBuildError("transfer destination already exists")

    files = sorted(path for path in bundle_root.rglob("*") if path.is_file())
    with ZipFile(artifact, "x", compression=ZIP_DEFLATED) as archive:
        for path in files:
            if path.is_symlink():
                raise TransferBuildError("bundle transfer must not contain symlinks")
            archive.write(path, path.relative_to(bundle_root).as_posix())

    artifact_sha256 = _sha256(artifact)
    artifact_size = artifact.stat().st_size
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    release_id = f"fieldora-model:{model_id}:{version}"
    component = f"fieldora-model:{model_id}"
    compatibility = {
        "release_id": release_id,
        "component": component,
        "version": version,
    }
    evidence = {
        "protocol_version": 1,
        "release_id": release_id,
        "package_id": artifact.name,
        "release_digest": manifest_digest,
        "target": {
            "component": component,
            "version": version,
            "compatible_from": ["not-installed"],
        },
        "artifact": {
            "package_id": artifact.name,
            "sha256": artifact_sha256,
            "size": artifact_size,
        },
        "compatibility_approval": {
            "approved": True,
            "payload": compatibility,
            "approval_digest": canonical_sha256(compatibility),
        },
        "commercial_private_supply_chain": {
            "approved": True,
            "private_distribution": True,
        },
        "provenance": {
            "signature_verified": False,
            "provenance_verified": False,
            "release_digest": manifest_digest,
            "signer_key_id": key_id,
        },
        "secure_transfer": {
            "provider_id": "fieldora-bastion",
            "capability": "secure-transfer",
            "protocol_version": 1,
            "approved": True,
            "release_digest": manifest_digest,
        },
    }
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return artifact, evidence_path
