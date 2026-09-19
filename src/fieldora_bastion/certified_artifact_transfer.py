"""Common standalone transfer envelope for Bastion-certified artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fieldora_bastion.release_binding import canonical_sha256
from fieldora_bastion.scanner import ScanError, payload_tree_digest

ARTIFACT_TYPES = {"ai_model", "map_dataset", "biodiversity_dataset"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CertifiedArtifactError(ValueError):
    """Raised when a standalone certified-artifact transfer is unsafe."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sign_evidence(evidence_bytes: bytes, signing_key: Path) -> tuple[str, str]:
    if signing_key.is_symlink() or not signing_key.is_file():
        raise CertifiedArtifactError("signing key must be a regular non-symlink file")
    try:
        key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise CertifiedArtifactError("signing key is unreadable or invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CertifiedArtifactError("signing key must be an Ed25519 private key")
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_id = hashlib.sha256(public_der).hexdigest()[:32]
    return key_id, base64.b64encode(key.sign(evidence_bytes)).decode("ascii")


def build_certified_artifact_transfer(
    source_root: Path,
    output_root: Path,
    *,
    artifact_type: str,
    artifact_id: str,
    version: str,
    signer_key_id: str,
    signing_key: Path,
    provenance: dict,
    validation: dict,
    expected_payload_sha256: str | None = None,
    expected_file_count: int | None = None,
) -> tuple[Path, Path]:
    """Package validated external material without any Fieldora dependency.

    Bastion records source facts and its own validation only. Receiver-side
    verification, receipts and PBAC decisions deliberately do not belong here.
    """
    if artifact_type not in ARTIFACT_TYPES:
        raise CertifiedArtifactError(f"unsupported artifact type: {artifact_type}")
    for name, value in (("artifact_id", artifact_id), ("version", version), ("signer_key_id", signer_key_id)):
        if not _SAFE_ID.fullmatch(value):
            raise CertifiedArtifactError(f"invalid {name}")
    if not isinstance(provenance, dict) or not provenance:
        raise CertifiedArtifactError("source provenance is required")
    if not isinstance(validation, dict) or validation.get("approved") is not True:
        raise CertifiedArtifactError("type-specific validation must be approved")

    source_root = source_root.resolve()
    try:
        observed_file_count, observed_payload_sha256 = payload_tree_digest(source_root)
    except ScanError as exc:
        raise CertifiedArtifactError("artifact source cannot be bound safely") from exc
    if expected_payload_sha256 is not None and observed_payload_sha256 != expected_payload_sha256:
        raise CertifiedArtifactError("artifact source changed after malware scan")
    if expected_file_count is not None and observed_file_count != expected_file_count:
        raise CertifiedArtifactError("artifact file count changed after malware scan")
    files = sorted(path for path in source_root.rglob("*") if path.is_file())
    if not files:
        raise CertifiedArtifactError("artifact source is empty")
    snapshot = Path(tempfile.mkdtemp(prefix="fieldora-bastion-snapshot-"))
    try:
        for path in files:
            if path.is_symlink():
                raise CertifiedArtifactError("certified transfer must not contain symlinks")
            relative = path.relative_to(source_root)
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())
        snapshot_count, snapshot_sha256 = payload_tree_digest(snapshot)
    except (OSError, ScanError) as exc:
        raise CertifiedArtifactError("artifact snapshot could not be created safely") from exc
    if snapshot_sha256 != observed_payload_sha256 or snapshot_count != observed_file_count:
        raise CertifiedArtifactError("artifact source changed while creating transfer snapshot")
    output_root.mkdir(parents=True, exist_ok=True)
    stem = f"{artifact_type}-{artifact_id}-{version}"
    package = output_root / f"{stem}.zip"
    evidence_path = output_root / f"{stem}.certified-artifact.json"
    signature_path = output_root / f"{stem}.certified-artifact.sig"
    if package.exists() or evidence_path.exists() or signature_path.exists():
        raise CertifiedArtifactError("transfer destination already exists")

    snapshot_files = sorted(path for path in snapshot.rglob("*") if path.is_file())
    with ZipFile(package, "x", compression=ZIP_DEFLATED) as archive:
        for path in snapshot_files:
            archive.write(path, path.relative_to(snapshot).as_posix())

    shutil.rmtree(snapshot, ignore_errors=True)
    package_sha = _sha256(package)
    release = {
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "version": version,
        "package_sha256": package_sha,
        "signer_key_id": signer_key_id,
    }
    evidence = {
        "protocol_version": 2,
        "release_id": f"fieldora-artifact:{artifact_type}:{artifact_id}:{version}",
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "version": version,
        "payload_sha256": observed_payload_sha256,
        "file_count": observed_file_count,
        "artifact": {
            "package_id": package.name,
            "sha256": package_sha,
            "size": package.stat().st_size,
        },
        "release_digest": canonical_sha256(release),
        "signer_key_id": signer_key_id,
        "source_provenance": provenance,
        "type_validation": validation,
        "secure_transfer": {
            "provider_id": "fieldora-bastion",
            "capability": "certified-artifact-transfer",
            "protocol_version": 2,
        },
    }
    evidence_bytes = (
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    derived_key_id, signature = _sign_evidence(evidence_bytes, signing_key)
    if derived_key_id != signer_key_id:
        raise CertifiedArtifactError("signer key id does not match Ed25519 signing key")
    evidence_path.write_bytes(evidence_bytes)
    signature_path.write_text(
        json.dumps(
            {"algorithm": "ed25519", "key_id": derived_key_id, "signature": signature},
            sort_keys=True, separators=(",", ":"),
        ) + "\n", encoding="utf-8",
    )
    return package, evidence_path
