"""Common standalone transfer envelope for Bastion-certified artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fieldora_bastion.release_binding import canonical_sha256
from fieldora_bastion.scanner import ScanError, payload_tree_digest
from fieldora_bastion.signing import PemFileSigner, Signer, SigningError

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


def build_certified_artifact_transfer(
    source_root: Path,
    output_root: Path,
    *,
    artifact_type: str,
    artifact_id: str,
    version: str,
    signer_key_id: str,
    signing_key: Path | None = None,
    signer: Signer | None = None,
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
    identity_fields = (
        ("artifact_id", artifact_id),
        ("version", version),
        ("signer_key_id", signer_key_id),
    )
    for name, value in identity_fields:
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
    if (
        expected_payload_sha256 is not None
        and observed_payload_sha256 != expected_payload_sha256
    ):
        raise CertifiedArtifactError("artifact source changed after malware scan")
    if expected_file_count is not None and observed_file_count != expected_file_count:
        raise CertifiedArtifactError("artifact file count changed after malware scan")
    if source_root.is_file():
        files = [source_root]
    elif source_root.is_dir():
        files = sorted(path for path in source_root.rglob("*") if path.is_file())
    else:
        raise CertifiedArtifactError("artifact source is unavailable")
    if not files:
        raise CertifiedArtifactError("artifact source is empty")
    snapshot = Path(tempfile.mkdtemp(prefix="fieldora-bastion-snapshot-"))
    package: Path | None = None
    try:
        try:
            for path in files:
                if path.is_symlink():
                    raise CertifiedArtifactError("certified transfer must not contain symlinks")
                relative = (
                    Path(path.name)
                    if source_root.is_file()
                    else path.relative_to(source_root)
                )
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
                try:
                    with os.fdopen(descriptor, "rb") as source, destination.open("xb") as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                except BaseException:
                    destination.unlink(missing_ok=True)
                    raise
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
    finally:
        shutil.rmtree(snapshot, ignore_errors=True)
    if package is None:
        raise CertifiedArtifactError("artifact package was not created")
    try:
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
        if signer is not None and signing_key is not None:
            raise CertifiedArtifactError("provide signer or signing_key, not both")
        try:
            active_signer = signer or (PemFileSigner(signing_key) if signing_key else None)
        except SigningError as exc:
            raise CertifiedArtifactError(str(exc)) from exc
        if active_signer is None:
            raise CertifiedArtifactError("a Bastion signer is required")
        signed = active_signer.sign(evidence_bytes)
        derived_key_id, signature = signed.key_id, signed.signature
        if derived_key_id != signer_key_id:
            raise CertifiedArtifactError("signer key id does not match configured signer")
        evidence_path.write_bytes(evidence_bytes)
        signature_path.write_text(
            json.dumps(
                {"algorithm": "ed25519", "key_id": derived_key_id, "signature": signature},
                sort_keys=True, separators=(",", ":"),
            ) + "\n", encoding="utf-8",
        )
    except BaseException:
        signature_path.unlink(missing_ok=True)
        evidence_path.unlink(missing_ok=True)
        package.unlink(missing_ok=True)
        raise
    return package, evidence_path
