"""Fail-closed certification orchestration for non-model Bastion datasets."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fieldora_bastion.certified_artifact_transfer import build_certified_artifact_transfer
from fieldora_bastion.dataset_validation import (
    DatasetValidationError,
    validate_biodiversity_dataset,
    validate_map_dataset,
)
from fieldora_bastion.gbif_provenance import validate_gbif_acquisition
from fieldora_bastion.scanner import ScanError, payload_tree_digest

_MAX_ZIP_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class DatasetCertificationError(ValueError):
    """Raised when a dataset cannot cross the Bastion certification boundary."""


def _clean_scan(report_path: Path, source: Path) -> dict[str, object]:
    if not report_path.is_file() or report_path.is_symlink():
        raise DatasetCertificationError("clean malware scan report is required")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetCertificationError("malware scan report is unreadable") from exc
    if report.get("result") != "clean" or report.get("scanner") != "clamav":
        raise DatasetCertificationError("dataset requires an approved clean ClamAV scan")
    expected = str(report.get("payload_sha256") or "").strip()
    if not expected:
        raise DatasetCertificationError("scan report is not bound to a payload digest")
    try:
        expected_count = int(report.get("file_count"))
    except (TypeError, ValueError):
        raise DatasetCertificationError("scan report is not bound to a file count") from None
    try:
        observed_count, observed = payload_tree_digest(source, 64 * 1024 * 1024 * 1024)
    except ScanError as exc:
        raise DatasetCertificationError("dataset cannot be rehashed safely") from exc
    if observed != expected or observed_count != expected_count:
        raise DatasetCertificationError("dataset changed after malware scan")
    return report


def certify_map_dataset(
    source: Path,
    output: Path,
    *,
    dataset_id: str,
    version: str,
    signer_key_id: str,
    signing_key: Path,
    source_id: str,
    license_id: str,
    scan_report: Path,
) -> tuple[Path, Path]:
    scan = _clean_scan(scan_report, source)
    try:
        validation = validate_map_dataset(source, source_id=source_id, license_id=license_id)
    except DatasetValidationError as exc:
        raise DatasetCertificationError(str(exc)) from exc
    provenance = {
        "provider": source_id,
        "license_id": license_id,
        "malware_scan": scan,
    }
    return build_certified_artifact_transfer(
        source, output, artifact_type="map_dataset", artifact_id=dataset_id,
        version=version, signer_key_id=signer_key_id, signing_key=signing_key,
        provenance=provenance, validation=validation,
        expected_payload_sha256=str(scan["payload_sha256"]),
        expected_file_count=int(scan["file_count"]),
    )


def certify_gbif_dataset(
    source: Path,
    output: Path,
    *,
    dataset_id: str,
    version: str,
    signer_key_id: str,
    signing_key: Path,
    acquisition_record: dict[str, object],
    scan_report: Path,
    acquisition_public_key: Path,
) -> tuple[Path, Path]:
    scan = _clean_scan(scan_report, source)
    acquisition = validate_gbif_acquisition(acquisition_record)
    attestation = acquisition_record.get("acquisition_attestation")
    if not isinstance(attestation, dict) or attestation.get("algorithm") != "ed25519":
        raise DatasetCertificationError("signed Bastion GBIF acquisition evidence is required")
    try:
        public_key = serialization.load_pem_public_key(acquisition_public_key.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise DatasetCertificationError("GBIF acquisition public key is unreadable") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise DatasetCertificationError("GBIF acquisition public key must be Ed25519")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_id = hashlib.sha256(public_der).hexdigest()[:32]
    if str(attestation.get("key_id") or "") != key_id:
        raise DatasetCertificationError(
            "GBIF acquisition attestation key does not match trusted key"
        )
    unsigned = {
        key: value
        for key, value in acquisition_record.items()
        if key != "acquisition_attestation"
    }
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        signature = bytes.fromhex(str(attestation.get("signature") or ""))
        public_key.verify(signature, payload)
    except (ValueError, InvalidSignature) as exc:
        raise DatasetCertificationError(
            "GBIF acquisition attestation signature is invalid"
        ) from exc
    archive_sha256 = str(acquisition_record.get("archive_sha256") or "").lower()
    archive_size = acquisition.archive_size
    if source.is_symlink() or not source.is_file():
        raise DatasetCertificationError(
            "GBIF certification source must be the Bastion-acquired archive file"
        )
    if source.stat().st_size != archive_size:
        raise DatasetCertificationError("GBIF acquisition archive size does not match source")
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != archive_sha256:
        raise DatasetCertificationError("GBIF acquisition archive digest does not match source")
    provenance = acquisition.as_provenance()
    try:
        with tempfile.TemporaryDirectory(prefix="fieldora-gbif-validate-") as temporary:
            validation_root = Path(temporary)
            with ZipFile(source, "r") as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_ZIP_MEMBERS:
                    raise DatasetCertificationError("GBIF archive contains too many members")
                seen: set[str] = set()
                total_uncompressed = 0
                for info in infos:
                    normalized = info.filename.replace("\\", "/")
                    path = PurePosixPath(normalized)
                    parts = path.parts
                    if (
                        not normalized
                        or normalized.startswith(("/", "//"))
                        or _DRIVE_PREFIX.match(normalized)
                        or any(part in {"", ".", ".."} for part in parts)
                        or normalized in seen
                    ):
                        raise DatasetCertificationError("GBIF archive contains an unsafe path")
                    seen.add(normalized)
                    mode = info.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise DatasetCertificationError("GBIF archive contains a special file")
                    if info.file_size > _MAX_MEMBER_BYTES:
                        raise DatasetCertificationError("GBIF archive member exceeds size limit")
                    total_uncompressed += info.file_size
                    if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                        raise DatasetCertificationError(
                            "GBIF archive exceeds uncompressed size limit"
                        )
                    if (
                        info.file_size > 1024 * 1024
                        and info.compress_size > 0
                        and info.file_size / info.compress_size > _MAX_COMPRESSION_RATIO
                    ):
                        raise DatasetCertificationError(
                            "GBIF archive member compression ratio is unsafe"
                        )
                    if info.is_dir():
                        continue
                    target = validation_root.joinpath(*parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    written = 0
                    with archive.open(info, "r") as stream, target.open("xb") as output_stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            written += len(block)
                            if written > info.file_size or written > _MAX_MEMBER_BYTES:
                                raise DatasetCertificationError(
                                    "GBIF archive member exceeded declared size"
                                )
                            output_stream.write(block)
                    if written != info.file_size:
                        raise DatasetCertificationError(
                            "GBIF archive member size did not match metadata"
                        )
            validation = validate_biodiversity_dataset(
                validation_root,
                source_id="gbif",
                license_id=acquisition.license_id,
                dataset_key=acquisition.download_key,
                doi=acquisition.doi,
            )
    except (BadZipFile, OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, DatasetCertificationError):
            raise
        raise DatasetCertificationError("GBIF acquired archive is not a valid dataset ZIP") from exc
    provenance["malware_scan"] = scan
    return build_certified_artifact_transfer(
        source, output, artifact_type="biodiversity_dataset", artifact_id=dataset_id,
        version=version, signer_key_id=signer_key_id, signing_key=signing_key,
        provenance=provenance, validation=validation,
        expected_payload_sha256=str(scan["payload_sha256"]),
        expected_file_count=int(scan["file_count"]),
    )
