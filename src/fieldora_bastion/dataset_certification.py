"""Fail-closed certification orchestration for non-model Bastion datasets."""

from __future__ import annotations

import hashlib
import json
import tempfile
from zipfile import BadZipFile, ZipFile
from pathlib import Path

from fieldora_bastion.certified_artifact_transfer import build_certified_artifact_transfer
from fieldora_bastion.dataset_validation import (
    DatasetValidationError,
    validate_biodiversity_dataset,
    validate_map_dataset,
)
from fieldora_bastion.gbif_provenance import validate_gbif_acquisition
from fieldora_bastion.scanner import ScanError, payload_tree_digest


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
) -> tuple[Path, Path]:
    scan = _clean_scan(scan_report, source)
    acquisition = validate_gbif_acquisition(acquisition_record)
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
                for info in archive.infolist():
                    target = (validation_root / info.filename).resolve()
                    if validation_root.resolve() not in target.parents and target != validation_root.resolve():
                        raise DatasetCertificationError("GBIF archive contains an unsafe path")
                    if info.is_dir():
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info, "r") as stream, target.open("xb") as output_stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            output_stream.write(block)
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
