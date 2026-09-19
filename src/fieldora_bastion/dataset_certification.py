"""Fail-closed certification orchestration for non-model Bastion datasets."""

from __future__ import annotations

import json
from pathlib import Path

from fieldora_bastion.certified_artifact_transfer import build_certified_artifact_transfer
from fieldora_bastion.dataset_validation import validate_biodiversity_dataset, validate_map_dataset
from fieldora_bastion.gbif_provenance import validate_gbif_acquisition


class DatasetCertificationError(ValueError):
    """Raised when a dataset cannot cross the Bastion certification boundary."""


def _clean_scan(report_path: Path) -> dict[str, object]:
    if not report_path.is_file() or report_path.is_symlink():
        raise DatasetCertificationError("clean malware scan report is required")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetCertificationError("malware scan report is unreadable") from exc
    if report.get("result") != "clean" or report.get("scanner") != "clamav":
        raise DatasetCertificationError("dataset requires an approved clean ClamAV scan")
    if not str(report.get("payload_sha256") or "").strip():
        raise DatasetCertificationError("scan report is not bound to a payload digest")
    return report


def certify_map_dataset(
    source: Path,
    output: Path,
    *,
    dataset_id: str,
    version: str,
    signer_key_id: str,
    source_id: str,
    license_id: str,
    scan_report: Path,
) -> tuple[Path, Path]:
    scan = _clean_scan(scan_report)
    validation = validate_map_dataset(source, source_id=source_id, license_id=license_id)
    if validation.get("native_geospatial_validation_required_on_bastion"):
        raise DatasetCertificationError(
            "native geospatial formats require Bastion GDAL validation before certification"
        )
    provenance = {
        "provider": source_id,
        "license_id": license_id,
        "malware_scan": scan,
    }
    return build_certified_artifact_transfer(
        source, output, artifact_type="map_dataset", artifact_id=dataset_id,
        version=version, signer_key_id=signer_key_id,
        provenance=provenance, validation=validation,
    )


def certify_gbif_dataset(
    source: Path,
    output: Path,
    *,
    dataset_id: str,
    version: str,
    signer_key_id: str,
    acquisition_record: dict[str, object],
    scan_report: Path,
) -> tuple[Path, Path]:
    scan = _clean_scan(scan_report)
    acquisition = validate_gbif_acquisition(acquisition_record)
    provenance = acquisition.as_provenance()
    validation = validate_biodiversity_dataset(
        source,
        source_id="gbif",
        license_id=acquisition.license_id,
        dataset_key=acquisition.download_key,
        doi=acquisition.doi,
    )
    provenance["malware_scan"] = scan
    return build_certified_artifact_transfer(
        source, output, artifact_type="biodiversity_dataset", artifact_id=dataset_id,
        version=version, signer_key_id=signer_key_id,
        provenance=provenance, validation=validation,
    )
