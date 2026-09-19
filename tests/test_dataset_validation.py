from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import pytest

from fieldora_bastion.dataset_validation import (
    DatasetValidationError,
    validate_biodiversity_dataset,
    validate_map_dataset,
)


def test_map_geojson_requires_source_license_and_structure(tmp_path: Path) -> None:
    (tmp_path / "birds.geojson").write_text(
        '{"type":"FeatureCollection","features":[]}', encoding="utf-8"
    )
    result = validate_map_dataset(tmp_path, source_id="map-provider", license_id="ODbL")
    assert result["approved"] is True
    assert result["geojson_structures_checked"] == 1
    assert result["native_geospatial_validation_required_on_bastion"] is False


def test_map_native_format_is_marked_for_deeper_geospatial_validation(tmp_path: Path) -> None:
    (tmp_path / "base.gpkg").write_bytes(b"SQLite format 3\x00")
    result = validate_map_dataset(tmp_path, source_id="map-provider", license_id="license")
    assert result["native_geospatial_validation_required_on_bastion"] is True


def test_biodiversity_preserves_gbif_identity_and_dwc_terms(tmp_path: Path) -> None:
    (tmp_path / "occurrence.csv").write_text(
        "occurrenceID,scientificName,eventDate\n1,Parus major,2026-09-19\n",
        encoding="utf-8",
    )
    result = validate_biodiversity_dataset(
        tmp_path,
        source_id="gbif",
        license_id="CC-BY-4.0",
        dataset_key="example-dataset-key",
        doi="10.0000/example",
    )
    assert result["approved"] is True
    assert result["dataset_key"] == "example-dataset-key"
    assert result["doi"] == "10.0000/example"
    assert result["darwin_core_terms_observed"] == [
        "eventDate", "occurrenceID", "scientificName"
    ]


def test_biodiversity_zip_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "gbif.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "bad")
    with pytest.raises(DatasetValidationError, match="unsafe path"):
        validate_biodiversity_dataset(tmp_path, source_id="gbif", license_id="CC0")


def test_dataset_rejects_executable_payload(tmp_path: Path) -> None:
    (tmp_path / "payload.exe").write_bytes(b"MZ")
    with pytest.raises(DatasetValidationError, match="unsupported map"):
        validate_map_dataset(tmp_path, source_id="maps", license_id="license")
