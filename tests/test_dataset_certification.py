from __future__ import annotations

import json
from pathlib import Path

import pytest

from fieldora_bastion.scanner import _preflight

from fieldora_bastion.dataset_certification import (
    DatasetCertificationError,
    certify_gbif_dataset,
    certify_map_dataset,
)


def _scan(path: Path, source: Path) -> Path:
    report = path / "scan.json"
    _, payload_sha256 = _preflight(source, 64 * 1024 * 1024)
    report.write_text(json.dumps({
        "result": "clean", "scanner": "clamav", "payload_sha256": payload_sha256
    }), encoding="utf-8")
    return report


def test_gbif_certification_binds_source_validation_and_scan(tmp_path: Path) -> None:
    source = tmp_path / "gbif"
    source.mkdir()
    (source / "occurrence.csv").write_text(
        "occurrenceID,scientificName\n1,Parus major\n", encoding="utf-8"
    )
    package, evidence_path = certify_gbif_dataset(
        source, tmp_path / "out", dataset_id="nl-birds", version="2026-09",
        signer_key_id="key-1", scan_report=_scan(tmp_path, source),
        acquisition_record={
            "download_key": "0003988-260831124212860",
            "doi": "10.15468/dl.example",
            "source_url": "https://www.gbif.org/occurrence/download/0003988-260831124212860",
            "retrieved_at": "2026-09-18T12:00:00Z",
            "license_id": "CC-BY-4.0",
            "query": {"country": "NL"},
            "record_count": 1,
        },
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert package.is_file()
    assert evidence["source_provenance"]["provider"] == "gbif"
    assert evidence["source_provenance"]["malware_scan"]["result"] == "clean"
    assert evidence["type_validation"]["dataset_key"] == "0003988-260831124212860"


def test_map_certification_rejects_native_format_until_bastion_gdal_passes(tmp_path: Path) -> None:
    source = tmp_path / "map"
    source.mkdir()
    (source / "map.gpkg").write_bytes(b"SQLite format 3\x00")
    with pytest.raises(DatasetCertificationError, match="GDAL"):
        certify_map_dataset(
            source, tmp_path / "out", dataset_id="base", version="1",
            signer_key_id="key-1", source_id="maps", license_id="license",
            scan_report=_scan(tmp_path, source),
        )


def test_dataset_certification_rejects_unclean_scan(tmp_path: Path) -> None:
    source = tmp_path / "map"
    source.mkdir()
    (source / "map.geojson").write_text(
        '{"type":"FeatureCollection","features":[]}', encoding="utf-8"
    )
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({
        "result": "infected", "scanner": "clamav", "payload_sha256": "a" * 64
    }), encoding="utf-8")
    with pytest.raises(DatasetCertificationError, match="clean"):
        certify_map_dataset(
            source, tmp_path / "out", dataset_id="base", version="1",
            signer_key_id="key-1", source_id="maps", license_id="license",
            scan_report=report,
        )


def test_dataset_certification_rejects_payload_changed_after_scan(tmp_path: Path) -> None:
    source = tmp_path / "map-changed"
    source.mkdir()
    payload = source / "map.geojson"
    payload.write_text('{"type":"FeatureCollection","features":[]}', encoding="utf-8")
    report = _scan(tmp_path, source)
    payload.write_text('{"type":"FeatureCollection","features":[{"type":"Feature","properties":{},"geometry":null}]}', encoding="utf-8")
    with pytest.raises(DatasetCertificationError, match="changed after malware scan"):
        certify_map_dataset(
            source, tmp_path / "out-changed", dataset_id="base", version="1",
            signer_key_id="key-1", source_id="maps", license_id="license",
            scan_report=report,
        )
