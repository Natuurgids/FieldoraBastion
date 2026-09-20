from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fieldora_bastion.dataset_certification import (
    DatasetCertificationError,
    certify_gbif_dataset,
    certify_map_dataset,
)
from fieldora_bastion.scanner import payload_tree_digest


def _signing_key(tmp_path: Path) -> tuple[Path, str]:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "signing-key.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return path, hashlib.sha256(public_der).hexdigest()[:32]


def _scan(path: Path, source: Path) -> Path:
    report = path / "scan.json"
    file_count, payload_sha256 = payload_tree_digest(source, 64 * 1024 * 1024)
    report.write_text(json.dumps({
        "result": "clean", "scanner": "clamav", "payload_sha256": payload_sha256,
        "file_count": file_count
    }), encoding="utf-8")
    return report


def test_gbif_certification_binds_source_validation_and_scan(tmp_path: Path) -> None:
    source = tmp_path / "0003988-260831124212860.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "occurrence.csv", "occurrenceID,scientificName\n1,Parus major\n"
        )
    archive_bytes = source.read_bytes()
    signing_key, key_id = _signing_key(tmp_path)
    package, evidence_path = certify_gbif_dataset(
        source, tmp_path / "out", dataset_id="nl-birds", version="2026-09",
        signer_key_id=key_id, signing_key=signing_key, scan_report=_scan(tmp_path, source),
        acquisition_record={
            "download_key": "0003988-260831124212860",
            "doi": "10.15468/dl.example",
            "source_url": "https://www.gbif.org/occurrence/download/0003988-260831124212860",
            "retrieved_at": "2026-09-18T12:00:00Z",
            "license_id": "CC-BY-4.0",
            "query": {"country": "NL"},
            "record_count": 1,
            "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "archive_size": len(archive_bytes),
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
        signing_key, key_id = _signing_key(tmp_path)
        certify_map_dataset(
            source, tmp_path / "out", dataset_id="base", version="1",
            signer_key_id=key_id, signing_key=signing_key, source_id="maps", license_id="license",
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
            signer_key_id=_signing_key(tmp_path)[1], signing_key=_signing_key(tmp_path)[0], source_id="maps", license_id="license",
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
        signing_key, key_id = _signing_key(tmp_path)
        certify_map_dataset(
            source, tmp_path / "out-changed", dataset_id="base", version="1",
            signer_key_id=key_id, signing_key=signing_key, source_id="maps", license_id="license",
            scan_report=report,
        )


def _gbif_record(source: Path) -> dict[str, object]:
    payload = source.read_bytes()
    return {
        "download_key": "0003988-260831124212860",
        "doi": "10.15468/dl.example",
        "source_url": "https://www.gbif.org/occurrence/download/0003988-260831124212860",
        "retrieved_at": "2026-09-18T12:00:00Z",
        "license_id": "CC-BY-4.0",
        "query": {"country": "NL"},
        "record_count": 1,
        "archive_sha256": hashlib.sha256(payload).hexdigest(),
        "archive_size": len(payload),
    }


@pytest.mark.parametrize("member", ["../escape.csv", "/absolute.csv", "C:/escape.csv", r"..\\escape.csv"])
def test_gbif_certification_rejects_unsafe_archive_paths(tmp_path: Path, member: str) -> None:
    source = tmp_path / "unsafe.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(member, "occurrenceID,scientificName\n1,Parus major\n")
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="unsafe path"):
        certify_gbif_dataset(
            source, tmp_path / "out", dataset_id="unsafe", version="1",
            signer_key_id=key_id, signing_key=signing_key,
            acquisition_record=_gbif_record(source), scan_report=_scan(tmp_path, source),
        )


def test_gbif_certification_rejects_acquisition_digest_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "digest.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("occurrence.csv", "occurrenceID,scientificName\n1,Parus major\n")
    record = _gbif_record(source)
    record["archive_sha256"] = "0" * 64
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="digest does not match"):
        certify_gbif_dataset(
            source, tmp_path / "out", dataset_id="digest", version="1",
            signer_key_id=key_id, signing_key=signing_key,
            acquisition_record=record, scan_report=_scan(tmp_path, source),
        )


def test_gbif_certification_rejects_invalid_zip(tmp_path: Path) -> None:
    source = tmp_path / "invalid.zip"
    source.write_bytes(b"not-a-zip")
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="valid dataset ZIP"):
        certify_gbif_dataset(
            source, tmp_path / "out", dataset_id="invalid", version="1",
            signer_key_id=key_id, signing_key=signing_key,
            acquisition_record=_gbif_record(source), scan_report=_scan(tmp_path, source),
        )


def test_gbif_certification_rejects_duplicate_normalized_member(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("occurrence.csv", "occurrenceID,scientificName\n1,Parus major\n")
        archive.writestr("occurrence.csv", "occurrenceID,scientificName\n2,Cyanistes caeruleus\n")
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="unsafe path"):
        certify_gbif_dataset(source, tmp_path / "out", dataset_id="duplicate", version="1", signer_key_id=key_id, signing_key=signing_key, acquisition_record=_gbif_record(source), scan_report=_scan(tmp_path, source))


def test_gbif_certification_rejects_symlink_member(tmp_path: Path) -> None:
    source = tmp_path / "symlink.zip"
    with ZipFile(source, "w") as archive:
        info = ZipInfo("occurrence.csv")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "target.csv")
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="special file"):
        certify_gbif_dataset(source, tmp_path / "out", dataset_id="symlink", version="1", signer_key_id=key_id, signing_key=signing_key, acquisition_record=_gbif_record(source), scan_report=_scan(tmp_path, source))


def test_gbif_certification_rejects_compression_ratio_bomb(tmp_path: Path) -> None:
    source = tmp_path / "bomb.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("occurrence.csv", b"A" * (2 * 1024 * 1024))
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="compression ratio"):
        certify_gbif_dataset(source, tmp_path / "out", dataset_id="bomb", version="1", signer_key_id=key_id, signing_key=signing_key, acquisition_record=_gbif_record(source), scan_report=_scan(tmp_path, source))


def test_gbif_certification_rejects_acquisition_size_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "size.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("occurrence.csv", "occurrenceID,scientificName\n1,Parus major\n")
    record = _gbif_record(source)
    record["archive_size"] = int(record["archive_size"]) + 1
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="size does not match"):
        certify_gbif_dataset(source, tmp_path / "out", dataset_id="size", version="1", signer_key_id=key_id, signing_key=signing_key, acquisition_record=record, scan_report=_scan(tmp_path, source))


def test_gbif_certification_rejects_scan_file_count_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "count.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("occurrence.csv", "occurrenceID,scientificName\n1,Parus major\n")
    report = _scan(tmp_path, source)
    data = json.loads(report.read_text())
    data["file_count"] += 1
    report.write_text(json.dumps(data), encoding="utf-8")
    signing_key, key_id = _signing_key(tmp_path)
    with pytest.raises(DatasetCertificationError, match="changed after malware scan"):
        certify_gbif_dataset(source, tmp_path / "out", dataset_id="count", version="1", signer_key_id=key_id, signing_key=signing_key, acquisition_record=_gbif_record(source), scan_report=report)
