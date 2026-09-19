from __future__ import annotations

import pytest

from fieldora_bastion.gbif_provenance import GbifProvenanceError, validate_gbif_acquisition


def _record() -> dict[str, object]:
    return {
        "download_key": "0003988-260831124212860",
        "doi": "10.15468/dl.example",
        "source_url": "https://www.gbif.org/occurrence/download/0003988-260831124212860",
        "retrieved_at": "2026-09-18T12:00:00Z",
        "license_id": "CC-BY-4.0",
        "query": {"country": "NL", "hasCoordinate": True},
        "record_count": 42,
        "archive_sha256": "a" * 64,
        "archive_size": 12345,
    }


def test_gbif_acquisition_preserves_source_facts() -> None:
    acquisition = validate_gbif_acquisition(_record())
    evidence = acquisition.as_provenance()
    assert evidence["provider"] == "gbif"
    assert evidence["download_key"] == "0003988-260831124212860"
    assert evidence["record_count"] == 42
    assert evidence["query"]["country"] == "NL"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("download_key", ""),
        ("doi", ""),
        ("license_id", ""),
        ("query", {}),
        ("record_count", -1),
        ("archive_sha256", ""),
        ("archive_size", 0),
    ],
)
def test_gbif_acquisition_fails_closed_on_missing_provenance(field: str, value: object) -> None:
    record = _record()
    record[field] = value
    with pytest.raises(GbifProvenanceError):
        validate_gbif_acquisition(record)


def test_gbif_acquisition_rejects_non_gbif_source() -> None:
    record = _record()
    record["source_url"] = "https://example.invalid/gbif.zip"
    with pytest.raises(GbifProvenanceError, match="approved GBIF host"):
        validate_gbif_acquisition(record)



def test_gbif_acquisition_accepts_official_api_host() -> None:
    record = _record()
    record["source_url"] = "https://api.gbif.org/v1/occurrence/download/request/0003988-260831124212860"
    assert validate_gbif_acquisition(record).source_url.startswith("https://api.gbif.org/")


@pytest.mark.parametrize("source_url", [
    "https://user@api.gbif.org/v1/occurrence/download/example",
    "https://api.gbif.org:8443/v1/occurrence/download/example",
    "https://api.gbif.org/v1/occurrence/download/example#fragment",
])
def test_gbif_acquisition_rejects_ambiguous_source_urls(source_url: str) -> None:
    record = _record()
    record["source_url"] = source_url
    with pytest.raises(GbifProvenanceError, match="clean HTTPS"):
        validate_gbif_acquisition(record)
