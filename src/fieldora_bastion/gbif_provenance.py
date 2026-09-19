"""Validate provenance captured by controlled GBIF acquisition."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse


class GbifProvenanceError(ValueError):
    """Raised when a GBIF acquisition record is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class GbifAcquisition:
    download_key: str
    doi: str
    source_url: str
    retrieved_at: str
    license_id: str
    query: dict[str, object]
    record_count: int

    def as_provenance(self) -> dict[str, object]:
        return {
            "provider": "gbif",
            "download_key": self.download_key,
            "doi": self.doi,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "license_id": self.license_id,
            "query": self.query,
            "record_count": self.record_count,
        }


def validate_gbif_acquisition(record: dict[str, object]) -> GbifAcquisition:
    """Fail closed unless the acquisition record identifies an actual GBIF download."""
    download_key = str(record.get("download_key") or "").strip()
    doi = str(record.get("doi") or "").strip()
    source_url = str(record.get("source_url") or "").strip()
    retrieved_at = str(record.get("retrieved_at") or "").strip()
    license_id = str(record.get("license_id") or "").strip()
    query = record.get("query")
    count = record.get("record_count")
    if not all((download_key, doi, source_url, retrieved_at, license_id)):
        raise GbifProvenanceError("GBIF download identity, DOI, source, retrieval time and license are required")
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or parsed.hostname not in {"gbif.org", "www.gbif.org"}:
        raise GbifProvenanceError("GBIF source URL must use HTTPS on gbif.org")
    try:
        observed = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GbifProvenanceError("GBIF retrieval time must be ISO-8601") from exc
    if observed.tzinfo is None or observed > datetime.now(timezone.utc):
        raise GbifProvenanceError("GBIF retrieval time must be timezone-aware and not in the future")
    if not isinstance(query, dict) or not query:
        raise GbifProvenanceError("GBIF acquisition query is required")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise GbifProvenanceError("GBIF record count must be a non-negative integer")
    return GbifAcquisition(
        download_key=download_key,
        doi=doi,
        source_url=source_url,
        retrieved_at=retrieved_at,
        license_id=license_id,
        query=query,
        record_count=count,
    )
