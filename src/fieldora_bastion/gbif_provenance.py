"""Validate provenance captured by controlled GBIF acquisition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GBIF_HOSTS = {"gbif.org", "www.gbif.org", "api.gbif.org"}


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
    archive_sha256: str
    archive_size: int

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
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
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
    archive_sha256 = str(record.get("archive_sha256") or "").strip().lower()
    archive_size = record.get("archive_size")
    if not all((download_key, doi, source_url, retrieved_at, license_id)):
        raise GbifProvenanceError("GBIF download identity, DOI, source, retrieval time and license are required")
    parsed = urlparse(source_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _GBIF_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise GbifProvenanceError("GBIF source URL must use clean HTTPS on an approved GBIF host")
    try:
        observed = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GbifProvenanceError("GBIF retrieval time must be ISO-8601") from exc
    if observed.tzinfo is None or observed > datetime.now(UTC):
        raise GbifProvenanceError("GBIF retrieval time must be timezone-aware and not in the future")
    if not isinstance(query, dict) or not query:
        raise GbifProvenanceError("GBIF acquisition query is required")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise GbifProvenanceError("GBIF record count must be a non-negative integer")
    if not _SHA256.fullmatch(archive_sha256):
        raise GbifProvenanceError("GBIF original archive SHA-256 is required")
    if not isinstance(archive_size, int) or isinstance(archive_size, bool) or archive_size <= 0:
        raise GbifProvenanceError("GBIF original archive size must be a positive integer")
    return GbifAcquisition(
        download_key=download_key,
        doi=doi,
        source_url=source_url,
        retrieved_at=retrieved_at,
        license_id=license_id,
        query=query,
        record_count=count,
        archive_sha256=archive_sha256,
        archive_size=archive_size,
    )
