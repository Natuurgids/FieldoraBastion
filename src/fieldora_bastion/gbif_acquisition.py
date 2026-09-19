"""Controlled GBIF archive acquisition owned by standalone Bastion."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from fieldora_bastion.gbif_provenance import GbifProvenanceError, validate_gbif_acquisition

_GBIF_HOSTS = {"gbif.org", "www.gbif.org", "api.gbif.org"}
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024


class GbifAcquisitionError(ValueError):
    """Raised when Bastion cannot acquire a GBIF archive safely."""


def _approved_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in _GBIF_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
        and not parsed.fragment
    )


class _GbifRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _approved_url(newurl):
            raise GbifAcquisitionError("GBIF redirect left approved HTTPS hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def acquire_gbif_archive(
    source_url: str,
    quarantine_root: Path,
    *,
    download_key: str,
    doi: str,
    license_id: str,
    query: dict[str, object],
    record_count: int,
    max_bytes: int = _MAX_ARCHIVE_BYTES,
    opener=None,
) -> tuple[Path, Path]:
    """Download into quarantine and generate provenance from bytes Bastion observed."""
    if not _approved_url(source_url):
        raise GbifAcquisitionError("GBIF source URL must use clean HTTPS on an approved GBIF host")
    if max_bytes <= 0:
        raise GbifAcquisitionError("GBIF archive size limit must be positive")
    quarantine_root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".gbif-", suffix=".part", dir=quarantine_root)
    os.close(descriptor)
    temporary = Path(temporary_name)
    final = quarantine_root / f"{download_key}.zip"
    provenance_path = quarantine_root / f"{download_key}.acquisition.json"
    if final.exists() or provenance_path.exists():
        temporary.unlink(missing_ok=True)
        raise GbifAcquisitionError("GBIF quarantine destination already exists")
    digest = hashlib.sha256()
    size = 0
    client = opener or build_opener(_GbifRedirectHandler())
    try:
        request = Request(source_url, headers={"User-Agent": "FieldoraBastion/controlled-acquisition"})
        with client.open(request, timeout=60) as response, temporary.open("wb") as target:
            final_url = response.geturl()
            if not _approved_url(final_url):
                raise GbifAcquisitionError("GBIF response URL left approved HTTPS hosts")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > max_bytes:
                    raise GbifAcquisitionError("GBIF archive exceeds configured size limit")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if size <= 0:
            raise GbifAcquisitionError("GBIF archive is empty")
        retrieved_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        record = {
            "download_key": download_key,
            "doi": doi,
            "source_url": final_url,
            "retrieved_at": retrieved_at,
            "license_id": license_id,
            "query": query,
            "record_count": record_count,
            "archive_sha256": digest.hexdigest(),
            "archive_size": size,
        }
        try:
            acquisition = validate_gbif_acquisition(record)
        except GbifProvenanceError as exc:
            raise GbifAcquisitionError(str(exc)) from exc
        os.replace(temporary, final)
        provenance_path.write_text(
            json.dumps(acquisition.as_provenance(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return final, provenance_path
    except (HTTPError, URLError, OSError) as exc:
        raise GbifAcquisitionError("GBIF archive acquisition failed") from exc
    finally:
        temporary.unlink(missing_ok=True)
