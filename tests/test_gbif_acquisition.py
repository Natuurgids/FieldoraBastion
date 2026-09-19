from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fieldora_bastion.gbif_acquisition import GbifAcquisitionError, acquire_gbif_archive


class _Response:
    def __init__(self, payload: bytes, url: str) -> None:
        self.payload = payload
        self.url = url
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, size: int) -> bytes:
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, _request, timeout: int):
        assert timeout == 60
        return self.response


def test_controlled_acquisition_binds_actual_downloaded_bytes(tmp_path: Path) -> None:
    payload = b"real-gbif-archive"
    archive, provenance = acquire_gbif_archive(
        "https://api.gbif.org/v1/occurrence/download/request/key-1",
        tmp_path,
        download_key="key-1",
        doi="10.15468/dl.example",
        license_id="CC-BY-4.0",
        query={"country": "NL"},
        record_count=7,
        opener=_Opener(_Response(payload, "https://api.gbif.org/v1/occurrence/download/request/key-1")),
    )
    assert archive.read_bytes() == payload
    import json
    record = json.loads(provenance.read_text())
    assert record["archive_sha256"] == hashlib.sha256(payload).hexdigest()
    assert record["archive_size"] == len(payload)


def test_controlled_acquisition_rejects_unapproved_final_url(tmp_path: Path) -> None:
    with pytest.raises(GbifAcquisitionError, match="response URL"):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-2",
            tmp_path,
            download_key="key-2",
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_Opener(_Response(b"payload", "https://evil.invalid/archive.zip")),
        )
    assert list(tmp_path.iterdir()) == []


def test_controlled_acquisition_enforces_stream_size_limit(tmp_path: Path) -> None:
    with pytest.raises(GbifAcquisitionError, match="size limit"):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-3",
            tmp_path,
            download_key="key-3",
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            max_bytes=3,
            opener=_Opener(_Response(b"1234", "https://api.gbif.org/v1/occurrence/download/request/key-3")),
        )
    assert list(tmp_path.iterdir()) == []
