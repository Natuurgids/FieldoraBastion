from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fieldora_bastion.gbif_acquisition as ga
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


def _signing_key(tmp_path: Path) -> Path:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "acquisition-key.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path


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
        opener=_Opener(
            _Response(payload, "https://api.gbif.org/v1/occurrence/download/request/key-1")
        ),
        signing_key=_signing_key(tmp_path),
    )
    assert archive.read_bytes() == payload
    record = json.loads(provenance.read_text())
    assert record["archive_sha256"] == hashlib.sha256(payload).hexdigest()
    assert record["archive_size"] == len(payload)
    assert record["acquisition_attestation"]["algorithm"] == "ed25519"
    assert record["acquisition_attestation"]["encoding"] == "base64"
    assert len(record["acquisition_attestation"]["signature"]) == 88


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
            signing_key=_signing_key(tmp_path),
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
            opener=_Opener(
                _Response(b"1234", "https://api.gbif.org/v1/occurrence/download/request/key-3")
            ),
            signing_key=_signing_key(tmp_path),
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("download_key", ["../escape", "..", ".", "a/b", r"a\\b"])
def test_controlled_acquisition_rejects_unsafe_download_key_before_network(
    tmp_path: Path, download_key: str
) -> None:
    class _NeverOpen:
        def open(self, *_args, **_kwargs):
            raise AssertionError("network must not be reached")

    with pytest.raises(GbifAcquisitionError, match="download key"):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-safe",
            tmp_path,
            download_key=download_key,
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_NeverOpen(),
            signing_key=_signing_key(tmp_path),
        )
    assert list(tmp_path.iterdir()) == []


def test_controlled_acquisition_rejects_invalid_metadata_before_network(tmp_path: Path) -> None:
    class _NeverOpen:
        def open(self, *_args, **_kwargs):
            raise AssertionError("network must not be reached")

    with pytest.raises(GbifAcquisitionError):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-4",
            tmp_path,
            download_key="key-4",
            doi="",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_NeverOpen(),
            signing_key=_signing_key(tmp_path),
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "source_url",
    [
        "https://api.gbif.org/v1/species/search?q=bird",
        "https://api.gbif.org/v1/occurrence/download/request/key-1?token=secret",
        "https://www.gbif.org/dataset/example",
    ],
)
def test_controlled_acquisition_rejects_non_download_endpoints_before_network(
    tmp_path: Path, source_url: str
) -> None:
    class _NeverOpen:
        def open(self, *_args, **_kwargs):
            raise AssertionError("network must not be reached")

    with pytest.raises(GbifAcquisitionError, match="source URL"):
        acquire_gbif_archive(
            source_url,
            tmp_path,
            download_key="key-safe",
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_NeverOpen(),
            signing_key=_signing_key(tmp_path),
        )
    assert list(tmp_path.iterdir()) == [tmp_path / "acquisition-key.pem"]


def test_controlled_acquisition_rolls_back_if_provenance_publish_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = _signing_key(tmp_path)
    real_replace = ga.os.replace
    calls = 0

    def fail_second_replace(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated provenance publish failure")
        return real_replace(source, destination)

    monkeypatch.setattr(ga.os, "replace", fail_second_replace)
    with pytest.raises(GbifAcquisitionError, match="acquisition failed"):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-rollback",
            tmp_path,
            download_key="key-rollback",
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_Opener(
                _Response(
                    b"payload",
                    "https://api.gbif.org/v1/occurrence/download/request/key-rollback",
                )
            ),
            signing_key=signing_key,
        )
    assert not (tmp_path / "key-rollback.zip").exists()
    assert not (tmp_path / "key-rollback.acquisition.json").exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["acquisition-key.pem"]


def test_controlled_acquisition_cleans_up_if_archive_publish_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = _signing_key(tmp_path)

    def fail_replace(_source, _destination):
        raise OSError("simulated archive publish failure")

    monkeypatch.setattr(ga.os, "replace", fail_replace)
    with pytest.raises(GbifAcquisitionError, match="acquisition failed"):
        acquire_gbif_archive(
            "https://api.gbif.org/v1/occurrence/download/request/key-no-publish",
            tmp_path,
            download_key="key-no-publish",
            doi="10.15468/dl.example",
            license_id="CC0-1.0",
            query={"country": "NL"},
            record_count=1,
            opener=_Opener(
                _Response(
                    b"payload",
                    "https://api.gbif.org/v1/occurrence/download/request/key-no-publish",
                )
            ),
            signing_key=signing_key,
        )
    assert not (tmp_path / "key-no-publish.zip").exists()
    assert not (tmp_path / "key-no-publish.acquisition.json").exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["acquisition-key.pem"]
