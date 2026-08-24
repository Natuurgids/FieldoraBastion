from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fieldora_bastion.model_bundle import BundleBuildError, build_model_bundle


def _signing_key(path: Path) -> tuple[Path, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, private


def test_builds_fieldora_compatible_model_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "model").mkdir(parents=True)
    (source / "model/model.safetensors").write_bytes(b"model")
    (source / "model/config.json").write_text('{"type":"test"}', encoding="utf-8")

    built = build_model_bundle(
        source,
        tmp_path / "out",
        model_id="bio-model",
        version="1.2.3",
        source="approved-upstream",
        license_id="test-license",
    )

    manifest = json.loads((built.root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_id"] == "bio-model"
    assert manifest["version"] == "1.2.3"
    assert manifest["source"] == "approved-upstream"
    assert manifest["license_id"] == "test-license"
    files = {item["path"]: item for item in manifest["files"]}
    assert files["model/model.safetensors"]["sha256"] == hashlib.sha256(b"model").hexdigest()
    assert files["model/model.safetensors"]["size_bytes"] == 5
    assert (built.root / "model/model.safetensors").read_bytes() == b"model"
    assert not (built.root / "manifest.sig").exists()


def test_signs_exact_manifest_with_ed25519(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.gguf").write_bytes(b"model")
    key_path, private = _signing_key(tmp_path / "bastion-signing.pem")

    built = build_model_bundle(
        source,
        tmp_path / "out",
        model_id="bio-model",
        version="1.2.3",
        signing_key=key_path,
    )

    envelope = json.loads((built.root / "manifest.sig").read_text(encoding="utf-8"))
    assert envelope["algorithm"] == "ed25519"
    assert envelope["key_id"] == built.signing_key_id
    private.public_key().verify(
        base64.b64decode(envelope["signature"]),
        (built.root / "manifest.json").read_bytes(),
    )


def test_rejects_non_ed25519_signing_key(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.gguf").write_bytes(b"model")
    bad_key = tmp_path / "bad.pem"
    bad_key.write_text("not a private key", encoding="utf-8")

    with pytest.raises(BundleBuildError, match="unreadable or invalid"):
        build_model_bundle(
            source,
            tmp_path / "out",
            model_id="m",
            version="1",
            signing_key=bad_key,
        )


def test_rejects_executable_and_pickle_model_inputs(tmp_path: Path) -> None:
    for filename in ("loader.py", "weights.pkl", "weights.pt", "setup.sh"):
        source = tmp_path / filename.replace(".", "-")
        source.mkdir()
        (source / filename).write_bytes(b"unsafe")
        with pytest.raises(BundleBuildError, match="unsupported or executable"):
            build_model_bundle(source, tmp_path / "out", model_id="m", version="1")


def test_requires_data_only_model_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text("{}", encoding="utf-8")

    with pytest.raises(BundleBuildError, match="no supported model artifact"):
        build_model_bundle(source, tmp_path / "out", model_id="m", version="1")


def test_rejects_source_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "model.gguf"
    target.write_bytes(b"model")
    link = source / "model.gguf"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(BundleBuildError, match="symlinks"):
        build_model_bundle(source, tmp_path / "out", model_id="m", version="1")


def test_enforces_bundle_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.gguf").write_bytes(b"0123456789")

    with pytest.raises(BundleBuildError, match="maximum total size"):
        build_model_bundle(
            source,
            tmp_path / "out",
            model_id="m",
            version="1",
            max_total_bytes=9,
        )
