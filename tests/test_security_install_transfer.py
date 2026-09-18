from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fieldora_bastion.model_bundle import build_model_bundle
from fieldora_bastion.security_install_transfer import build_security_install_transfer


def test_standalone_export_contains_sender_facts_not_receiver_attestations(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.safetensors").write_bytes(b"safe-model")
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "signing.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    built = build_model_bundle(
        source,
        tmp_path / "bundles",
        model_id="bird-model",
        version="1.0.0",
        signing_key=key_path,
    )

    artifact, evidence_path = build_security_install_transfer(
        built.root, tmp_path / "transfer", collector_id="offline-media"
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert artifact.is_file()
    assert evidence["release_id"] == "fieldora-model:bird-model:1.0.0"
    assert evidence["secure_transfer"]["provider_id"] == "fieldora-bastion"
    assert evidence["provenance"]["signature_verified"] is False
    assert "transfer_receipt" not in evidence
    assert "independent_verification" not in evidence
    serialized = json.dumps(evidence)
    assert "postgres" not in serialized.lower()
    assert "fieldora-access-dsn" not in serialized
