from __future__ import annotations

import pytest

from fieldora_bastion.cli import _external_signer, _parser


def _args(*argv: str):
    return _parser().parse_args(list(argv))


def test_model_external_signer_requires_complete_pair() -> None:
    args = _args("build-model-bundle", "source", "out", "--model-id", "m", "--version", "1", "--signer-socket", "/run/bastion/signer.sock")
    with pytest.raises(ValueError, match="provided together"):
        _external_signer(args)


def test_external_signer_rejects_pem_and_socket_together() -> None:
    args = _args("build-model-bundle", "source", "out", "--model-id", "m", "--version", "1", "--signing-key", "key.pem", "--signer-socket", "/run/bastion/signer.sock", "--signer-key-id", "a" * 32)
    with pytest.raises(ValueError, match="cannot be combined"):
        _external_signer(args)


def test_dataset_external_signer_identity_is_separate() -> None:
    args = _args("certify-map-dataset", "source", "out", "--dataset-id", "d", "--version", "1", "--signer-key-id", "b" * 32, "--signer-socket", "/run/bastion/signer.sock", "--source-id", "maps", "--license-id", "lic", "--scan-report", "scan.json")
    with pytest.raises(ValueError, match="provided together"):
        _external_signer(args, key_id_attr="external_signer_key_id")


def test_dataset_external_signer_uses_explicit_identity() -> None:
    args = _args("certify-map-dataset", "source", "out", "--dataset-id", "d", "--version", "1", "--signer-key-id", "b" * 32, "--signer-socket", "/run/bastion/signer.sock", "--external-signer-key-id", "a" * 32, "--source-id", "maps", "--license-id", "lic", "--scan-report", "scan.json")
    signer = _external_signer(args, key_id_attr="external_signer_key_id")
    assert signer is not None
    assert signer.key_id == "a" * 32
