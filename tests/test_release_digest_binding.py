from __future__ import annotations

import pytest

from fieldora_bastion.provider_runtime import FieldoraBastionProvider
from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BrokerError,
    RequestKind,
    TransferRequest,
    TransferState,
)


def _request() -> TransferRequest:
    return TransferRequest(
        request_id="req-release-1",
        kind=RequestKind.DELIVERY,
        package_class="software-update",
        artifact_id="fieldora-desktop",
        version="2.4.0",
        source="security-install",
        requested_by="release-pipeline",
        audience=("fieldora-prod",),
    )


def _package() -> ApprovedPackage:
    return ApprovedPackage(
        package_id="pkg-release-1",
        request_id="req-release-1",
        package_class="software-update",
        artifact_id="fieldora-desktop",
        version="2.4.0",
        sha256="a" * 64,
        total_bytes=1234,
        provenance="security-install:release",
        signing_key_id="release-key-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
    )


def _approved_provider(tmp_path):
    provider = FieldoraBastionProvider(tmp_path / "bastion.db")
    provider.submit(_request())
    provider.advance("req-release-1", TransferState.RECEIVING)
    provider.advance("req-release-1", TransferState.QUARANTINED)
    provider.advance("req-release-1", TransferState.SCANNING)
    provider.advance("req-release-1", TransferState.VERIFYING)
    provider.approve("req-release-1", _package())
    return provider


def test_broadcast_requires_pretransfer_release_digest(tmp_path) -> None:
    provider = _approved_provider(tmp_path)
    with pytest.raises(BrokerError, match="no authorized release digest"):
        provider.broadcast("req-release-1")


def test_authorized_release_digest_survives_restart_and_binds_descriptor(tmp_path) -> None:
    database = tmp_path / "bastion.db"
    provider = _approved_provider(tmp_path)
    digest = "b" * 64
    provider.authorize_release("req-release-1", digest)

    restored = FieldoraBastionProvider(database)
    assert restored.authorized_release_digest("req-release-1") == digest
    descriptor = restored.broadcast("req-release-1")
    assert descriptor.release_digest == digest
    assert descriptor.package_id == "pkg-release-1"


def test_release_digest_is_immutable(tmp_path) -> None:
    provider = _approved_provider(tmp_path)
    provider.authorize_release("req-release-1", "b" * 64)
    with pytest.raises(BrokerError, match="different authorized release digest"):
        provider.authorize_release("req-release-1", "c" * 64)


def test_release_digest_must_be_sha256(tmp_path) -> None:
    provider = _approved_provider(tmp_path)
    with pytest.raises(BrokerError, match="64-character hexadecimal"):
        provider.authorize_release("req-release-1", "not-a-digest")


def test_collector_receipt_carries_same_release_digest(tmp_path) -> None:
    provider = _approved_provider(tmp_path)
    digest = "b" * 64
    provider.authorize_release("req-release-1", digest)
    provider.broadcast("req-release-1")
    provider.claim("req-release-1", "fieldora-prod")
    provider.mark_transferred("req-release-1", "fieldora-prod")
    provider.begin_collector_verification("req-release-1", "fieldora-prod")
    receipt = provider.confirm_collection("req-release-1", "fieldora-prod", "a" * 64)

    assert receipt.status == "accepted"
    assert receipt.release_digest == digest
    persisted = provider.receipt("pkg-release-1", "fieldora-prod")
    assert persisted is not None
    assert persisted.release_digest == digest


def test_integrity_failure_still_carries_release_digest(tmp_path) -> None:
    provider = _approved_provider(tmp_path)
    digest = "b" * 64
    provider.authorize_release("req-release-1", digest)
    provider.broadcast("req-release-1")
    provider.claim("req-release-1", "fieldora-prod")
    provider.mark_transferred("req-release-1", "fieldora-prod")
    provider.begin_collector_verification("req-release-1", "fieldora-prod")
    receipt = provider.confirm_collection("req-release-1", "fieldora-prod", "c" * 64)

    assert receipt.status == "integrity-failed"
    assert receipt.release_digest == digest
