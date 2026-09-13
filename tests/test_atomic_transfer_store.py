from __future__ import annotations

import pytest

from fieldora_bastion.atomic_transfer_store import AtomicTransferStore
from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BroadcastDescriptor,
    BrokerError,
    CollectionReceipt,
    RequestKind,
    TransferRequest,
    TransferState,
)


def _request() -> TransferRequest:
    return TransferRequest(
        request_id="req-001",
        kind=RequestKind.DELIVERY,
        package_class="integration-adapter",
        artifact_id="siem-adapter",
        version="1.2.3",
        source="signed-release",
        requested_by="security-install",
        audience=("fieldora-prod",),
    )


def _package() -> ApprovedPackage:
    return ApprovedPackage(
        package_id="pkg-001",
        request_id="req-001",
        package_class="integration-adapter",
        artifact_id="siem-adapter",
        version="1.2.3",
        sha256="a" * 64,
        total_bytes=2048,
        provenance="spec:sha256:" + "b" * 64,
        signing_key_id="bastion-release-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
    )


def _descriptor() -> BroadcastDescriptor:
    return BroadcastDescriptor(
        broadcast_id="broadcast:req-001:aaaaaaaaaaaaaaaa",
        package_id="pkg-001",
        package_class="integration-adapter",
        artifact_id="siem-adapter",
        version="1.2.3",
        sha256="a" * 64,
        total_bytes=2048,
        provenance="spec:sha256:" + "b" * 64,
        signing_key_id="bastion-release-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
        audience=("fieldora-prod",),
    )


def test_publish_commits_transfer_and_descriptor_together(tmp_path) -> None:
    store = AtomicTransferStore(tmp_path / "transfer.db")
    store.publish_descriptor_atomic(_request(), _package(), _descriptor())
    assert store.state("req-001") is TransferState.BROADCAST
    assert store.descriptor("pkg-001") == _descriptor()


def test_finalize_commits_terminal_state_and_receipt_together(tmp_path) -> None:
    store = AtomicTransferStore(tmp_path / "transfer.db")
    store.save_transfer(
        _request(),
        TransferState.COLLECTOR_VERIFYING,
        claimed_by="fieldora-prod",
        package=_package(),
    )
    receipt = CollectionReceipt(
        package_id="pkg-001",
        collector_id="fieldora-prod",
        expected_sha256="a" * 64,
        observed_sha256="a" * 64,
        status="accepted",
    )
    store.finalize_collection_atomic("req-001", "fieldora-prod", receipt)
    assert store.state("req-001") is TransferState.ACCEPTED
    assert store.receipt("pkg-001", "fieldora-prod") == receipt


def test_conflicting_receipt_rolls_back_state_change(tmp_path) -> None:
    store = AtomicTransferStore(tmp_path / "transfer.db")
    store.save_transfer(
        _request(),
        TransferState.COLLECTOR_VERIFYING,
        claimed_by="fieldora-prod",
        package=_package(),
    )
    receipt = CollectionReceipt(
        "pkg-001", "fieldora-prod", "a" * 64, "a" * 64, "accepted"
    )
    store.finalize_collection_atomic("req-001", "fieldora-prod", receipt)
    store.save_transfer(
        _request(),
        TransferState.COLLECTOR_VERIFYING,
        claimed_by="fieldora-prod",
        package=_package(),
    )
    conflicting = CollectionReceipt(
        "pkg-001", "fieldora-prod", "a" * 64, "c" * 64, "integrity-failed"
    )
    with pytest.raises(BrokerError, match="different evidence"):
        store.finalize_collection_atomic("req-001", "fieldora-prod", conflicting)
    assert store.state("req-001") is TransferState.COLLECTOR_VERIFYING
    assert store.receipt("pkg-001", "fieldora-prod") == receipt


def test_store_schema_has_no_package_bytes_or_secrets(tmp_path) -> None:
    store = AtomicTransferStore(tmp_path / "transfer.db")
    with store._connect() as connection:
        sql = " ".join(
            row[0]
            for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL"
            )
        ).lower()
    for forbidden in ("package_bytes", "bearer_token", "credential", "private_key"):
        assert forbidden not in sql
