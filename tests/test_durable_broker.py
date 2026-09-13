from __future__ import annotations

from fieldora_bastion.durable_broker import DurableTransferBroker
from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    RequestKind,
    TransferRequest,
    TransferState,
)

DIGEST = "a" * 64


def _request() -> TransferRequest:
    return TransferRequest(
        request_id="req-durable-1",
        kind=RequestKind.COLLECTION,
        package_class="integration-adapter",
        artifact_id="adapter-1",
        version="1.2.3",
        source="approved-source",
        requested_by="fieldora",
        audience=("fieldora-prod",),
    )


def _package() -> ApprovedPackage:
    return ApprovedPackage(
        package_id="pkg-durable-1",
        request_id="req-durable-1",
        package_class="integration-adapter",
        artifact_id="adapter-1",
        version="1.2.3",
        sha256=DIGEST,
        total_bytes=4096,
        provenance="spec:sha256:" + "b" * 64,
        signing_key_id="bastion-release-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
    )


def test_state_recovers_after_restart(tmp_path) -> None:
    db = tmp_path / "broker.sqlite3"
    broker = DurableTransferBroker(db)
    broker.submit(_request())
    for state in (
        TransferState.ACQUIRING,
        TransferState.QUARANTINED,
        TransferState.SCANNING,
        TransferState.VERIFYING,
    ):
        broker.advance("req-durable-1", state)
    broker.approve("req-durable-1", _package())
    broker.broadcast("req-durable-1")
    broker.claim("req-durable-1", "fieldora-prod")

    recovered = DurableTransferBroker(db)
    assert recovered.state("req-durable-1") is TransferState.CLAIMED
    assert recovered.persisted_count() == 1
    assert recovered.mark_transferred("req-durable-1", "fieldora-prod") is TransferState.TRANSFERRED


def test_terminal_integrity_failure_survives_restart(tmp_path) -> None:
    db = tmp_path / "broker.sqlite3"
    broker = DurableTransferBroker(db)
    broker.submit(_request())
    for state in (
        TransferState.ACQUIRING,
        TransferState.QUARANTINED,
        TransferState.SCANNING,
        TransferState.VERIFYING,
    ):
        broker.advance("req-durable-1", state)
    broker.approve("req-durable-1", _package())
    broker.broadcast("req-durable-1")
    broker.claim("req-durable-1", "fieldora-prod")
    broker.mark_transferred("req-durable-1", "fieldora-prod")
    broker.begin_collector_verification("req-durable-1", "fieldora-prod")
    receipt = broker.confirm_collection("req-durable-1", "fieldora-prod", "c" * 64)
    assert receipt.status == "integrity-failed"

    recovered = DurableTransferBroker(db)
    assert recovered.state("req-durable-1") is TransferState.INTEGRITY_FAILED


def test_database_contains_metadata_not_package_bytes_or_credentials(tmp_path) -> None:
    db = tmp_path / "broker.sqlite3"
    broker = DurableTransferBroker(db)
    broker.submit(_request())
    raw = db.read_bytes()
    assert b"package_bytes" not in raw
    assert b"bearer" not in raw
    assert b"private_key" not in raw
