from __future__ import annotations

import pytest

from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BrokerError,
    RequestKind,
    TransferBroker,
    TransferRequest,
    TransferState,
)

DIGEST = "a" * 64


def _request(kind: RequestKind = RequestKind.COLLECTION) -> TransferRequest:
    return TransferRequest(
        request_id="req-001",
        kind=kind,
        package_class="scientific-data",
        artifact_id="dataset-42",
        version="2026.09",
        source="approved-source",
        requested_by="fieldora",
        audience=("science-importer",),
    )


def _package() -> ApprovedPackage:
    return ApprovedPackage(
        package_id="pkg-001",
        request_id="req-001",
        package_class="scientific-data",
        artifact_id="dataset-42",
        version="2026.09",
        sha256=DIGEST,
        total_bytes=1024,
        provenance="approved-source",
        signing_key_id="bastion-key-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
    )


def test_collection_request_reaches_broadcast_and_receipt() -> None:
    broker = TransferBroker()
    assert broker.submit(_request()) is TransferState.REQUESTED
    for state in (
        TransferState.ACQUIRING,
        TransferState.QUARANTINED,
        TransferState.SCANNING,
        TransferState.VERIFYING,
    ):
        assert broker.advance("req-001", state) is state
    assert broker.approve("req-001", _package()) is TransferState.APPROVED
    notice = broker.broadcast("req-001")
    assert notice.sha256 == DIGEST
    assert notice.malware_scan_result == "clean"
    assert notice.audience == ("science-importer",)
    assert broker.claim("req-001", "science-importer") is TransferState.CLAIMED
    receipt = broker.collect("req-001", "science-importer", DIGEST)
    assert receipt.status == "collected"
    assert broker.state("req-001") is TransferState.COLLECTED


def test_delivery_request_must_start_with_receiving() -> None:
    broker = TransferBroker()
    broker.submit(_request(RequestKind.DELIVERY))
    with pytest.raises(BrokerError, match="must start"):
        broker.advance("req-001", TransferState.ACQUIRING)
    assert broker.advance("req-001", TransferState.RECEIVING) is TransferState.RECEIVING


def test_untrusted_package_cannot_be_approved() -> None:
    with pytest.raises(BrokerError, match="clean malware scan"):
        ApprovedPackage(
            package_id="pkg-001",
            request_id="req-001",
            package_class="scientific-data",
            artifact_id="dataset-42",
            version="2026.09",
            sha256=DIGEST,
            total_bytes=1024,
            provenance="approved-source",
            signing_key_id="bastion-key-1",
            manifest_signature="ed25519",
            malware_scan_result="infected",
        )


def test_unauthorized_collector_cannot_claim_broadcast() -> None:
    broker = TransferBroker()
    broker.submit(_request())
    for state in (
        TransferState.ACQUIRING,
        TransferState.QUARANTINED,
        TransferState.SCANNING,
        TransferState.VERIFYING,
    ):
        broker.advance("req-001", state)
    broker.approve("req-001", _package())
    broker.broadcast("req-001")
    with pytest.raises(BrokerError, match="broadcast audience"):
        broker.claim("req-001", "other-service")


def test_collection_receipt_requires_exact_approved_digest() -> None:
    broker = TransferBroker()
    broker.submit(_request())
    for state in (
        TransferState.ACQUIRING,
        TransferState.QUARANTINED,
        TransferState.SCANNING,
        TransferState.VERIFYING,
    ):
        broker.advance("req-001", state)
    broker.approve("req-001", _package())
    broker.broadcast("req-001")
    broker.claim("req-001", "science-importer")
    with pytest.raises(BrokerError, match="digest"):
        broker.collect("req-001", "science-importer", "b" * 64)
