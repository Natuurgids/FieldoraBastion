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


def _claimed_transfer() -> TransferBroker:
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
    return broker


def test_collection_request_reaches_verified_acceptance() -> None:
    broker = _claimed_transfer()
    assert broker.mark_transferred("req-001", "science-importer") is TransferState.TRANSFERRED
    assert (
        broker.begin_collector_verification("req-001", "science-importer")
        is TransferState.COLLECTOR_VERIFYING
    )
    receipt = broker.confirm_collection("req-001", "science-importer", DIGEST)
    assert receipt.status == "accepted"
    assert receipt.expected_sha256 == DIGEST
    assert receipt.observed_sha256 == DIGEST
    assert broker.state("req-001") is TransferState.ACCEPTED


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


def test_digest_mismatch_is_terminal_integrity_failure_and_alert() -> None:
    broker = _claimed_transfer()
    broker.mark_transferred("req-001", "science-importer")
    broker.begin_collector_verification("req-001", "science-importer")
    observed = "b" * 64
    receipt = broker.confirm_collection("req-001", "science-importer", observed)

    assert receipt.status == "integrity-failed"
    assert receipt.expected_sha256 == DIGEST
    assert receipt.observed_sha256 == observed
    assert broker.state("req-001") is TransferState.INTEGRITY_FAILED

    alert = broker.integrity_alert("req-001", "science-importer", observed)
    assert alert.event_type == "package_integrity_mismatch"
    assert alert.severity == "high"
    assert alert.expected_sha256 == DIGEST
    assert alert.observed_sha256 == observed
    assert alert.signing_key_id == "bastion-key-1"

    with pytest.raises(BrokerError, match="terminal request"):
        broker.advance("req-001", TransferState.ACCEPTED)
