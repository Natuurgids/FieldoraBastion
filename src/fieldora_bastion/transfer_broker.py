"""Secure transfer-broker contract for FieldoraBastion.

The broker accepts collection or delivery requests, quarantines externally sourced
bytes, and only broadcasts immutable package descriptors after scanning and
verification have succeeded. Collector verification is mandatory after transfer;
a digest mismatch is a terminal integrity failure, never a successful collection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerError(ValueError):
    """Raised when a transfer request violates the broker trust contract."""


class RequestKind(StrEnum):
    COLLECTION = "collection"
    DELIVERY = "delivery"


class TransferState(StrEnum):
    REQUESTED = "requested"
    ACQUIRING = "acquiring"
    RECEIVING = "receiving"
    QUARANTINED = "quarantined"
    SCANNING = "scanning"
    VERIFYING = "verifying"
    APPROVED = "approved"
    BROADCAST = "broadcast"
    CLAIMED = "claimed"
    TRANSFERRED = "transferred"
    COLLECTOR_VERIFYING = "collector-verifying"
    ACCEPTED = "accepted"
    INTEGRITY_FAILED = "integrity-failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    FAILED = "failed"


_TERMINAL = {
    TransferState.ACCEPTED,
    TransferState.INTEGRITY_FAILED,
    TransferState.REJECTED,
    TransferState.EXPIRED,
    TransferState.CANCELLED,
    TransferState.FAILED,
}

_ALLOWED: dict[TransferState, set[TransferState]] = {
    TransferState.REQUESTED: {
        TransferState.ACQUIRING,
        TransferState.RECEIVING,
        TransferState.CANCELLED,
        TransferState.FAILED,
    },
    TransferState.ACQUIRING: {TransferState.QUARANTINED, TransferState.FAILED},
    TransferState.RECEIVING: {TransferState.QUARANTINED, TransferState.FAILED},
    TransferState.QUARANTINED: {
        TransferState.SCANNING,
        TransferState.REJECTED,
        TransferState.FAILED,
    },
    TransferState.SCANNING: {
        TransferState.VERIFYING,
        TransferState.REJECTED,
        TransferState.FAILED,
    },
    TransferState.VERIFYING: {
        TransferState.APPROVED,
        TransferState.REJECTED,
        TransferState.FAILED,
    },
    TransferState.APPROVED: {
        TransferState.BROADCAST,
        TransferState.EXPIRED,
        TransferState.FAILED,
    },
    TransferState.BROADCAST: {
        TransferState.CLAIMED,
        TransferState.EXPIRED,
        TransferState.FAILED,
    },
    TransferState.CLAIMED: {
        TransferState.TRANSFERRED,
        TransferState.BROADCAST,
        TransferState.EXPIRED,
        TransferState.FAILED,
    },
    TransferState.TRANSFERRED: {
        TransferState.COLLECTOR_VERIFYING,
        TransferState.INTEGRITY_FAILED,
        TransferState.FAILED,
    },
    TransferState.COLLECTOR_VERIFYING: {
        TransferState.ACCEPTED,
        TransferState.INTEGRITY_FAILED,
        TransferState.FAILED,
    },
}


@dataclass(frozen=True, slots=True)
class TransferRequest:
    request_id: str
    kind: RequestKind
    package_class: str
    artifact_id: str
    version: str
    source: str
    requested_by: str
    audience: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("request_id", self.request_id),
            ("package_class", self.package_class),
            ("artifact_id", self.artifact_id),
            ("version", self.version),
            ("source", self.source),
            ("requested_by", self.requested_by),
        ):
            if not value.strip():
                raise BrokerError(f"{name} must not be blank")
        if not self.audience or any(not item.strip() for item in self.audience):
            raise BrokerError("audience must contain at least one non-blank collector identity")


@dataclass(frozen=True, slots=True)
class ApprovedPackage:
    package_id: str
    request_id: str
    package_class: str
    artifact_id: str
    version: str
    sha256: str
    total_bytes: int
    provenance: str
    signing_key_id: str
    manifest_signature: str
    malware_scan_result: str

    def __post_init__(self) -> None:
        if not _SHA256_RE.fullmatch(self.sha256):
            raise BrokerError("sha256 must be a lowercase 64-character hexadecimal digest")
        if self.total_bytes < 0:
            raise BrokerError("total_bytes must not be negative")
        if self.manifest_signature != "ed25519":
            raise BrokerError("approved packages require an Ed25519-signed manifest")
        if self.malware_scan_result != "clean":
            raise BrokerError("approved packages require a clean malware scan attestation")
        if not self.signing_key_id.strip() or not self.provenance.strip():
            raise BrokerError("approved packages require signing-key identity and provenance")


@dataclass(frozen=True, slots=True)
class BroadcastDescriptor:
    broadcast_id: str
    package_id: str
    package_class: str
    artifact_id: str
    version: str
    sha256: str
    total_bytes: int
    provenance: str
    signing_key_id: str
    manifest_signature: str
    malware_scan_result: str
    audience: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CollectionReceipt:
    package_id: str
    collector_id: str
    expected_sha256: str
    observed_sha256: str
    status: str


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    event_type: str
    severity: str
    request_id: str
    package_id: str
    collector_id: str
    expected_sha256: str
    observed_sha256: str
    signing_key_id: str
    package_class: str
    artifact_id: str
    version: str
    provenance: str


@dataclass(slots=True)
class _TransferRecord:
    request: TransferRequest
    state: TransferState = TransferState.REQUESTED
    package: ApprovedPackage | None = None
    claimed_by: str | None = None


class TransferBroker:
    """In-memory state machine defining the Bastion transfer-broker protocol."""

    def __init__(self) -> None:
        self._records: dict[str, _TransferRecord] = {}

    def submit(self, request: TransferRequest) -> TransferState:
        if request.request_id in self._records:
            raise BrokerError("request_id already exists")
        self._records[request.request_id] = _TransferRecord(request=request)
        return TransferState.REQUESTED

    def state(self, request_id: str) -> TransferState:
        return self._record(request_id).state

    def advance(self, request_id: str, new_state: TransferState) -> TransferState:
        record = self._record(request_id)
        if record.state in _TERMINAL:
            raise BrokerError(f"terminal request cannot transition from {record.state}")
        allowed = _ALLOWED.get(record.state, set())
        if new_state not in allowed:
            raise BrokerError(f"invalid transition: {record.state} -> {new_state}")
        if record.state is TransferState.REQUESTED:
            required = (
                TransferState.ACQUIRING
                if record.request.kind is RequestKind.COLLECTION
                else TransferState.RECEIVING
            )
            if new_state not in {required, TransferState.CANCELLED, TransferState.FAILED}:
                raise BrokerError(f"{record.request.kind} requests must start with {required}")
        record.state = new_state
        if new_state is TransferState.BROADCAST:
            record.claimed_by = None
        return record.state

    def approve(self, request_id: str, package: ApprovedPackage) -> TransferState:
        record = self._record(request_id)
        if record.state is not TransferState.VERIFYING:
            raise BrokerError("approval is only allowed from verifying state")
        if package.request_id != request_id:
            raise BrokerError("approved package request_id does not match request")
        request = record.request
        if (
            package.package_class != request.package_class
            or package.artifact_id != request.artifact_id
            or package.version != request.version
        ):
            raise BrokerError("approved package identity does not match the request")
        record.package = package
        record.state = TransferState.APPROVED
        return record.state

    def broadcast(self, request_id: str) -> BroadcastDescriptor:
        record = self._record(request_id)
        if record.state is not TransferState.APPROVED or record.package is None:
            raise BrokerError("only an approved package can be broadcast")
        record.state = TransferState.BROADCAST
        package = record.package
        return BroadcastDescriptor(
            broadcast_id=f"broadcast:{request_id}:{package.sha256[:16]}",
            package_id=package.package_id,
            package_class=package.package_class,
            artifact_id=package.artifact_id,
            version=package.version,
            sha256=package.sha256,
            total_bytes=package.total_bytes,
            provenance=package.provenance,
            signing_key_id=package.signing_key_id,
            manifest_signature=package.manifest_signature,
            malware_scan_result=package.malware_scan_result,
            audience=record.request.audience,
        )

    def claim(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        if record.state is not TransferState.BROADCAST:
            raise BrokerError("package is not available for collection")
        if collector_id not in record.request.audience and "*" not in record.request.audience:
            raise BrokerError("collector is not in the broadcast audience")
        record.claimed_by = collector_id
        record.state = TransferState.CLAIMED
        return record.state

    def release_claim(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        if record.state is not TransferState.CLAIMED or record.claimed_by != collector_id:
            raise BrokerError("collector does not hold this claim")
        record.claimed_by = None
        record.state = TransferState.BROADCAST
        return record.state

    def mark_transferred(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        if record.state is not TransferState.CLAIMED or record.claimed_by != collector_id:
            raise BrokerError("collector must hold the package claim")
        record.state = TransferState.TRANSFERRED
        return record.state

    def begin_collector_verification(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        if record.state is not TransferState.TRANSFERRED or record.claimed_by != collector_id:
            raise BrokerError("collector must verify the transferred package it claimed")
        record.state = TransferState.COLLECTOR_VERIFYING
        return record.state

    def confirm_collection(
        self, request_id: str, collector_id: str, observed_sha256: str
    ) -> CollectionReceipt:
        record = self._record(request_id)
        package = record.package
        if record.state is not TransferState.COLLECTOR_VERIFYING or record.claimed_by != collector_id:
            raise BrokerError("collector verification must be in progress")
        if package is None:
            raise BrokerError("approved package is missing")
        if observed_sha256 != package.sha256:
            record.state = TransferState.INTEGRITY_FAILED
            return CollectionReceipt(
                package.package_id,
                collector_id,
                package.sha256,
                observed_sha256,
                "integrity-failed",
            )
        record.state = TransferState.ACCEPTED
        return CollectionReceipt(
            package.package_id,
            collector_id,
            package.sha256,
            observed_sha256,
            "accepted",
        )

    def integrity_alert(
        self, request_id: str, collector_id: str, observed_sha256: str
    ) -> SecurityAlert:
        record = self._record(request_id)
        package = record.package
        if record.state is not TransferState.INTEGRITY_FAILED or package is None:
            raise BrokerError("integrity alert requires an integrity-failed transfer")
        if record.claimed_by != collector_id:
            raise BrokerError("collector identity does not match the failed transfer")
        if observed_sha256 == package.sha256:
            raise BrokerError("integrity alert requires a digest discrepancy")
        return SecurityAlert(
            event_type="package_integrity_mismatch",
            severity="high",
            request_id=request_id,
            package_id=package.package_id,
            collector_id=collector_id,
            expected_sha256=package.sha256,
            observed_sha256=observed_sha256,
            signing_key_id=package.signing_key_id,
            package_class=package.package_class,
            artifact_id=package.artifact_id,
            version=package.version,
            provenance=package.provenance,
        )

    def _record(self, request_id: str) -> _TransferRecord:
        try:
            return self._records[request_id]
        except KeyError as exc:
            raise BrokerError("unknown request_id") from exc
