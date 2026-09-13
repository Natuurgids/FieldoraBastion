"""Single certified runtime facade for FieldoraBastion provider operations.

The facade combines bounded scan/build jobs with secure-transfer state operations
and the atomic local metadata store. It is not a network daemon and does not own
protected-product business authorization.
"""

from __future__ import annotations

from pathlib import Path

from fieldora_bastion.atomic_transfer_store import AtomicTransferStore
from fieldora_bastion.model_bundle import BuiltModelBundle, build_model_bundle
from fieldora_bastion.scanner import scan_with_clamav
from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BroadcastDescriptor,
    BrokerError,
    CollectionReceipt,
    TransferBroker,
    TransferRequest,
    TransferState,
    _TransferRecord,
)


class FieldoraBastionProvider(TransferBroker):
    """Provider facade consumed by Security Install or another orchestrator."""

    provider_id = "fieldora-bastion"
    capability = "secure-transfer"
    execution_kind = "job"
    protocol_version = 1

    def __init__(self, state_db: str | Path) -> None:
        super().__init__()
        self.store = AtomicTransferStore(state_db)
        for snapshot in self.store.transfers():
            self._records[snapshot.request.request_id] = _TransferRecord(
                request=snapshot.request,
                state=snapshot.state,
                package=snapshot.package,
                claimed_by=snapshot.claimed_by,
            )

    def _persist_record(self, request_id: str) -> None:
        record = self._record(request_id)
        self.store.save_transfer(
            record.request,
            record.state,
            claimed_by=record.claimed_by,
            package=record.package,
        )

    def submit(self, request: TransferRequest) -> TransferState:
        state = super().submit(request)
        try:
            self._persist_record(request.request_id)
        except BaseException:
            self._records.pop(request.request_id, None)
            raise
        return state

    def advance(self, request_id: str, new_state: TransferState) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        previous_claim = record.claimed_by
        state = super().advance(request_id, new_state)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            record.claimed_by = previous_claim
            raise
        return state

    def approve(self, request_id: str, package: ApprovedPackage) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        previous_package = record.package
        state = super().approve(request_id, package)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            record.package = previous_package
            raise
        return state

    def broadcast(self, request_id: str) -> BroadcastDescriptor:
        record = self._record(request_id)
        previous_state = record.state
        previous_claim = record.claimed_by
        descriptor = super().broadcast(request_id)
        if record.package is None:
            record.state = previous_state
            record.claimed_by = previous_claim
            raise BrokerError("approved package is missing")
        try:
            self.store.publish_descriptor_atomic(record.request, record.package, descriptor)
        except BaseException:
            record.state = previous_state
            record.claimed_by = previous_claim
            raise
        return descriptor

    def claim(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        previous_claim = record.claimed_by
        state = super().claim(request_id, collector_id)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            record.claimed_by = previous_claim
            raise
        return state

    def release_claim(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        previous_claim = record.claimed_by
        state = super().release_claim(request_id, collector_id)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            record.claimed_by = previous_claim
            raise
        return state

    def mark_transferred(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        state = super().mark_transferred(request_id, collector_id)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            raise
        return state

    def begin_collector_verification(self, request_id: str, collector_id: str) -> TransferState:
        record = self._record(request_id)
        previous_state = record.state
        state = super().begin_collector_verification(request_id, collector_id)
        try:
            self._persist_record(request_id)
        except BaseException:
            record.state = previous_state
            raise
        return state

    def confirm_collection(
        self, request_id: str, collector_id: str, observed_sha256: str
    ) -> CollectionReceipt:
        record = self._record(request_id)
        previous_state = record.state
        receipt = super().confirm_collection(request_id, collector_id, observed_sha256)
        try:
            self.store.finalize_collection_atomic(request_id, collector_id, receipt)
        except BaseException:
            record.state = previous_state
            raise
        return receipt

    def descriptor_for_collector(
        self, package_id: str, collector_id: str
    ) -> BroadcastDescriptor:
        descriptor = self.store.descriptor(package_id)
        if descriptor is None:
            raise BrokerError("package is not published")
        if collector_id not in descriptor.audience and "*" not in descriptor.audience:
            raise BrokerError("collector is not in the descriptor audience")
        return descriptor

    def receipt(self, package_id: str, collector_id: str) -> CollectionReceipt | None:
        return self.store.receipt(package_id, collector_id)

    def scan_model_source(
        self,
        source_root: Path,
        report_path: Path,
        *,
        database_dir: Path,
        max_total_bytes: int = 64 * 1024 * 1024 * 1024,
    ) -> dict[str, object]:
        return scan_with_clamav(
            source_root,
            report_path,
            database_dir=database_dir,
            max_total_bytes=max_total_bytes,
        )

    def build_model_bundle(
        self,
        source_root: Path,
        output_root: Path,
        *,
        model_id: str,
        version: str,
        signing_key: Path,
        scan_report: Path,
        source: str = "fieldora-bastion",
        license_id: str = "unspecified",
        max_total_bytes: int = 64 * 1024 * 1024 * 1024,
    ) -> BuiltModelBundle:
        return build_model_bundle(
            source_root,
            output_root,
            model_id=model_id,
            version=version,
            source=source,
            license_id=license_id,
            max_total_bytes=max_total_bytes,
            signing_key=signing_key,
            scan_report=scan_report,
        )
