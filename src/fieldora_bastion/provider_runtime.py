"""Single certified runtime facade for FieldoraBastion provider operations.

The facade combines bounded scan/build jobs with secure-transfer state operations
and the atomic local metadata store. It is not a network daemon and does not own
protected-product business authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fieldora_bastion.atomic_transfer_store import AtomicTransferStore
from fieldora_bastion.model_bundle import BuiltModelBundle, build_model_bundle
from fieldora_bastion.release_binding import ReleaseBindingStore
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


@dataclass(frozen=True, slots=True)
class ReleaseBoundDescriptor:
    """Published descriptor bound to a pre-transfer certified release manifest."""

    descriptor: BroadcastDescriptor
    release_digest: str

    def __getattr__(self, name: str):
        return getattr(self.descriptor, name)


@dataclass(frozen=True, slots=True)
class ReleaseBoundReceipt:
    """Collector receipt bound to the same release digest authorized before transfer."""

    receipt: CollectionReceipt
    release_digest: str

    def __getattr__(self, name: str):
        return getattr(self.receipt, name)


class FieldoraBastionProvider(TransferBroker):
    """Provider facade consumed by Security Install or another orchestrator."""

    provider_id = "fieldora-bastion"
    capability = "secure-transfer"
    execution_kind = "job"
    protocol_version = 1

    def __init__(self, state_db: str | Path) -> None:
        super().__init__()
        self.store = AtomicTransferStore(state_db)
        self.release_bindings = ReleaseBindingStore(state_db)
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

    def authorize_release(self, request_id: str, release_digest: str) -> str:
        """Bind a Security Install-certified release digest before broadcast.

        Bastion does not decide whether the release manifest satisfies business or
        commercial policy. It only requires an immutable validated digest before
        making the package collectable.
        """
        record = self._record(request_id)
        if record.state is not TransferState.APPROVED or record.package is None:
            raise BrokerError("release authorization requires an approved package")
        self.release_bindings.authorize(request_id, release_digest)
        return release_digest

    def authorized_release_digest(self, request_id: str) -> str | None:
        return self.release_bindings.get(request_id)

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

    def broadcast(self, request_id: str) -> ReleaseBoundDescriptor:
        release_digest = self.release_bindings.get(request_id)
        if release_digest is None:
            raise BrokerError("approved package has no authorized release digest")
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
        return ReleaseBoundDescriptor(descriptor=descriptor, release_digest=release_digest)

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
    ) -> ReleaseBoundReceipt:
        release_digest = self.release_bindings.get(request_id)
        if release_digest is None:
            raise BrokerError("transfer has no authorized release digest")
        record = self._record(request_id)
        previous_state = record.state
        receipt = super().confirm_collection(request_id, collector_id, observed_sha256)
        try:
            self.store.finalize_collection_atomic(request_id, collector_id, receipt)
        except BaseException:
            record.state = previous_state
            raise
        return ReleaseBoundReceipt(receipt=receipt, release_digest=release_digest)

    def descriptor_for_collector(
        self, package_id: str, collector_id: str
    ) -> ReleaseBoundDescriptor:
        descriptor = self.store.descriptor(package_id)
        if descriptor is None:
            raise BrokerError("package is not published")
        if collector_id not in descriptor.audience and "*" not in descriptor.audience:
            raise BrokerError("collector is not in the descriptor audience")
        request_id = self._request_id_for_package(package_id)
        release_digest = self.release_bindings.get(request_id)
        if release_digest is None:
            raise BrokerError("published package has no authorized release digest")
        return ReleaseBoundDescriptor(descriptor=descriptor, release_digest=release_digest)

    def receipt(self, package_id: str, collector_id: str) -> ReleaseBoundReceipt | None:
        receipt = self.store.receipt(package_id, collector_id)
        if receipt is None:
            return None
        request_id = self._request_id_for_package(package_id)
        release_digest = self.release_bindings.get(request_id)
        if release_digest is None:
            raise BrokerError("receipt has no authorized release digest")
        return ReleaseBoundReceipt(receipt=receipt, release_digest=release_digest)

    def _request_id_for_package(self, package_id: str) -> str:
        for request_id, record in self._records.items():
            if record.package is not None and record.package.package_id == package_id:
                return request_id
        raise BrokerError("unknown package_id")

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
