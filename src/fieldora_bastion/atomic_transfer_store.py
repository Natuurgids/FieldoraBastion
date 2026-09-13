"""Single SQLite transaction boundary for broker, catalogue, and receipts.

The store coordinates bounded metadata only. Package bytes, bearer tokens,
credentials, signing keys, and malware databases remain outside this database.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BroadcastDescriptor,
    BrokerError,
    CollectionReceipt,
    TransferRequest,
    TransferState,
)


class AtomicTransferStore:
    """Persist secure-transfer metadata with SQLite atomic commit semantics."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfers (
                    request_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    claimed_by TEXT,
                    package_json TEXT
                );
                CREATE TABLE IF NOT EXISTS catalogue_descriptors (
                    package_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    descriptor_json TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES transfers(request_id)
                );
                CREATE TABLE IF NOT EXISTS collection_receipts (
                    package_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    PRIMARY KEY(package_id, collector_id)
                );
                """
            )

    @staticmethod
    def _request_json(request: TransferRequest) -> str:
        return json.dumps(
            {
                "request_id": request.request_id,
                "kind": request.kind.value,
                "package_class": request.package_class,
                "artifact_id": request.artifact_id,
                "version": request.version,
                "source": request.source,
                "requested_by": request.requested_by,
                "audience": request.audience,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _package_json(package: ApprovedPackage | None) -> str | None:
        if package is None:
            return None
        return json.dumps(
            {
                "package_id": package.package_id,
                "request_id": package.request_id,
                "package_class": package.package_class,
                "artifact_id": package.artifact_id,
                "version": package.version,
                "sha256": package.sha256,
                "total_bytes": package.total_bytes,
                "provenance": package.provenance,
                "signing_key_id": package.signing_key_id,
                "manifest_signature": package.manifest_signature,
                "malware_scan_result": package.malware_scan_result,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _descriptor_json(descriptor: BroadcastDescriptor) -> str:
        return json.dumps(
            {
                "broadcast_id": descriptor.broadcast_id,
                "package_id": descriptor.package_id,
                "package_class": descriptor.package_class,
                "artifact_id": descriptor.artifact_id,
                "version": descriptor.version,
                "sha256": descriptor.sha256,
                "total_bytes": descriptor.total_bytes,
                "provenance": descriptor.provenance,
                "signing_key_id": descriptor.signing_key_id,
                "manifest_signature": descriptor.manifest_signature,
                "malware_scan_result": descriptor.malware_scan_result,
                "audience": descriptor.audience,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _receipt_json(receipt: CollectionReceipt) -> str:
        return json.dumps(
            {
                "package_id": receipt.package_id,
                "collector_id": receipt.collector_id,
                "expected_sha256": receipt.expected_sha256,
                "observed_sha256": receipt.observed_sha256,
                "status": receipt.status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def save_transfer(
        self,
        request: TransferRequest,
        state: TransferState,
        *,
        claimed_by: str | None = None,
        package: ApprovedPackage | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO transfers(request_id, request_json, state, claimed_by, package_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    request_json=excluded.request_json,
                    state=excluded.state,
                    claimed_by=excluded.claimed_by,
                    package_json=excluded.package_json
                """,
                (
                    request.request_id,
                    self._request_json(request),
                    state.value,
                    claimed_by,
                    self._package_json(package),
                ),
            )

    def publish_descriptor_atomic(
        self,
        request: TransferRequest,
        package: ApprovedPackage,
        descriptor: BroadcastDescriptor,
    ) -> None:
        if descriptor.package_id != package.package_id or package.request_id != request.request_id:
            raise BrokerError("descriptor/package/request identity mismatch")
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT descriptor_json FROM catalogue_descriptors WHERE package_id = ?",
                (descriptor.package_id,),
            ).fetchone()
            encoded = self._descriptor_json(descriptor)
            if existing is not None and existing["descriptor_json"] != encoded:
                raise BrokerError("package_id already published with different descriptor")
            connection.execute(
                """
                INSERT INTO transfers(request_id, request_json, state, claimed_by, package_json)
                VALUES (?, ?, ?, NULL, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    request_json=excluded.request_json,
                    state=excluded.state,
                    claimed_by=NULL,
                    package_json=excluded.package_json
                """,
                (
                    request.request_id,
                    self._request_json(request),
                    TransferState.BROADCAST.value,
                    self._package_json(package),
                ),
            )
            connection.execute(
                """
                INSERT INTO catalogue_descriptors(package_id, request_id, descriptor_json)
                VALUES (?, ?, ?)
                ON CONFLICT(package_id) DO NOTHING
                """,
                (descriptor.package_id, request.request_id, encoded),
            )

    def finalize_collection_atomic(
        self,
        request_id: str,
        collector_id: str,
        receipt: CollectionReceipt,
    ) -> None:
        if receipt.collector_id != collector_id:
            raise BrokerError("receipt collector does not match collection")
        if receipt.status not in {"accepted", "integrity-failed"}:
            raise BrokerError("unsupported terminal collection receipt status")
        target = (
            TransferState.ACCEPTED
            if receipt.status == "accepted"
            else TransferState.INTEGRITY_FAILED
        )
        encoded = self._receipt_json(receipt)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT claimed_by, package_json FROM transfers WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise BrokerError("unknown request_id")
            if row["claimed_by"] != collector_id:
                raise BrokerError("collector does not hold this transfer")
            package_json = row["package_json"]
            if package_json is None or json.loads(package_json)["package_id"] != receipt.package_id:
                raise BrokerError("receipt package does not match transfer package")
            existing = connection.execute(
                """
                SELECT receipt_json FROM collection_receipts
                WHERE package_id = ? AND collector_id = ?
                """,
                (receipt.package_id, collector_id),
            ).fetchone()
            if existing is not None and existing["receipt_json"] != encoded:
                raise BrokerError("collection receipt already exists with different evidence")
            connection.execute(
                "UPDATE transfers SET state = ? WHERE request_id = ?",
                (target.value, request_id),
            )
            connection.execute(
                """
                INSERT INTO collection_receipts(package_id, collector_id, receipt_json)
                VALUES (?, ?, ?)
                ON CONFLICT(package_id, collector_id) DO NOTHING
                """,
                (receipt.package_id, collector_id, encoded),
            )

    def state(self, request_id: str) -> TransferState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM transfers WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise BrokerError("unknown request_id")
        return TransferState(row["state"])

    def descriptor(self, package_id: str) -> BroadcastDescriptor | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT descriptor_json FROM catalogue_descriptors WHERE package_id = ?",
                (package_id,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["descriptor_json"])
        payload["audience"] = tuple(payload["audience"])
        return BroadcastDescriptor(**payload)

    def receipt(self, package_id: str, collector_id: str) -> CollectionReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT receipt_json FROM collection_receipts
                WHERE package_id = ? AND collector_id = ?
                """,
                (package_id, collector_id),
            ).fetchone()
        if row is None:
            return None
        return CollectionReceipt(**json.loads(row["receipt_json"]))
