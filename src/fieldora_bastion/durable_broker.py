"""SQLite-backed recovery for the FieldoraBastion transfer broker.

Only bounded broker metadata is persisted. Package bytes, bearer tokens,
credentials, signing keys, and malware databases are never stored here.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BrokerError,
    CollectionReceipt,
    RequestKind,
    TransferBroker,
    TransferRequest,
    TransferState,
    _TransferRecord,
)


class DurableTransferBroker(TransferBroker):
    """TransferBroker variant that persists bounded state after every mutation."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_store()
        self._restore()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_store(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS broker_records (
                    request_id TEXT PRIMARY KEY,
                    request_kind TEXT NOT NULL,
                    package_class TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    source TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    audience_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    claimed_by TEXT,
                    package_json TEXT
                )
                """
            )

    def _restore(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT request_id, request_kind, package_class, artifact_id, version,
                       source, requested_by, audience_json, state, claimed_by, package_json
                FROM broker_records
                ORDER BY request_id
                """
            ).fetchall()

        for row in rows:
            request = TransferRequest(
                request_id=row["request_id"],
                kind=RequestKind(row["request_kind"]),
                package_class=row["package_class"],
                artifact_id=row["artifact_id"],
                version=row["version"],
                source=row["source"],
                requested_by=row["requested_by"],
                audience=tuple(json.loads(row["audience_json"])),
            )
            package = None
            if row["package_json"]:
                package = ApprovedPackage(**json.loads(row["package_json"]))
            self._records[request.request_id] = _TransferRecord(
                request=request,
                state=TransferState(row["state"]),
                package=package,
                claimed_by=row["claimed_by"],
            )

    def _persist(self, request_id: str) -> None:
        record = self._record(request_id)
        package_json = None
        if record.package is not None:
            package_json = json.dumps(
                {
                    "package_id": record.package.package_id,
                    "request_id": record.package.request_id,
                    "package_class": record.package.package_class,
                    "artifact_id": record.package.artifact_id,
                    "version": record.package.version,
                    "sha256": record.package.sha256,
                    "total_bytes": record.package.total_bytes,
                    "provenance": record.package.provenance,
                    "signing_key_id": record.package.signing_key_id,
                    "manifest_signature": record.package.manifest_signature,
                    "malware_scan_result": record.package.malware_scan_result,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        request = record.request
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO broker_records (
                    request_id, request_kind, package_class, artifact_id, version,
                    source, requested_by, audience_json, state, claimed_by, package_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    request_kind=excluded.request_kind,
                    package_class=excluded.package_class,
                    artifact_id=excluded.artifact_id,
                    version=excluded.version,
                    source=excluded.source,
                    requested_by=excluded.requested_by,
                    audience_json=excluded.audience_json,
                    state=excluded.state,
                    claimed_by=excluded.claimed_by,
                    package_json=excluded.package_json
                """,
                (
                    request.request_id,
                    request.kind.value,
                    request.package_class,
                    request.artifact_id,
                    request.version,
                    request.source,
                    request.requested_by,
                    json.dumps(request.audience, separators=(",", ":")),
                    record.state.value,
                    record.claimed_by,
                    package_json,
                ),
            )

    def submit(self, request: TransferRequest) -> TransferState:
        state = super().submit(request)
        self._persist(request.request_id)
        return state

    def advance(self, request_id: str, new_state: TransferState) -> TransferState:
        state = super().advance(request_id, new_state)
        self._persist(request_id)
        return state

    def approve(self, request_id: str, package: ApprovedPackage) -> TransferState:
        state = super().approve(request_id, package)
        self._persist(request_id)
        return state

    def broadcast(self, request_id: str):
        descriptor = super().broadcast(request_id)
        self._persist(request_id)
        return descriptor

    def claim(self, request_id: str, collector_id: str) -> TransferState:
        state = super().claim(request_id, collector_id)
        self._persist(request_id)
        return state

    def release_claim(self, request_id: str, collector_id: str) -> TransferState:
        state = super().release_claim(request_id, collector_id)
        self._persist(request_id)
        return state

    def mark_transferred(self, request_id: str, collector_id: str) -> TransferState:
        state = super().mark_transferred(request_id, collector_id)
        self._persist(request_id)
        return state

    def begin_collector_verification(self, request_id: str, collector_id: str) -> TransferState:
        state = super().begin_collector_verification(request_id, collector_id)
        self._persist(request_id)
        return state

    def confirm_collection(
        self, request_id: str, collector_id: str, observed_sha256: str
    ) -> CollectionReceipt:
        receipt = super().confirm_collection(request_id, collector_id, observed_sha256)
        self._persist(request_id)
        return receipt

    def persisted_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM broker_records").fetchone()
        if row is None:
            raise BrokerError("could not read durable broker state")
        return int(row["n"])
