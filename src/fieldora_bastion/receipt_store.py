"""Durable SQLite-backed collection receipt storage.

The store persists bounded receipt metadata only. It never stores package bytes,
identity tokens, credentials, or signing keys.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3

from fieldora_bastion.transfer_broker import BrokerError, CollectionReceipt


class ReceiptStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS collection_receipts (
                    package_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    observed_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    PRIMARY KEY (package_id, collector_id)
                )
                """
            )

    def record(self, receipt: CollectionReceipt) -> None:
        if receipt.status not in {"accepted", "integrity-failed"}:
            raise BrokerError("unsupported collection receipt status")
        existing = self.get(receipt.package_id, receipt.collector_id)
        if existing is not None:
            if existing == receipt:
                return
            raise BrokerError("collection receipt already exists with different evidence")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO collection_receipts
                (package_id, collector_id, expected_sha256, observed_sha256, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    receipt.package_id,
                    receipt.collector_id,
                    receipt.expected_sha256,
                    receipt.observed_sha256,
                    receipt.status,
                ),
            )

    def get(self, package_id: str, collector_id: str) -> CollectionReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT package_id, collector_id, expected_sha256, observed_sha256, status
                FROM collection_receipts
                WHERE package_id = ? AND collector_id = ?
                """,
                (package_id, collector_id),
            ).fetchone()
        if row is None:
            return None
        return CollectionReceipt(
            package_id=row["package_id"],
            collector_id=row["collector_id"],
            expected_sha256=row["expected_sha256"],
            observed_sha256=row["observed_sha256"],
            status=row["status"],
        )

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM collection_receipts").fetchone()
        return int(row["n"])
