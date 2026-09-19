"""Durable binding between a transfer request and a certified release digest.

The binding is metadata only. It does not validate Security Install policy itself;
that validation occurs before the digest is authorized by the orchestrator.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

from fieldora_bastion.transfer_broker import BrokerError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_sha256(value: object) -> str:
    """Hash canonical JSON for immutable release/evidence bindings."""
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ReleaseBindingStore:
    """Persist immutable release-digest authorization in the Bastion state DB."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS release_bindings (
                    request_id TEXT PRIMARY KEY,
                    release_digest TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def authorize(self, request_id: str, release_digest: str) -> None:
        if not request_id.strip():
            raise BrokerError("request_id must not be blank")
        if not _SHA256_RE.fullmatch(release_digest):
            raise BrokerError(
                "release_digest must be a lowercase 64-character hexadecimal digest"
            )
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT release_digest FROM release_bindings WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing["release_digest"] == release_digest:
                    return
                raise BrokerError("request already has a different authorized release digest")
            connection.execute(
                "INSERT INTO release_bindings(request_id, release_digest) VALUES (?, ?)",
                (request_id, release_digest),
            )

    def get(self, request_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT release_digest FROM release_bindings WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        return None if row is None else str(row["release_digest"])
