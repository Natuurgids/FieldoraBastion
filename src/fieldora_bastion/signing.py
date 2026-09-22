"""Signing abstraction for Bastion trust-boundary operations."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SigningError(ValueError):
    """Raised when a Bastion signer cannot produce a valid Ed25519 signature."""


@dataclass(frozen=True, slots=True)
class Signature:
    key_id: str
    signature: str


class Signer(Protocol):
    """Non-exporting signing contract implemented by local or external handlers."""

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> Signature: ...


class PemFileSigner:
    """Development/test signer. Production deployment rejects file-based private keys."""

    def __init__(self, path: Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise SigningError("signing key must be a regular non-symlink file")
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except (OSError, TypeError, ValueError) as exc:
            raise SigningError("signing key is unreadable or invalid") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningError("signing key must be an Ed25519 private key")
        self._key = key
        public_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = hashlib.sha256(public_der).hexdigest()[:32]

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> Signature:
        return Signature(
            key_id=self._key_id,
            signature=base64.b64encode(self._key.sign(payload)).decode("ascii"),
        )
