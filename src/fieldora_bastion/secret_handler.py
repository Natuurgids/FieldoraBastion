"""Client for a local non-exporting Bastion signing service."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path

from fieldora_bastion.signing import Signature, Signer, SigningError

_MAX_RESPONSE_BYTES = 16 * 1024


class UnixSocketSigner(Signer):
    """Request Ed25519 signatures over a root-managed Unix-domain socket."""

    def __init__(self, socket_path: Path, key_id: str, *, timeout: float = 10.0) -> None:
        if not socket_path.is_absolute():
            raise SigningError("signer socket path must be absolute")
        if not key_id or len(key_id) > 128:
            raise SigningError("signer key id is invalid")
        self._socket_path = socket_path
        self._key_id = key_id
        self._timeout = timeout

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> Signature:
        request = (
            json.dumps(
                {"operation": "ed25519-sign", "payload": base64.b64encode(payload).decode("ascii")},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self._timeout)
                client.connect(str(self._socket_path))
                client.sendall(request)
                response = bytearray()
                while not response.endswith(b"\n"):
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > _MAX_RESPONSE_BYTES:
                        raise SigningError("signer response exceeds size limit")
        except (OSError, TimeoutError) as exc:
            raise SigningError("Bastion signing service is unavailable") from exc
        try:
            document = json.loads(bytes(response))
            signature = str(document["signature"])
            returned_key_id = str(document["key_id"])
            raw = base64.b64decode(signature, validate=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SigningError("Bastion signing service returned an invalid response") from exc
        if returned_key_id != self._key_id:
            raise SigningError("Bastion signing service returned an unexpected key id")
        if len(raw) != 64:
            raise SigningError("Bastion signing service returned an invalid Ed25519 signature")
        return Signature(key_id=returned_key_id, signature=signature)
