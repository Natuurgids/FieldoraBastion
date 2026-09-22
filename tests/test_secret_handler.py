from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import fieldora_bastion.secret_handler as sh
from fieldora_bastion.signing import SigningError


class _Socket:
    response = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, _timeout):
        pass

    def connect(self, _path):
        pass

    def sendall(self, request):
        document = json.loads(request)
        assert document["operation"] == "ed25519-sign"
        assert base64.b64decode(document["payload"]) == b"payload"

    def recv(self, _size):
        response, type(self).response = type(self).response, b""
        return response


def test_unix_socket_signer_accepts_bound_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    _Socket.response = (
        json.dumps({"key_id": "key-1", "signature": base64.b64encode(b"x" * 64).decode()})
        + "\n"
    ).encode()
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    signed = sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "key-1").sign(b"payload")
    assert signed.key_id == "key-1"


def test_unix_socket_signer_rejects_wrong_key_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _Socket.response = (
        json.dumps({"key_id": "other", "signature": base64.b64encode(b"x" * 64).decode()})
        + "\n"
    ).encode()
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    with pytest.raises(SigningError, match="unexpected key id"):
        sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "key-1").sign(b"payload")
