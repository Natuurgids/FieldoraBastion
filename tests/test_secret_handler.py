from __future__ import annotations

import base64
import json
import stat
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


def _socket_stat():
    class _Stat:
        st_mode = stat.S_IFSOCK | 0o660

    return _Stat()


def test_unix_socket_signer_accepts_bound_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: _socket_stat())
    _Socket.response = (
        json.dumps({"key_id": "a" * 32, "signature": base64.b64encode(b"x" * 64).decode()})
        + "\n"
    ).encode()
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    signed = sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "a" * 32).sign(b"payload")
    assert signed.key_id == "a" * 32


def test_unix_socket_signer_rejects_wrong_key_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: _socket_stat())
    _Socket.response = (
        json.dumps({"key_id": "b" * 32, "signature": base64.b64encode(b"x" * 64).decode()})
        + "\n"
    ).encode()
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    with pytest.raises(SigningError, match="unexpected key id"):
        sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "a" * 32).sign(b"payload")


def test_unix_socket_signer_rejects_non_socket_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Stat:
        st_mode = stat.S_IFREG | 0o600

    monkeypatch.setattr(Path, "lstat", lambda _path: _Stat())
    signer = sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "a" * 32)
    with pytest.raises(SigningError, match="Unix-domain socket"):
        signer.sign(b"payload")


def test_unix_socket_signer_rejects_noncanonical_key_id() -> None:
    with pytest.raises(SigningError, match="32 lowercase hexadecimal"):
        sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "key-1")


def test_unix_socket_signer_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: _socket_stat())
    _Socket.response = b"x" * (sh._MAX_RESPONSE_BYTES + 1)
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    with pytest.raises(SigningError, match="size limit"):
        sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "a" * 32).sign(b"payload")


@pytest.mark.parametrize("response", [b"not-json\n", b"{}\n", b'{"key_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"!"}\n'])
def test_unix_socket_signer_rejects_malformed_response(
    monkeypatch: pytest.MonkeyPatch, response: bytes
) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: _socket_stat())
    _Socket.response = response
    monkeypatch.setattr(sh.socket, "socket", lambda *_args: _Socket())
    with pytest.raises(SigningError, match="invalid response"):
        sh.UnixSocketSigner(Path("/run/bastion/signer.sock"), "a" * 32).sign(b"payload")
