from __future__ import annotations

from pathlib import Path

import pytest

import fieldora_bastion.provider_runtime as runtime_module
from fieldora_bastion.provider_runtime import FieldoraBastionProvider
from fieldora_bastion.transfer_broker import (
    ApprovedPackage,
    BrokerError,
    RequestKind,
    TransferRequest,
    TransferState,
)


def _request() -> TransferRequest:
    return TransferRequest(
        request_id="req-001",
        kind=RequestKind.DELIVERY,
        package_class="integration-adapter",
        artifact_id="example-siem",
        version="1.2.3",
        source="builder://candidate-1",
        requested_by="security-install",
        audience=("fieldora-prod",),
    )


def _package() -> ApprovedPackage:
    return ApprovedPackage(
        package_id="pkg-001",
        request_id="req-001",
        package_class="integration-adapter",
        artifact_id="example-siem",
        version="1.2.3",
        sha256="a" * 64,
        total_bytes=2048,
        provenance="spec:sha256:" + "b" * 64,
        signing_key_id="release-key-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
    )


def _publish(provider: FieldoraBastionProvider) -> None:
    provider.submit(_request())
    provider.advance("req-001", TransferState.RECEIVING)
    provider.advance("req-001", TransferState.QUARANTINED)
    provider.advance("req-001", TransferState.SCANNING)
    provider.advance("req-001", TransferState.VERIFYING)
    provider.approve("req-001", _package())
    provider.broadcast("req-001")


def test_runtime_declares_job_secure_transfer_provider(tmp_path: Path) -> None:
    provider = FieldoraBastionProvider(tmp_path / "state.db")
    assert provider.provider_id == "fieldora-bastion"
    assert provider.capability == "secure-transfer"
    assert provider.execution_kind == "job"
    assert provider.protocol_version == 1


def test_runtime_restores_published_transfer_and_descriptor(tmp_path: Path) -> None:
    state_db = tmp_path / "state.db"
    provider = FieldoraBastionProvider(state_db)
    _publish(provider)

    restored = FieldoraBastionProvider(state_db)
    assert restored.state("req-001") is TransferState.BROADCAST
    descriptor = restored.descriptor_for_collector("pkg-001", "fieldora-prod")
    assert descriptor.sha256 == "a" * 64


def test_runtime_persists_terminal_receipt_across_restart(tmp_path: Path) -> None:
    state_db = tmp_path / "state.db"
    provider = FieldoraBastionProvider(state_db)
    _publish(provider)
    provider.claim("req-001", "fieldora-prod")
    provider.mark_transferred("req-001", "fieldora-prod")
    provider.begin_collector_verification("req-001", "fieldora-prod")
    receipt = provider.confirm_collection("req-001", "fieldora-prod", "a" * 64)
    assert receipt.status == "accepted"

    restored = FieldoraBastionProvider(state_db)
    assert restored.state("req-001") is TransferState.ACCEPTED
    assert restored.receipt("pkg-001", "fieldora-prod") == receipt


def test_runtime_enforces_catalogue_audience(tmp_path: Path) -> None:
    provider = FieldoraBastionProvider(tmp_path / "state.db")
    _publish(provider)
    with pytest.raises(BrokerError, match="descriptor audience"):
        provider.descriptor_for_collector("pkg-001", "other-product")


def test_scan_job_delegates_to_bounded_scanner(monkeypatch, tmp_path: Path) -> None:
    calls = {}

    def fake_scan(source_root, report_path, *, database_dir, max_total_bytes):
        calls.update(
            source_root=source_root,
            report_path=report_path,
            database_dir=database_dir,
            max_total_bytes=max_total_bytes,
        )
        return {"result": "clean"}

    monkeypatch.setattr(runtime_module, "scan_with_clamav", fake_scan)
    provider = FieldoraBastionProvider(tmp_path / "state.db")
    result = provider.scan_model_source(
        tmp_path / "payload",
        tmp_path / "scan.json",
        database_dir=tmp_path / "clamav",
        max_total_bytes=123,
    )
    assert result == {"result": "clean"}
    assert calls["max_total_bytes"] == 123


def test_model_build_job_requires_explicit_security_inputs(monkeypatch, tmp_path: Path) -> None:
    calls = {}

    def fake_build(source_root, output_root, **kwargs):
        calls.update(source_root=source_root, output_root=output_root, **kwargs)
        return "built"

    monkeypatch.setattr(runtime_module, "build_model_bundle", fake_build)
    provider = FieldoraBastionProvider(tmp_path / "state.db")
    result = provider.build_model_bundle(
        tmp_path / "payload",
        tmp_path / "out",
        model_id="m1",
        version="1.0.0",
        signing_key=tmp_path / "key.pem",
        scan_report=tmp_path / "scan.json",
    )
    assert result == "built"
    assert calls["signing_key"] == tmp_path / "key.pem"
    assert calls["scan_report"] == tmp_path / "scan.json"
