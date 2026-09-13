import json

import pytest

from fieldora_bastion.security_monitoring import WazuhJsonlSink
from fieldora_bastion.transfer_broker import SecurityAlert


def _alert() -> SecurityAlert:
    return SecurityAlert(
        event_type="package_integrity_mismatch",
        severity="high",
        request_id="req-001",
        package_id="pkg-001",
        collector_id="fieldora-importer",
        expected_sha256="a" * 64,
        observed_sha256="b" * 64,
        signing_key_id="bastion-key-1",
        package_class="scientific-data",
        artifact_id="dataset-42",
        version="2026.09",
        provenance="approved-source",
    )


def test_wazuh_sink_writes_bounded_bastion_alert(tmp_path) -> None:
    log = tmp_path / "bastion-security.jsonl"
    WazuhJsonlSink(log).emit_security_alert(_alert())
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["fieldora"]["component"] == "bastion"
    assert event["fieldora"]["event_type"] == "package_integrity_mismatch"
    assert event["fieldora"]["expected_sha256"] == "a" * 64
    assert "path" not in event["fieldora"]
    assert "content" not in event["fieldora"]


def test_wazuh_sink_requires_precreated_event_directory(tmp_path) -> None:
    sink = WazuhJsonlSink(tmp_path / "missing" / "events.jsonl")
    with pytest.raises(FileNotFoundError):
        sink.emit_security_alert(_alert())
