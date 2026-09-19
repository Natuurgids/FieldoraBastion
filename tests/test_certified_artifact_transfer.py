from __future__ import annotations

import json
from pathlib import Path

import pytest

from fieldora_bastion.certified_artifact_transfer import (
    CertifiedArtifactError,
    build_certified_artifact_transfer,
)


@pytest.mark.parametrize("artifact_type", ["ai_model", "map_dataset", "biodiversity_dataset"])
def test_certified_artifact_types_are_standalone(tmp_path: Path, artifact_type: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.dat").write_bytes(b"fieldora-test-payload")
    out = tmp_path / "out"
    package, evidence_path = build_certified_artifact_transfer(
        source,
        out,
        artifact_type=artifact_type,
        artifact_id="example",
        version="2026.09",
        signer_key_id="bastion-key-1",
        provenance={"source_id": "upstream-example", "retrieved_at": "2026-09-19T00:00:00Z"},
        validation={"approved": True, "validator": f"{artifact_type}-validator"},
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert package.is_file()
    assert evidence["artifact_type"] == artifact_type
    assert evidence["source_provenance"]["source_id"] == "upstream-example"
    serialized = json.dumps(evidence).lower()
    for forbidden in ("postgres", "fieldora-access-dsn", "transfer_receipt", "independent_verification"):
        assert forbidden not in serialized


def test_rejects_unvalidated_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.dat").write_bytes(b"x")
    with pytest.raises(CertifiedArtifactError, match="validation"):
        build_certified_artifact_transfer(
            source,
            tmp_path / "out",
            artifact_type="map_dataset",
            artifact_id="map",
            version="1",
            signer_key_id="key",
            provenance={"source_id": "source"},
            validation={"approved": False},
        )


def test_rejects_payload_not_matching_scan_binding(tmp_path: Path) -> None:
    source = tmp_path / "source-bound"
    source.mkdir()
    (source / "payload.dat").write_bytes(b"changed")
    with pytest.raises(CertifiedArtifactError, match="changed after malware scan"):
        build_certified_artifact_transfer(
            source,
            tmp_path / "out-bound",
            artifact_type="map_dataset",
            artifact_id="map",
            version="1",
            signer_key_id="key",
            provenance={"source_id": "source"},
            validation={"approved": True},
            expected_payload_sha256="0" * 64,
            expected_file_count=1,
        )
