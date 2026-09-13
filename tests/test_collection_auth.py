from __future__ import annotations

import pytest

from fieldora_bastion.collection_auth import AuthenticatedCollector, authorize_collection
from fieldora_bastion.secure_catalogue import SecureCatalogue
from fieldora_bastion.transfer_broker import BroadcastDescriptor, BrokerError


def _descriptor() -> BroadcastDescriptor:
    return BroadcastDescriptor(
        broadcast_id="broadcast:req-001:aaaaaaaaaaaaaaaa",
        package_id="pkg-001",
        package_class="software-update",
        artifact_id="fieldora",
        version="1.0.1",
        sha256="a" * 64,
        total_bytes=2048,
        provenance="release:fieldora:1.0.1",
        signing_key_id="release-key-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
        audience=("fieldora-prod",),
    )


def test_unverified_principal_is_rejected() -> None:
    with pytest.raises(BrokerError, match="externally verified"):
        AuthenticatedCollector(
            collector_id="fieldora-prod",
            issuer="https://identity.internal",
            subject="workload:fieldora-prod",
            authentication_method="oidc",
            verified=False,
        )


def test_authenticated_authorized_collector_gets_descriptor() -> None:
    catalogue = SecureCatalogue()
    catalogue.publish(_descriptor())
    principal = AuthenticatedCollector(
        collector_id="fieldora-prod",
        issuer="https://identity.internal",
        subject="workload:fieldora-prod",
        authentication_method="oidc",
        verified=True,
    )
    descriptor = authorize_collection(catalogue, "pkg-001", principal)
    assert descriptor.package_id == "pkg-001"


def test_authenticated_but_wrong_audience_is_rejected() -> None:
    catalogue = SecureCatalogue()
    catalogue.publish(_descriptor())
    principal = AuthenticatedCollector(
        collector_id="other-product",
        issuer="https://identity.internal",
        subject="workload:other-product",
        authentication_method="oidc",
        verified=True,
    )
    with pytest.raises(BrokerError, match="descriptor audience"):
        authorize_collection(catalogue, "pkg-001", principal)
