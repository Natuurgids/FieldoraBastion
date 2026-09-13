from __future__ import annotations

import pytest

from fieldora_bastion.secure_catalogue import SecureCatalogue
from fieldora_bastion.transfer_broker import BroadcastDescriptor, BrokerError


def _descriptor(*, audience: tuple[str, ...] = ("fieldora-prod",)) -> BroadcastDescriptor:
    return BroadcastDescriptor(
        broadcast_id="broadcast:req-001:aaaaaaaaaaaaaaaa",
        package_id="pkg-001",
        package_class="integration-adapter",
        artifact_id="example-siem",
        version="1.2.3",
        sha256="a" * 64,
        total_bytes=2048,
        provenance="spec:sha256:" + "b" * 64,
        signing_key_id="bastion-release-1",
        manifest_signature="ed25519",
        malware_scan_result="clean",
        audience=audience,
    )


def test_catalogue_stores_descriptor_not_package_bytes() -> None:
    catalogue = SecureCatalogue()
    catalogue.publish(_descriptor())
    descriptor = catalogue.get_for_collector("pkg-001", "fieldora-prod")
    assert descriptor.package_id == "pkg-001"
    assert not hasattr(descriptor, "package_bytes")
    assert catalogue.count() == 1


def test_catalogue_rejects_unauthorized_collector() -> None:
    catalogue = SecureCatalogue()
    catalogue.publish(_descriptor(audience=("fieldora-prod",)))
    with pytest.raises(BrokerError, match="descriptor audience"):
        catalogue.get_for_collector("pkg-001", "other-product")


def test_package_id_cannot_be_republished_with_changed_descriptor() -> None:
    catalogue = SecureCatalogue()
    catalogue.publish(_descriptor())
    changed = BroadcastDescriptor(
        **{**_descriptor().__dict__, "sha256": "c" * 64}
    )
    with pytest.raises(BrokerError, match="different descriptor"):
        catalogue.publish(changed)
