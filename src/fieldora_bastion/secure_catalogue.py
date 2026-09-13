"""Bounded descriptor catalogue for approved FieldoraBastion packages.

The catalogue contains metadata only. Package bytes remain in quarantine/artifact
storage and are transferred through a separately controlled mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fieldora_bastion.transfer_broker import BroadcastDescriptor, BrokerError


@dataclass(slots=True)
class SecureCatalogue:
    """In-memory protocol contract for descriptor publication and lookup."""

    _descriptors: dict[str, BroadcastDescriptor] = field(default_factory=dict)

    def publish(self, descriptor: BroadcastDescriptor) -> None:
        existing = self._descriptors.get(descriptor.package_id)
        if existing is not None and existing != descriptor:
            raise BrokerError("package_id is already published with a different descriptor")
        self._descriptors[descriptor.package_id] = descriptor

    def get_for_collector(
        self, package_id: str, collector_id: str
    ) -> BroadcastDescriptor:
        try:
            descriptor = self._descriptors[package_id]
        except KeyError as exc:
            raise BrokerError("package is not published") from exc
        if collector_id not in descriptor.audience and "*" not in descriptor.audience:
            raise BrokerError("collector is not in the descriptor audience")
        return descriptor

    def count(self) -> int:
        return len(self._descriptors)
