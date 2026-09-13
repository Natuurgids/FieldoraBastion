"""Authenticated collector boundary for FieldoraBastion.

Identity-token validation remains the responsibility of the configured identity
provider or trusted gateway. Bastion consumes only a verified principal and still
enforces the secure-catalogue audience itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from fieldora_bastion.secure_catalogue import SecureCatalogue
from fieldora_bastion.transfer_broker import BroadcastDescriptor, BrokerError


@dataclass(frozen=True, slots=True)
class AuthenticatedCollector:
    collector_id: str
    issuer: str
    subject: str
    authentication_method: str
    verified: bool

    def __post_init__(self) -> None:
        for name, value in (
            ("collector_id", self.collector_id),
            ("issuer", self.issuer),
            ("subject", self.subject),
            ("authentication_method", self.authentication_method),
        ):
            if not value.strip():
                raise BrokerError(f"{name} must not be blank")
        if not self.verified:
            raise BrokerError("collector principal must be externally verified")


def authorize_collection(
    catalogue: SecureCatalogue,
    package_id: str,
    principal: AuthenticatedCollector,
) -> BroadcastDescriptor:
    """Return the descriptor only for an authenticated, audience-authorized collector."""
    return catalogue.get_for_collector(package_id, principal.collector_id)
