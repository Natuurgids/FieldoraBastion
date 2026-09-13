"""Interchangeable secure-transfer provider contract for FieldoraBastion."""

from __future__ import annotations

from dataclasses import dataclass


class ProviderContractError(ValueError):
    """Raised when the Bastion provider declaration violates the security-install contract."""


@dataclass(frozen=True, slots=True)
class SecurityProvider:
    """Describe one independently replaceable provider in the Security Install."""

    capability: str
    provider_id: str
    protocol_version: int
    implementation_version: str

    def __post_init__(self) -> None:
        if not self.capability.strip():
            raise ProviderContractError("capability must not be blank")
        if not self.provider_id.strip():
            raise ProviderContractError("provider_id must not be blank")
        if self.protocol_version < 1:
            raise ProviderContractError("protocol_version must be positive")
        if not self.implementation_version.strip():
            raise ProviderContractError("implementation_version must not be blank")


def fieldora_bastion_provider(version: str = "0.1.0") -> SecurityProvider:
    """Declare FieldoraBastion as one replaceable secure-transfer provider."""
    return SecurityProvider(
        capability="secure-transfer",
        provider_id="fieldora-bastion",
        protocol_version=1,
        implementation_version=version,
    )
