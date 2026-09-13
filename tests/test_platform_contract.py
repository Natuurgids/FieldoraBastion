import pytest

from fieldora_bastion.platform_contract import (
    ProviderContractError,
    SecurityProvider,
    fieldora_bastion_provider,
)


def test_bastion_declares_secure_transfer_capability() -> None:
    provider = fieldora_bastion_provider()
    assert provider.capability == "secure-transfer"
    assert provider.provider_id == "fieldora-bastion"
    assert provider.protocol_version == 1


def test_alternative_provider_can_implement_same_capability() -> None:
    alternative = SecurityProvider(
        capability="secure-transfer",
        provider_id="alternative-transfer-gateway",
        protocol_version=1,
        implementation_version="2.0.0",
    )
    assert alternative.capability == fieldora_bastion_provider().capability
    assert alternative.provider_id != fieldora_bastion_provider().provider_id


def test_provider_identity_is_required() -> None:
    with pytest.raises(ProviderContractError, match="provider_id"):
        SecurityProvider(
            capability="secure-transfer",
            provider_id="",
            protocol_version=1,
            implementation_version="1.0.0",
        )


def test_protocol_version_must_be_positive() -> None:
    with pytest.raises(ProviderContractError, match="protocol_version"):
        SecurityProvider(
            capability="secure-transfer",
            provider_id="example",
            protocol_version=0,
            implementation_version="1.0.0",
        )
