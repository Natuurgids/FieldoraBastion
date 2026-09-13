import pytest

from fieldora_bastion.platform_contract import (
    PlatformContractError,
    ProductAdapter,
    SecurityPlatformContract,
    fieldora_adapter,
)


def _contract(*products: ProductAdapter) -> SecurityPlatformContract:
    return SecurityPlatformContract(
        capabilities=(
            "secure-transfer",
            "identity-broker",
            "security-monitoring",
            "security-posture",
            "software-supply-chain",
        ),
        supply_chain_controls=("renovate", "trivy", "syft", "osv"),
        license_policy="commercial-private",
        products=products,
    )


def test_fieldora_is_one_product_adapter() -> None:
    contract = _contract(fieldora_adapter())
    assert contract.products[0].authorization_authority == "fieldora-pbac"
    assert "software-update" in contract.products[0].package_classes


def test_other_products_keep_their_own_authorization_authority() -> None:
    other = ProductAdapter(
        product_id="example-product",
        adapter="generic-oidc",
        authorization_authority="example-product-rbac",
        package_classes=("software-update", "reference-data"),
    )
    contract = _contract(fieldora_adapter(), other)
    assert contract.products[1].authorization_authority == "example-product-rbac"


def test_supply_chain_controls_cannot_be_weakened() -> None:
    with pytest.raises(PlatformContractError, match="Renovate"):
        SecurityPlatformContract(
            capabilities=(
                "secure-transfer",
                "identity-broker",
                "security-monitoring",
                "security-posture",
                "software-supply-chain",
            ),
            supply_chain_controls=("renovate", "trivy", "syft"),
            license_policy="commercial-private",
            products=(fieldora_adapter(),),
        )


def test_private_commercial_license_gate_is_required() -> None:
    with pytest.raises(PlatformContractError, match="commercial-private"):
        SecurityPlatformContract(
            capabilities=(
                "secure-transfer",
                "identity-broker",
                "security-monitoring",
                "security-posture",
                "software-supply-chain",
            ),
            supply_chain_controls=("renovate", "trivy", "syft", "osv"),
            license_policy="permissive-only",
            products=(fieldora_adapter(),),
        )
