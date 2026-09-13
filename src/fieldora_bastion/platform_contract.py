"""Product-neutral security-platform contract for FieldoraBastion."""

from __future__ import annotations

from dataclasses import dataclass

_SECURITY_CAPABILITIES = {
    "secure-transfer",
    "identity-broker",
    "security-monitoring",
    "security-posture",
    "software-supply-chain",
}
_SUPPLY_CHAIN_CONTROLS = {"renovate", "trivy", "syft", "osv"}
_LICENSE_POLICY = "commercial-private"


class PlatformContractError(ValueError):
    """Raised when a product adapter violates the Bastion platform boundary."""


@dataclass(frozen=True, slots=True)
class ProductAdapter:
    """Bounded description of a product consuming Bastion security services."""

    product_id: str
    adapter: str
    authorization_authority: str
    package_classes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("product_id", self.product_id),
            ("adapter", self.adapter),
            ("authorization_authority", self.authorization_authority),
        ):
            if not value.strip():
                raise PlatformContractError(f"{name} must not be blank")
        if not self.package_classes or any(not item.strip() for item in self.package_classes):
            raise PlatformContractError("package_classes must contain non-blank values")


@dataclass(frozen=True, slots=True)
class SecurityPlatformContract:
    """Validated reusable Bastion capabilities and attached product adapters."""

    capabilities: tuple[str, ...]
    supply_chain_controls: tuple[str, ...]
    license_policy: str
    products: tuple[ProductAdapter, ...]

    def __post_init__(self) -> None:
        capabilities = set(self.capabilities)
        if capabilities != _SECURITY_CAPABILITIES:
            raise PlatformContractError("all approved security capabilities must be declared exactly once")
        controls = set(self.supply_chain_controls)
        if controls != _SUPPLY_CHAIN_CONTROLS:
            raise PlatformContractError("Renovate, Trivy, Syft, and OSV are required controls")
        if self.license_policy != _LICENSE_POLICY:
            raise PlatformContractError("license_policy must be commercial-private")
        if not self.products:
            raise PlatformContractError("at least one product adapter is required")
        product_ids = [product.product_id for product in self.products]
        if len(product_ids) != len(set(product_ids)):
            raise PlatformContractError("product_id values must be unique")


def fieldora_adapter() -> ProductAdapter:
    """Return the Fieldora integration without making Fieldora a platform authority."""
    return ProductAdapter(
        product_id="fieldora",
        adapter="fieldora",
        authorization_authority="fieldora-pbac",
        package_classes=("software-update", "model", "taxonomy", "scientific-data", "maps"),
    )
