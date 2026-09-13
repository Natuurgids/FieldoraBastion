# Reusable security platform

FieldoraBastion is evolving from a Fieldora-specific acquisition helper into a reusable security gateway and control-plane contract for protected products. Fieldora remains the first product adapter, not the authority for the generic platform.

## Capabilities

The reusable platform contract separates five capabilities:

- secure transfer: collection/delivery requests, quarantine, scanning, provenance and signature verification, approved catalogue/broadcast, governed collection, and receipts;
- identity broker integration: Keycloak and standards-based human federation such as OIDC and SAML;
- security monitoring: bounded events for Wazuh or another monitoring sink;
- security posture: optional OpenKAT integration for vulnerability and exposure assessment;
- software supply chain: Renovate update discovery, Trivy vulnerability scanning, Syft SBOM generation, OSV intelligence, and a `commercial-private` license gate.

These capabilities are logical control-plane responsibilities. They must not be collapsed into one privileged container. Keycloak, Wazuh, OpenKAT, scanners, signing stages, and product services remain independently isolated according to least privilege.

## Product adapters

A product adapter declares a stable product ID, adapter identity, the product's own authorization authority, and package classes that it accepts. The platform must not silently inherit one product's business authorization model.

For Fieldora, Fieldora remains authoritative for PBAC and trusted-side acceptance. A different product can retain RBAC, ABAC, or another authorization authority while reusing the same Bastion transfer, monitoring, posture, identity-federation, and supply-chain controls.

The generic platform must not require Fieldora database credentials, scientific-domain permissions, or Fieldora filesystem paths. Product-specific trusted-side verification stays in the product adapter or protected product.

## Software and security updates

Software updates are a governed package class. Update discovery never means automatic production deployment. A candidate update must pass review, tests, vulnerability and license gates, SBOM generation, signing, and the applicable product/deployment certifications before it becomes an approved update package.

Unknown, non-commercial, incompatible, or otherwise unapproved licensing must fail the `commercial-private` release gate. Independently deployed open-source services must not create an obligation to publish unrelated proprietary consumer-product source.

## Bootstrap relationship

The reusable Bastion contract should be the security-platform portion of higher-level installers. Product installers may add their own database, storage, UI, PBAC/RBAC, and domain configuration, but should consume the Bastion security contract rather than redefine Keycloak, Wazuh, OpenKAT, update scanning, or secure-transfer semantics independently.

Bootstrap credentials are ephemeral provisioning input. Target-specific installers must migrate them to protected secret storage and must not make Bastion a permanent plaintext secret database or general cloud credential vault.
