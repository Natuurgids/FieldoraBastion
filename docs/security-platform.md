# Security Install provider boundary

FieldoraBastion is one independently deployable component in a larger reusable Security Install. It is not the umbrella security platform.

The Security Install owns composition. It defines capability slots and compatibility contracts. Concrete products fill those slots and must be replaceable without changing protected products or weakening the policy boundary.

## Default provider model

The intended defaults are:

- secure transfer: FieldoraBastion;
- human identity broker: Keycloak;
- security monitoring/SIEM: Wazuh;
- security posture and exposure assessment: OpenKAT;
- update discovery: Renovate;
- vulnerability scanning: Trivy;
- SBOM generation: Syft;
- vulnerability intelligence: OSV;
- secrets: a deployment-target-appropriate secret provider.

These names are defaults, not architectural requirements. A compatible alternative may replace any provider when it implements the same capability contract, preserves required evidence and fail-closed behavior, and passes certification.

For example, replacing Wazuh must not change the bounded security-event contract; replacing Keycloak must preserve the required OIDC/SAML identity-broker contract; replacing Trivy must preserve the vulnerability-scan evidence contract; replacing FieldoraBastion must preserve the secure-transfer request, quarantine, verification, approval, broadcast/catalogue, collection, receipt, and independent-verification semantics.

## FieldoraBastion responsibility

FieldoraBastion implements the `secure-transfer` provider slot. Its responsibilities remain collection and delivery requests, quarantine, malware/content-policy scanning, provenance and signature verification, approved package catalogue/broadcast, governed collection, receipts, and bounded security events.

FieldoraBastion does not own Keycloak, Wazuh, OpenKAT, Renovate, Trivy, Syft, OSV, or the overall installer. It must not require another provider to be embedded inside the Bastion container.

## Product independence

Fieldora is one protected product that can consume the Security Install. Other products may consume the same installation while keeping their own business authorization model and trusted-side acceptance rules.

Fieldora remains authoritative for Fieldora PBAC and trusted-side acceptance. Another product may use RBAC, ABAC, or another authorization model. Security providers must not silently become the business-authorization authority for protected products.

## Isolation and secrets

Providers stay independently isolated according to least privilege. The Security Install may orchestrate deployment and configuration, but it must not collapse all security functions into one privileged container or one shared permanent credential store.

Bootstrap credentials are ephemeral provisioning input and must move into target-appropriate protected secret storage. High-value signing keys, encryption keys, and cloud workload credentials remain outside ordinary configuration.

## Commercial/private release policy

The Security Install should keep the `commercial-private` licensing gate. Unknown, non-commercial, incompatible, or otherwise unapproved dependencies must block release. Using independently deployed open-source providers must not create an obligation to publish unrelated proprietary protected-product source.
