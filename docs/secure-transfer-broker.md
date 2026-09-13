# Secure transfer broker

FieldoraBastion is the security boundary for externally sourced data packages. The host accepts exactly two request classes:

- **collection request** — obtain a named/versioned package from an approved source;
- **delivery request** — receive a package supplied to the Bastion boundary.

Both requests converge on the same fail-closed lifecycle:

`requested -> acquiring|receiving -> quarantined -> scanning -> verifying -> approved -> broadcast -> claimed -> transferred -> collector-verifying -> accepted`

Terminal negative states include `rejected`, `expired`, `cancelled`, `failed`, and `integrity-failed`.

## Trust rules

Externally supplied bytes are never broadcast directly. They remain in quarantine until package-class policy, provenance, cryptographic identity, malware scanning, content-policy checks, and bundle verification have succeeded. An approved package must carry a signed manifest and a clean malware-scan attestation. Hash identity alone is not treated as evidence of safety.

The broadcast is metadata, not package content. It exposes a bounded immutable descriptor containing the package identity, class, version, byte size, digest, provenance, signing identity, clean-scan state, and intended collector audience. Filesystem paths, quarantine paths, signing keys, and protected-zone credentials are never broadcast.

Collectors authenticate before claiming an approved broadcast. A claim reserves the package for an eligible collector. Transfer is not considered successful collection: after bytes arrive, the collector independently verifies the signed manifest and recomputes package digests. Only an exact match produces an `accepted` receipt.

If the collector observes bytes whose SHA-256 differs from the Bastion-approved SHA-256, the request becomes terminal `integrity-failed`. The collector must reject or quarantine those received bytes, never admit them to trusted storage, and emit a high-severity `package_integrity_mismatch` security event to the configured security-monitoring sink. The event contains bounded metadata such as request/package/collector identity, expected and observed digests, signing-key identity, package class/version, and provenance; it must not include package contents, credentials, or sensitive filesystem paths.

## Transport independence

The same state and descriptor semantics apply to connected and air-gapped deployments. Connected installations may transport requests, broadcasts, claims, packages, receipts, and security events through mutually authenticated service APIs. Air-gapped installations may serialize the same bounded records onto approved removable-media or one-way-transfer mechanisms. A discrepancy event can return on the next approved return channel. Transport must not weaken approval or verification semantics.

## Fieldora relationship

Fieldora may originate collection requests, submit delivery requests, observe bounded broker state, consume eligible broadcasts, independently verify collected bytes, record acceptance/integrity-failure receipts, and forward bounded security alerts to its configured monitoring host. FieldoraBastion remains responsible for quarantine, scanning, package-policy verification, and signed approval. Fieldora remains responsible for PBAC and final trusted-side acceptance. No browser control may declare a package clean or bypass either boundary.
