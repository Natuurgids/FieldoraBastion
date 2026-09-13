# Secure transfer broker

FieldoraBastion is the security boundary for externally sourced data packages. The host accepts exactly two request classes:

- **collection request** — obtain a named/versioned package from an approved source;
- **delivery request** — receive a package supplied to the Bastion boundary.

Both requests converge on the same fail-closed lifecycle:

`requested -> acquiring|receiving -> quarantined -> scanning -> verifying -> approved -> broadcast -> claimed -> collected`

Terminal negative states are `rejected`, `expired`, `cancelled`, and `failed`.

## Trust rules

Externally supplied bytes are never broadcast directly. They remain in quarantine until package-class policy, provenance, cryptographic identity, malware scanning, content-policy checks, and bundle verification have succeeded. An approved package must carry a signed manifest and a clean malware-scan attestation. Hash identity alone is not treated as evidence of safety.

The broadcast is metadata, not package content. It exposes a bounded immutable descriptor containing the package identity, class, version, byte size, digest, provenance, signing identity, clean-scan state, and intended collector audience. Filesystem paths, quarantine paths, signing keys, and protected-zone credentials are never broadcast.

Collectors authenticate before claiming an approved broadcast. A claim reserves the package for an eligible collector; collection completes only when the collector confirms the exact approved digest. A collection receipt records the package identity, collector identity, and digest. Collector-side verification remains mandatory: the collector must independently verify the signed manifest and package digests before admitting content into its own trusted storage.

## Transport independence

The same state and descriptor semantics apply to connected and air-gapped deployments. Connected installations may transport requests, broadcasts, claims, packages, and receipts through mutually authenticated service APIs. Air-gapped installations may serialize the same bounded records onto approved removable-media or one-way-transfer mechanisms. Transport must not weaken approval or verification semantics.

## Fieldora relationship

Fieldora may originate collection requests, submit delivery requests, observe bounded broker state, consume eligible broadcasts, and record collection receipts. FieldoraBastion remains responsible for quarantine, scanning, package-policy verification, and signed approval. Fieldora remains responsible for PBAC and final trusted-side acceptance. No browser control may declare a package clean or bypass either boundary.
