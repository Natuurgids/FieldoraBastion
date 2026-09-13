# Secure transfer catalogue

FieldoraBastion publishes bounded metadata descriptors only after a package has reached the broker's approved state. Package bytes are not stored in or broadcast by the catalogue.

The descriptor carries package identity, class, artifact/version, SHA-256, byte count, provenance, signing-key identity, manifest-signature type, malware-scan result, and collector audience.

Collectors may resolve a descriptor only when their authenticated identity is in the audience (or the explicitly configured wildcard audience). A package identifier cannot be silently republished with changed descriptor contents.

The existing `TransferBroker` remains the authority for request state, approval, claim ownership, transfer state, collector verification, accepted receipts, and terminal integrity failure. The catalogue is intentionally a bounded discovery surface rather than an artifact store or business-authorization service.

## Storage boundary

Package bytes remain in quarantine/approved artifact storage owned by the secure-transfer implementation. The catalogue stores descriptors only. Protected products independently verify the collected bytes against the approved digest/signature before installation.

## Current maturity

This module is an in-memory protocol contract. Durable storage, authenticated transport/API, expiry enforcement, and multi-collector persistence are separate implementation milestones and must not be inferred from this contract.