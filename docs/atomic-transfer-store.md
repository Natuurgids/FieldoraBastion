# Atomic transfer transaction store

FieldoraBastion now defines a single local SQLite transaction boundary for bounded secure-transfer metadata that must remain consistent across crashes.

The store coordinates:

- transfer request/state/claim metadata;
- approved-package metadata;
- published catalogue descriptors;
- terminal collection receipts.

Publication commits the transfer's `broadcast` state and catalogue descriptor in one transaction. Final collection commits the terminal broker state and receipt in one transaction. Conflicting terminal evidence fails closed and rolls back the attempted state change.

The database deliberately does **not** contain package bytes, bearer tokens, credentials, private signing keys, or malware databases. Package content remains in secure-transfer-owned artifact/quarantine storage.

This is a local durability baseline, not clustered high availability or a network service. SQLite transaction semantics provide local atomicity; HA storage and distributed coordination require a separately certified provider implementation.
