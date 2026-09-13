# Durable broker state

FieldoraBastion persists bounded transfer-broker metadata so an in-progress secure-transfer workflow can recover after process restart without weakening the trust boundary.

Persisted data includes:

- transfer request identity and kind;
- package class, artifact ID and version;
- source/requestor identifiers;
- audience identities;
- current transfer state;
- active collector claim;
- approved-package metadata, including digest, provenance, signing-key ID and scan result.

The broker-state database does **not** store package bytes, bearer tokens, credentials, private signing keys, malware databases, or protected-product business data.

`DurableTransferBroker` preserves the existing `TransferBroker` state machine and persists after each successful state mutation. On restart, records are reconstructed into the same state-machine representation, including terminal integrity failures.

The SQLite implementation is a local durability baseline and not a claim of clustered/high-availability persistence. A future provider deployment may replace the backing store while retaining the same bounded data contract and fail-closed recovery semantics.
