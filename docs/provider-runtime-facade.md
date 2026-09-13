# Unified provider runtime facade

`FieldoraBastionProvider` is the provider-facing runtime contract for orchestrators such as Security Install.

It deliberately combines two execution styles behind one certified Python interface:

- bounded package jobs: quarantine malware scanning and signed model-bundle building;
- secure-transfer state operations: request, quarantine/verification transitions, approval, publication, claim, transfer, collector verification and terminal receipt retrieval.

The provider remains **job-oriented**. This facade is not a long-running daemon and does not add a network API.

## Persistence

The runtime uses `AtomicTransferStore` as its only secure-transfer metadata persistence boundary. On startup it reconstructs persisted transfer records so in-progress transfers can continue after a process restart.

Publication atomically persists the `broadcast` state with its bounded catalogue descriptor. Terminal collector verification atomically persists `accepted` or `integrity-failed` with the corresponding receipt.

Other state-machine mutations are persisted immediately and the in-memory mutation is rolled back if persistence fails.

## Security boundary

The runtime database may contain bounded request metadata, state, claims, approved-package metadata, catalogue descriptors and collection receipts.

It does not contain package bytes, bearer tokens, identity-provider credentials, private signing keys, ClamAV databases or protected-product business data.

Identity authentication stays outside this facade. Bastion still independently enforces the descriptor audience before exposing a descriptor to a collector.

Protected products remain responsible for their final trusted-side verification and business authorization before installation.

## Security Install integration

Security Install should consume this facade as the default `secure-transfer` provider contract rather than coordinate `TransferBroker`, `SecureCatalogue`, `DurableTransferBroker` and `ReceiptStore` separately.

The older components remain compatibility/internal primitives for now; this change does not delete them. A later migration can deprecate redundant stores after consumers have moved to the unified runtime.
