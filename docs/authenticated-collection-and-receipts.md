# Authenticated collection and durable receipts

FieldoraBastion keeps authentication, authorization and package verification as
separate trust decisions.

## Authentication boundary

Bastion does **not** become an identity provider and does not store bearer tokens.
A configured identity provider or trusted gateway (Keycloak by default in
Security Install, but replaceable) validates the external credential and supplies
a bounded `AuthenticatedCollector` principal.

Bastion then independently enforces the secure-catalogue audience using the
principal's `collector_id`. An authenticated identity that is not in the package
descriptor audience is still denied.

The principal records only bounded authentication evidence: collector identity,
issuer, subject, authentication method and the fact that external verification
succeeded. Secrets and raw tokens are outside this contract.

## Durable receipt boundary

`ReceiptStore` persists `CollectionReceipt` metadata in a local SQLite database.
It stores:

- package ID;
- collector ID;
- expected package SHA-256;
- observed package SHA-256;
- terminal receipt status (`accepted` or `integrity-failed`).

It does not store package bytes, identity tokens, credentials or signing keys.

A `(package_id, collector_id)` receipt is immutable after first persistence. An
exact replay is idempotent; conflicting evidence fails closed.

## Current maturity

The existing `TransferBroker` remains the authority for claim, transfer and
collector-verification state. This change adds a durable receipt primitive and an
authenticated catalogue-access boundary; it does not yet make the complete broker
state machine durable and it does not expose a network API.
