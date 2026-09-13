# Release digest transfer binding

FieldoraBastion does not decide whether a Security Install release manifest satisfies commercial, compatibility, or protected-product policy. Those decisions stay outside Bastion.

The certified provider runtime does require an immutable SHA-256 `release_digest` before an approved package can enter `broadcast` state. `authorize_release(request_id, release_digest)` is only valid after package approval and stores the digest durably in the Bastion state database.

The binding is intentionally one-way and immutable. Re-authorizing the same request with the same digest is idempotent; attempting to substitute a different release digest fails closed.

A successful `broadcast()` returns a release-bound descriptor containing the ordinary bounded Bastion descriptor plus the authorized release digest. Collector lookup reconstructs the same binding after restart.

After transfer, both accepted and integrity-failed collection receipts are returned as release-bound receipts carrying the same release digest. This lets Security Install construct its post-transfer install-verification envelope without correlating release metadata through a separate side channel.

The release digest is metadata only. Package bytes, release signing keys, credentials, bearer tokens, and protected-product authorization remain outside the binding store.

This contract does not turn Bastion into the Security Install umbrella and does not make Bastion the final business authorization authority.
