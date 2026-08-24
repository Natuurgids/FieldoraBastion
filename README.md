# FieldoraBastion

FieldoraBastion is an optional containerized transfer and quarantine component for Fieldora deployments that need controlled acquisition from external networks before content enters a protected or offline Fieldora environment.

It is deliberately a separate component from the Fieldora application stack. Small organisations can run it as one additional container on Docker, Podman, OpenShift, or another immutable-container platform; higher-assurance installations can place the same container on a separate network boundary without changing the transfer protocol.

## Intended uses

Initial scope:

- acquire approved offline AI/model bundles;
- acquire taxonomy/reference-data releases;
- acquire controlled Fieldora update bundles;
- quarantine externally supplied scientific/reference packages before import.

The bastion is not a transparent proxy and must not expose storage paths, Fieldora database credentials, or protected-zone credentials to external systems.

## Trust model

1. Fieldora or an operator produces an acquisition request containing only the requested artifact identity/version and policy metadata.
2. The bastion resolves that request against explicit allowlisted upstream sources.
3. Downloads are bounded and written only to bastion quarantine storage.
4. The bastion computes cryptographic hashes, validates expected/vendor hashes or signatures when available, records provenance, and performs malware/content-policy scanning.
5. The bastion emits an immutable Fieldora transfer bundle plus a signed manifest containing a digest for every payload file and, when required, a signed clean-scan attestation.
6. The protected Fieldora side independently verifies the manifest signature, validates the clean-scan claim when policy requires it, and recomputes every payload digest before accepting the bundle.
7. Acceptance, rejection, actor/service identity, provenance, hashes, signing-key identity, and bounded scan provenance are auditable.

For a genuine air gap, the request and response bundles can cross via removable media or a one-way transfer mechanism. There is no requirement for the protected Fieldora system to maintain a live route to the bastion or the Internet.

For an isolated but connected deployment, FieldoraBastion may be enrolled as a durable Fieldora service using mTLS service identity and least-authority APIs. That mode must preserve the same bundle verification semantics as the offline transfer mode.

## High-assurance offline model flow

The reference model transfer uses two separate hardened tool stages. The scanner has the quarantined payload and ClamAV definitions but no signing key. The bundle builder has the quarantined payload, the scanner report, and an externally managed Ed25519 private key. Neither stage needs a live route into Fieldora.

Prepare host directories for `quarantine`, `approved`, `scanner-db`, and `signing`. Place the pre-vetted model payload under `quarantine/model`, current ClamAV definition files under `scanner-db`, and the Bastion Ed25519 private key at `signing/model-bundle-ed25519.pem`. Keep the corresponding public key separately for the protected Fieldora side.

Run the isolated scan stage:

```text
docker compose --profile tools run --rm model-scanner
```

A clean scan writes `approved/model-scan.json`. Infected or scanner-error results are not accepted as clean bundle attestations. The scanner report is deliberately outside the scanned payload and is bounded metadata only.

Then build and sign the model bundle:

```text
docker compose --profile tools run --rm model-bundle-builder
```

The builder verifies the source tree again, rejects executable/pickle-style model content, recomputes SHA-256 and sizes, verifies that the scan report is `clean` and covers the exact payload file count, embeds the bounded scan provenance in `manifest.json`, and signs the exact manifest bytes into `manifest.sig`. The private key is never copied into the bundle.

Transfer the resulting bundle directory from `approved` and the Bastion public key across the approved air-gap mechanism. On the protected Fieldora host, install with the repository-controlled PowerShell 7 helper using both signature and scan enforcement:

```text
./Install-Fieldora-Offline-Model.ps1 -InstallRoot <fieldora-install-root> -BundlePath <bundle-directory> -TrustedSigningKey <bastion-public-key.pem> -RequireSignature -RequireCleanScan
```

`-RequireCleanScan` fails closed unless the clean-scan metadata is inside a manifest whose Ed25519 signature verifies against the supplied public key. Fieldora then independently verifies every declared payload size and SHA-256 before installing the model into the read-only runtime model store. Browser/API model metadata uses opaque artifact IDs and exposes only bounded trust provenance, never Bastion or Fieldora filesystem paths.

The signing key should be generated, protected, rotated, and backed up through the organisation's approved key-management process. FieldoraBastion does not silently generate or retain signing keys.

## Container and filesystem constraints

- run as a non-root user where practical;
- immutable/read-only container root filesystem;
- separate writable quarantine and approved-bundle volumes;
- scanner definitions mounted read-only and updated outside the network-isolated scanning stage;
- signing key mounted read-only only into the bundle-builder stage;
- no Docker/Podman/OpenShift control socket mounted into the container;
- no Fieldora database credentials;
- no NAS/archive credentials unless a future explicitly scoped acquisition adapter requires them;
- outbound network access restricted to configured allowlists for acquisition stages; the reference scanner and builder run with no network;
- inbound interfaces limited to the minimum required control plane;
- resource limits for CPU, memory, temporary storage, file count, and maximum artifact size;
- downloaded content is never executed during acquisition or scanning.

## Model-package safety

Model bundles accept data-oriented model artifacts including `safetensors`, constrained ONNX, and GGUF plus a bounded support-file allowlist. Arbitrary Python, pickle, shell scripts, installers, executable libraries, and model-supplied executable hooks are rejected by default. Hash verification proves identity, not safety, so high-assurance model acceptance additionally requires signed provenance and a clean malware-scan attestation.

## Package classes

Software updates, AI models, taxonomy/reference data, and scientific data are separate package classes with separate allowlists and acceptance policies. A model approval must not implicitly authorize executable software, and a reference-data approval must not authorize a model runtime.

## Relationship to Fieldora

Fieldora remains authoritative for PBAC, scientific provenance, service lifecycle, and final acceptance into trusted storage. FieldoraBastion is an optional acquisition/quarantine boundary and must not become an authority that can bypass those controls.

The main Fieldora repository remains responsible for defining the request/response protocol and the trusted-side verifier/importer. This repository implements the external acquisition/quarantine side of that contract.
