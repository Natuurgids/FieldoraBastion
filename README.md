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
5. The bastion emits an immutable Fieldora transfer bundle plus a signed manifest containing a digest for every payload file.
6. The protected Fieldora side independently verifies the manifest/signature and recomputes every digest before accepting the bundle.
7. Acceptance, rejection, actor/service identity, provenance, and hashes are auditable.

For a genuine air gap, the request and response bundles can cross via removable media or a one-way transfer mechanism. There is no requirement for the protected Fieldora system to maintain a live route to the bastion or the Internet.

For an isolated but connected deployment, FieldoraBastion may be enrolled as a durable Fieldora service using mTLS service identity and least-authority APIs. That mode must preserve the same bundle verification semantics as the offline transfer mode.

## Container and filesystem constraints

- run as a non-root user where practical;
- immutable/read-only container root filesystem;
- separate writable quarantine and approved-bundle volumes;
- no Docker/Podman/OpenShift control socket mounted into the container;
- no Fieldora database credentials;
- no NAS/archive credentials unless a future explicitly scoped acquisition adapter requires them;
- outbound network access restricted to configured allowlists;
- inbound interfaces limited to the minimum required control plane;
- resource limits for CPU, memory, temporary storage, file count, and maximum artifact size;
- downloaded content is never executed during acquisition or scanning.

## Model-package safety

Model bundles should prefer data-only formats such as `safetensors` or constrained ONNX artifacts. Arbitrary Python, pickle, shell scripts, installers, or model-supplied executable hooks are rejected by default. Hash verification proves identity, not safety, so model acceptance also requires provenance, policy validation, and malware/content inspection.

## Package classes

Software updates, AI models, taxonomy/reference data, and scientific data are separate package classes with separate allowlists and acceptance policies. A model approval must not implicitly authorize executable software, and a reference-data approval must not authorize a model runtime.

## Relationship to Fieldora

Fieldora remains authoritative for PBAC, scientific provenance, service lifecycle, and final acceptance into trusted storage. FieldoraBastion is an optional acquisition/quarantine boundary and must not become an authority that can bypass those controls.

The main Fieldora repository remains responsible for defining the request/response protocol and the trusted-side verifier/importer. This repository implements the external acquisition/quarantine side of that contract.
