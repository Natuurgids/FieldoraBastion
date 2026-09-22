# Standalone Bastion deployment

This directory provisions the operating-system boundary around Fieldora Bastion.

Ansible owns host configuration, service identity, quarantine/export directories,
scanner installation, filesystem permissions and runtime-boundary hardening. It does **not** decide
whether an artifact is trusted. The Bastion application creates signed evidence;
Fieldora independently verifies that evidence and applies its own PBAC policy.

## Trust-domain rules

- Never place Fieldora PostgreSQL, PBAC, application, internal-CA or other
  Fieldora secrets in this inventory.
- Never store the Bastion private signing key in Git, inventory, group_vars,
  host_vars or an Ansible Vault ciphertext committed to this repository.
- A production secret handler (Vault/HSM/TPM integration) must provision or
  expose signing capability locally to Bastion without making Fieldora depend
  on that service. This role does not install a fake long-running Bastion daemon
  or copy private signing key material.
- Set `bastion_base_signer_key_id` to the expected non-secret 32-character
  lowercase hexadecimal signer identity. The live Unix signing socket itself is
  externally provisioned by the selected Bastion-local secret handler.
- Keycloak is Bastion-local when an authenticated operator/API surface is
  deployed. Fieldora package verification must not require Bastion Keycloak.
- Export contains only certified artifacts and evidence intended to cross the
  controlled/offline boundary.

Run against a reviewed inventory:

    ansible-playbook site.yml

The placeholder inventory intentionally cannot target a production host until
an operator supplies the standalone Bastion address and SSH identity.
