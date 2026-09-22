# Standalone Bastion deployment

This directory provisions the operating-system boundary around Fieldora Bastion.

Ansible owns host configuration, service identity, quarantine/export directories,
scanner installation, permissions and service hardening. It does **not** decide
whether an artifact is trusted. The Bastion application creates signed evidence;
Fieldora independently verifies that evidence and applies its own PBAC policy.

## Trust-domain rules

- Never place Fieldora PostgreSQL, PBAC, application, internal-CA or other
  Fieldora secrets in this inventory.
- Never store the Bastion private signing key in Git, inventory, group_vars,
  host_vars or an Ansible Vault ciphertext committed to this repository.
- A production secret handler (Vault/HSM/TPM integration) must provision or
  expose signing capability locally to Bastion without making Fieldora depend
  on that service.
- Keycloak is Bastion-local when an authenticated operator/API surface is
  deployed. Fieldora package verification must not require Bastion Keycloak.
- Export contains only certified artifacts and evidence intended to cross the
  controlled/offline boundary.

Run against a reviewed inventory:

    ansible-playbook site.yml

The placeholder inventory intentionally cannot target a production host until
an operator supplies the standalone Bastion address and SSH identity.
