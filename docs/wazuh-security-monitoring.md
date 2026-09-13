# Wazuh security monitoring

FieldoraBastion can emit bounded security alerts as single-line JSON for collection by Wazuh. Wazuh is an observability, correlation, and alerting destination; it is not part of the Bastion trust decision and cannot mark a package clean, approved, or accepted.

Configure `WazuhJsonlSink` with an operator-controlled, pre-created path such as `/var/log/fieldora-bastion/security-events.jsonl`. The sink serializes the existing `SecurityAlert` contract and adds only `fieldora.component = bastion`.

A Wazuh agent can collect the stream as JSON:

```xml
<localfile>
  <location>/var/log/fieldora-bastion/security-events.jsonl</location>
  <log_format>json</log_format>
  <label key="@source">fieldora-bastion</label>
</localfile>
```

Do not mount Bastion quarantine storage, approved package storage, signing keys, container-engine sockets, Fieldora databases, or protected-zone credentials into Wazuh solely for event collection. The event directory is the intended boundary.

An integrity discrepancy remains fail-closed even if Wazuh is unavailable. Monitoring delivery must never be able to turn an `integrity-failed` transfer into `accepted`.
