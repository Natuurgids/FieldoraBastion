"""Bounded Wazuh-compatible security-event output for FieldoraBastion."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from fieldora_bastion.transfer_broker import SecurityAlert


class WazuhJsonlSink:
    """Append Bastion security alerts to a JSON log collected by Wazuh."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit_security_alert(self, alert: SecurityAlert) -> None:
        """Write one bounded single-line JSON alert and durably flush it."""
        if not self.path.parent.is_dir():
            raise FileNotFoundError(f"security event directory does not exist: {self.path.parent}")
        payload = {"bastion": {**asdict(alert), "component": "security-broker"}}
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
