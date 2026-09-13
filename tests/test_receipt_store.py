from __future__ import annotations

import pytest

from fieldora_bastion.receipt_store import ReceiptStore
from fieldora_bastion.transfer_broker import BrokerError, CollectionReceipt


def _receipt(*, observed: str = "a" * 64, status: str = "accepted") -> CollectionReceipt:
    return CollectionReceipt(
        package_id="pkg-001",
        collector_id="fieldora-prod",
        expected_sha256="a" * 64,
        observed_sha256=observed,
        status=status,
    )


def test_receipt_survives_store_reopen(tmp_path) -> None:
    path = tmp_path / "receipts.sqlite3"
    ReceiptStore(path).record(_receipt())
    reopened = ReceiptStore(path)
    assert reopened.get("pkg-001", "fieldora-prod") == _receipt()
    assert reopened.count() == 1


def test_exact_repeat_is_idempotent(tmp_path) -> None:
    store = ReceiptStore(tmp_path / "receipts.sqlite3")
    store.record(_receipt())
    store.record(_receipt())
    assert store.count() == 1


def test_conflicting_receipt_is_rejected(tmp_path) -> None:
    store = ReceiptStore(tmp_path / "receipts.sqlite3")
    store.record(_receipt())
    with pytest.raises(BrokerError, match="different evidence"):
        store.record(_receipt(observed="b" * 64, status="integrity-failed"))
