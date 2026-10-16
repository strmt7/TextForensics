from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_record_payload(record: dict[str, Any]) -> bytes:
    payload = {
        key: value
        for key, value in record.items()
        if key != "record_sha256"
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_ledger(ledger_path: str | Path) -> dict[str, Any]:
    ledger_path = Path(ledger_path)
    if not ledger_path.exists():
        return {
            "valid": False,
            "records": 0,
            "errors": ["ledger_not_found"],
        }

    errors: list[str] = []
    previous = None
    records = 0
    for index, line in enumerate(
        ledger_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        records += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line_{index}:invalid_json")
            continue
        if not isinstance(record, dict):
            errors.append(f"line_{index}:record_not_object")
            continue

        expected = sha256_bytes(_canonical_record_payload(record))
        if record.get("record_sha256") != expected:
            errors.append(f"line_{index}:record_hash_mismatch")
        if record.get("previous_record_sha256") != previous:
            errors.append(f"line_{index}:chain_mismatch")
        previous = record.get("record_sha256")

    return {
        "valid": not errors,
        "records": records,
        "errors": errors,
        "warning": (
            "The ledger is tamper-evident but uses the local system clock; "
            "it is not an independent trusted timestamp."
        ),
    }


def snapshot_file(
    file_path: str | Path,
    ledger_path: str | Path,
) -> dict[str, Any]:
    file_path = Path(file_path)
    ledger_path = Path(ledger_path)
    data = file_path.read_bytes()

    previous_record_sha256 = None
    if ledger_path.exists():
        verification = verify_ledger(ledger_path)
        if not verification["valid"]:
            raise ValueError(
                "Refusing to append to an invalid provenance ledger."
            )
        lines = [
            line
            for line in ledger_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if lines:
            previous_record_sha256 = json.loads(lines[-1])[
                "record_sha256"
            ]

    record: dict[str, Any] = {
        "schema": "textforensics-ledger/v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "file_name": file_path.name,
        "file_size": len(data),
        "file_sha256": sha256_bytes(data),
        "previous_record_sha256": previous_record_sha256,
    }
    record["record_sha256"] = sha256_bytes(
        _canonical_record_payload(record)
    )

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
    return record
