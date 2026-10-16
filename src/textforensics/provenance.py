from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


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


@contextmanager
def _ledger_lock(ledger_path: Path) -> Iterator[None]:
    """Serialize ledger reads/writes across local processes.

    A separate lock file avoids changing the ledger contents merely to lock it.
    The lock file intentionally persists; deleting lock files can introduce a
    race with another process that is waiting on the same inode/handle.
    """
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(str(ledger_path) + ".lock")
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _verify_ledger_unlocked(ledger_path: Path) -> dict[str, Any]:
    if not ledger_path.exists():
        return {
            "valid": False,
            "records": 0,
            "errors": ["ledger_not_found"],
        }

    errors: list[str] = []
    previous = None
    records = 0
    with ledger_path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
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


def verify_ledger(ledger_path: str | Path) -> dict[str, Any]:
    ledger = Path(ledger_path)
    with _ledger_lock(ledger):
        return _verify_ledger_unlocked(ledger)


def snapshot_file(
    file_path: str | Path,
    ledger_path: str | Path,
) -> dict[str, Any]:
    file_path = Path(file_path)
    ledger_path = Path(ledger_path)
    data = file_path.read_bytes()

    with _ledger_lock(ledger_path):
        previous_record_sha256 = None
        if ledger_path.exists():
            verification = _verify_ledger_unlocked(ledger_path)
            if not verification["valid"]:
                raise ValueError(
                    "Refusing to append to an invalid provenance ledger."
                )
            with ledger_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        previous_record_sha256 = json.loads(line)[
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
