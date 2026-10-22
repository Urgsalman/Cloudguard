
import json
from pathlib import Path
from threading import Lock
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
HISTORY_FILE = DATA_DIR / "audits.json"

_file_lock = Lock()


def save_audit(audit: dict[str, Any]) -> None:
    """Persist an audit without overwriting previous audit records."""
    audit_id = audit.get("audit_id")

    if not isinstance(audit_id, str) or not audit_id:
        raise TypeError("audit_id must be a non-empty string.")

    with _file_lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if HISTORY_FILE.exists():
            with HISTORY_FILE.open("r", encoding="utf-8") as file:
                audits = json.load(file)
            if not isinstance(audits, list):
                raise TypeError("Audit history must contain a JSON list.")
        else:
            audits = []

        # Prevent duplicate records if the same audit is saved twice.
        audits = [
            item for item in audits
            if isinstance(item, dict)
            and item.get("audit_id") != audit_id
        ]
        audits.append(audit)

        temporary_file = HISTORY_FILE.with_suffix(".tmp")
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(audits, file, ensure_ascii=False, indent=2)

        temporary_file.replace(HISTORY_FILE)


def list_audits() -> list[dict[str, Any]]:
    """Return audits from newest to oldest."""
    with _file_lock:
        if not HISTORY_FILE.exists():
            return []

        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            audits = json.load(file)

        if not isinstance(audits, list):
            raise TypeError("Audit history must contain a JSON list.")

        valid_audits = [
            item for item in audits if isinstance(item, dict)
        ]

        return sorted(
            valid_audits,
            key=lambda item: str(item.get("audited_at", "")),
            reverse=True,
        )


def get_audit(audit_id: str) -> dict[str, Any] | None:
    """Return one audit by its identifier."""
    return next(
        (
            audit for audit in list_audits()
            if audit.get("audit_id") == audit_id
        ),
        None,
    )
