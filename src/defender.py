
import json
import subprocess

from datetime import datetime
from typing import Any

from src.models import SecurityEvent


POWERSHELL_COMMAND = r"""
$ErrorActionPreference = 'Stop'
Get-MpThreatDetection |
    Select-Object ThreatID, InitialDetectionTime, LastThreatStatusChangeTime,
                  ThreatStatusID, ActionSuccess, Resources |
    ConvertTo-Json -Depth 4 -Compress
"""


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp returned by PowerShell."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return timestamp.astimezone()
        return timestamp
    except ValueError:
        return None


def _as_list(value: Any) -> list:
    """Normalize PowerShell's single-item and multi-item JSON output."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_defender_records(records: list[dict[str, Any]]) -> list[SecurityEvent]:
    """Convert Defender detection records into normalized events."""
    events = []

    for index, record in enumerate(records):
        timestamp = _parse_timestamp(record.get("InitialDetectionTime"))
        if timestamp is None:
            continue

        threat_id = str(record.get("ThreatID") or f"unknown-{index}")
        resources = record.get("Resources") or []
        if not isinstance(resources, list):
            resources = [resources]

        events.append(
            SecurityEvent(
                event_id=f"defender-{threat_id}-{index}",
                timestamp=timestamp,
                source="Windows Defender",
                event_type="malware_detection",
                title=f"Defender detection: {threat_id}",
                details=(
                    "Detection history record. This does not by itself "
                    "establish whether a threat executed or caused an incident."
                ),
                affected_path=str(resources[0]) if resources else None,
                recorded_action=str(record.get("ThreatStatusID") or "Unknown"),
                evidence_status="observed",
                metadata={
                    "threat_id": threat_id,
                    "action_success": record.get("ActionSuccess"),
                    "last_status_change": record.get("LastThreatStatusChangeTime"),
                    "resources": resources,
                },
            )
        )

    return events


def collect_defender_events(timeout_seconds: int = 20) -> list[SecurityEvent]:
    """
    Read local Defender detection history using PowerShell.

    Returns an empty list when no detections are found. Raises RuntimeError
    when PowerShell or Defender cannot provide the requested data.
    """
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL_COMMAND,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not run Defender query: {exc}") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or "PowerShell command failed"
        raise RuntimeError(message)

    output = result.stdout.strip()
    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Defender returned unreadable JSON") from exc

    return parse_defender_records(_as_list(data))
