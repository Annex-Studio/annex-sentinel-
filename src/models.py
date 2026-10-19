
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


VALID_EVIDENCE_STATUSES = {
    "observed",
    "user_reported",
    "inferred",
}


@dataclass
class SecurityEvent:
    """A normalized security event recorded by Annex Sentinel."""

    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    title: str
    details: str = ""
    affected_path: str | None = None
    recorded_action: str | None = None
    evidence_status: str = "observed"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("event_id", "source", "event_type", "title"):
            value = getattr(self, name)
            if not value.strip():
                raise ValueError(f"{name} cannot be empty")

        if (
            self.timestamp.tzinfo is None
            or self.timestamp.utcoffset() is None
        ):
            raise ValueError("timestamp must include a timezone")

        if self.evidence_status not in VALID_EVIDENCE_STATUSES:
            raise ValueError("Invalid evidence_status")

    def timestamp_utc(self) -> datetime:
        """Return the event timestamp converted to UTC."""
        return self.timestamp.astimezone(timezone.utc)

    