
from dataclasses import dataclass
from datetime import timedelta

from src.models import SecurityEvent


@dataclass
class TimelineFlag:
    event_a_id: str
    event_b_id: str
    reason: str


def build_timeline(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Sort events by timestamp, normalizing timestamps to UTC."""
    return sorted(events, key=lambda event: event.timestamp_utc())


def flag_temporally_close_events(
    events: list[SecurityEvent],
    window: timedelta = timedelta(hours=24),
) -> list[TimelineFlag]:
    """
    Flag events from different sources that occurred close together.

    Temporal proximity does not prove that events are related.
    """
    ordered = build_timeline(events)
    flags: list[TimelineFlag] = []

    for i, event_a in enumerate(ordered):
        for event_b in ordered[i + 1:]:
            difference = (
                event_b.timestamp_utc() - event_a.timestamp_utc()
            )

            if difference > window:
                break

            if event_a.source != event_b.source:
                flags.append(
                    TimelineFlag(
                        event_a_id=event_a.event_id,
                        event_b_id=event_b.event_id,
                        reason=(
                            "Events from different sources occurred "
                            f"within {window} of each other. "
                            "This is a timing observation, not proof "
                            "of a causal relationship."
                        ),
                    )
                )

    return flags
