
from datetime import datetime, timedelta, timezone

from src.models import SecurityEvent
from src.timeline import build_timeline, flag_temporally_close_events


def make_event(event_id, hour, source):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(
            2026, 10, 19, hour, tzinfo=timezone.utc
        ),
        source=source,
        event_type="test_event",
        title=f"Test event {event_id}",
    )


def test_timeline_sorts_events_chronologically():
    events = [
        make_event("C", 15, "Defender"),
        make_event("A", 9, "System"),
        make_event("B", 12, "Browser"),
    ]

    result = build_timeline(events)

    assert [event.event_id for event in result] == ["A", "B", "C"]


def test_close_events_from_different_sources_are_flagged():
    events = [
        make_event("A", 10, "Defender"),
        make_event("B", 11, "System"),
    ]

    flags = flag_temporally_close_events(events)

    assert len(flags) == 1
    assert flags[0].event_a_id == "A"
    assert flags[0].event_b_id == "B"


def test_events_from_same_source_are_not_flagged():
    events = [
        make_event("A", 10, "Defender"),
        make_event("B", 11, "Defender"),
    ]

    assert flag_temporally_close_events(events) == []


def test_events_outside_window_are_not_flagged():
    events = [
        make_event("A", 9, "Defender"),
        make_event("B", 12, "System"),
    ]

    flags = flag_temporally_close_events(
        events, window=timedelta(hours=2)
    )

    assert flags == []


def test_empty_timeline_returns_empty_results():
    assert build_timeline([]) == []
    assert flag_temporally_close_events([]) == []
