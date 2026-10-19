
from datetime import datetime, timezone

import pytest

from src.models import SecurityEvent


def make_event(**overrides):
    data = {
        "event_id": "TEST-001",
        "timestamp": datetime(
            2026, 10, 19, 10, 30, tzinfo=timezone.utc
        ),
        "source": "Test",
        "event_type": "malware_detection",
        "title": "Test detection",
    }
    data.update(overrides)
    return SecurityEvent(**data)


def test_valid_event_is_created():
    event = make_event()

    assert event.event_id == "TEST-001"
    assert event.evidence_status == "observed"


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="timezone"):
        make_event(timestamp=datetime(2026, 10, 19, 10, 30))


def test_empty_title_is_rejected():
    with pytest.raises(ValueError, match="title"):
        make_event(title=" ")


def test_invalid_evidence_status_is_rejected():
    with pytest.raises(ValueError, match="evidence_status"):
        make_event(evidence_status="confirmed_by_ai")


def test_timestamp_converts_to_utc():
    event = make_event()

    assert event.timestamp_utc().tzinfo == timezone.utc
