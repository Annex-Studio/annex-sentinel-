
from datetime import timezone

from src.defender import parse_defender_records


def test_parses_valid_detection():
    records = [
        {
            "ThreatID": "12345",
            "InitialDetectionTime": "2026-10-19T10:30:00Z",
            "LastThreatStatusChangeTime": "2026-10-19T10:35:00Z",
            "ThreatStatusID": 2,
            "ActionSuccess": True,
            "Resources": ["file:_C:\\Temp\\sample.exe"],
        }
    ]

    events = parse_defender_records(records)

    assert len(events) == 1
    assert events[0].source == "Windows Defender"
    assert events[0].event_type == "malware_detection"
    assert events[0].timestamp.tzinfo == timezone.utc
    assert events[0].metadata["threat_id"] == "12345"


def test_skips_records_without_valid_timestamp():
    records = [{"ThreatID": "12345", "InitialDetectionTime": None}]

    assert parse_defender_records(records) == []


def test_empty_records_return_empty_list():
    assert parse_defender_records([]) == []


def test_handles_multiple_resources():
    records = [
        {
            "ThreatID": "99",
            "InitialDetectionTime": "2026-10-19T10:30:00Z",
            "Resources": ["file:C:\\a.exe", "file:C:\\b.exe"],
        }
    ]

    event = parse_defender_records(records)[0]

    assert event.affected_path == "file:C:\\a.exe"
    assert len(event.metadata["resources"]) == 2
