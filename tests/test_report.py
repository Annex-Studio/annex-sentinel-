
from datetime import datetime, timezone

from pypdf import PdfReader

from src.models import SecurityEvent
from src.report import export_incident_report


def test_report_is_created_and_contains_limitations(tmp_path):
    event = SecurityEvent(
        event_id="TEST-001",
        timestamp=datetime(2026, 10, 19, 10, 30, tzinfo=timezone.utc),
        source="Test",
        event_type="test_event",
        title="Synthetic test event",
    )

    output = tmp_path / "incident-report.pdf"
    result = export_incident_report([event], [], output)

    assert result.exists()
    assert result.stat().st_size > 0

    reader = PdfReader(str(result))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert "Annex Sentinel" in text
    assert "Synthetic test event" in text
    assert "Limitations" in text
    assert "not necessarily related" in text
