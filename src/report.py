
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from src.models import SecurityEvent
from src.timeline import TimelineFlag, build_timeline


def export_incident_report(
    events: list[SecurityEvent],
    flags: list[TimelineFlag],
    output_path: str | Path,
) -> Path:
    """Export an evidence-focused incident report as a PDF."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    story = [
        Paragraph("Annex Sentinel", styles["Title"]),
        Paragraph("Security Incident Report", styles["Heading2"]),
        Paragraph(
            f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
            styles["Normal"],
        ),
        Spacer(1, 8 * mm),
        Paragraph("1. Summary", styles["Heading1"]),
        Paragraph(f"Recorded events: {len(events)}", styles["Normal"]),
        Paragraph(f"Temporal proximity flags: {len(flags)}", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("2. Event Timeline", styles["Heading1"]),
    ]

    ordered = build_timeline(events)

    table_data = [["Timestamp", "Source", "Event", "Evidence status"]]
    for event in ordered:
        table_data.append([
            event.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
            event.source,
            event.title,
            event.evidence_status,
        ])

    if len(table_data) == 1:
        table_data.append(["—", "—", "No events recorded", "—"])

    table = Table(
        table_data,
        colWidths=[38 * mm, 32 * mm, 68 * mm, 28 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263746")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Spacer(1, 7 * mm)])

    story.append(Paragraph("3. Temporal Proximity Flags", styles["Heading1"]))

    if flags:
        for flag in flags:
            story.append(Paragraph(
                f"{flag.event_a_id} ↔ {flag.event_b_id}",
                styles["Heading3"],
            ))
            story.append(Paragraph(flag.reason, styles["BodyText"]))
            story.append(Spacer(1, 3 * mm))
    else:
        story.append(Paragraph("No temporal proximity flags were generated.", styles["Normal"]))

    story.extend([
        Spacer(1, 5 * mm),
        Paragraph("4. Limitations", styles["Heading1"]),
        Paragraph(
            "This report summarizes the records supplied to Annex Sentinel. "
            "Missing events do not prove that no incident occurred. Events "
            "close together in time are not necessarily related. A Defender "
            "detection does not by itself prove execution, account compromise, "
            "or causation. Validate findings with the relevant system or "
            "service and preserve original evidence.",
            styles["BodyText"],
        ),
    ])

    document.build(story)
    return path
