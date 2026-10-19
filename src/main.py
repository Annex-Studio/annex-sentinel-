
import sys
from datetime import timedelta
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.defender import collect_defender_events
from src.report import export_incident_report
from src.timeline import build_timeline, flag_temporally_close_events


class AnnexSentinelWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Annex Sentinel")
        self.resize(1100, 680)

        self.events = []
        self.flags = []

        central = QWidget()
        layout = QVBoxLayout(central)

        heading = QLabel("ANNEX SENTINEL")
        heading.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(heading)

        subtitle = QLabel(
            "Local-first security investigation | Evidence before conclusions"
        )
        layout.addWidget(subtitle)

        buttons = QHBoxLayout()

        scan_button = QPushButton("Read Defender History")
        scan_button.clicked.connect(self.load_defender_history)
        buttons.addWidget(scan_button)

        sample_button = QPushButton("Load Sample Events")
        sample_button.clicked.connect(self.load_sample_events)
        buttons.addWidget(sample_button)

        export_button = QPushButton("Export PDF Report")
        export_button.clicked.connect(self.export_report)
        buttons.addWidget(export_button)

        layout.addLayout(buttons)

        self.status_label = QLabel("No events loaded.")
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Source", "Type", "Event", "Evidence"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setWordWrap(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(
            3, self.table.horizontalHeader().ResizeMode.Stretch
        )
        layout.addWidget(self.table)

        disclaimer = QLabel(
            "Proximity flags show timing only. They do not prove that "
            "events are related or that an account was compromised."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setStyleSheet("color: #9a6b20; padding: 6px;")
        layout.addWidget(disclaimer)

        self.setCentralWidget(central)

    def show_events(self):
        ordered = build_timeline(self.events)
        self.table.setRowCount(len(ordered))

        for row, event in enumerate(ordered):
            values = [
                event.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
                event.source,
                event.event_type,
                event.title,
                event.evidence_status,
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)

        self.flags = flag_temporally_close_events(
            self.events, window=timedelta(hours=24)
        )

        self.status_label.setText(
            f"{len(self.events)} events loaded | "
            f"{len(self.flags)} temporal proximity flags"
        )

    def load_defender_history(self):
        try:
            self.events = collect_defender_events()
            self.show_events()
            QMessageBox.information(
                self,
                "Defender History",
                f"Loaded {len(self.events)} Defender detection records.",
            )
        except RuntimeError as exc:
            QMessageBox.warning(
                self,
                "Could Not Read Defender History",
                f"{exc}\n\nTry running on Windows with Microsoft Defender "
                "available. No security settings were changed.",
            )

    def load_sample_events(self):
        from datetime import datetime, timezone

        self.events = [
            __import__("src.models", fromlist=["SecurityEvent"]).SecurityEvent(
                event_id="SAMPLE-001",
                timestamp=datetime(
                    2026, 10, 19, 10, 0, tzinfo=timezone.utc
                ),
                source="Windows Defender (sample)",
                event_type="malware_detection",
                title="Synthetic malware detection example",
                details="Sample data only; not a real detection.",
                evidence_status="observed",
            ),
            __import__("src.models", fromlist=["SecurityEvent"]).SecurityEvent(
                event_id="SAMPLE-002",
                timestamp=datetime(
                    2026, 10, 19, 10, 30, tzinfo=timezone.utc
                ),
                source="System (sample)",
                event_type="system_event",
                title="Synthetic system event",
                details="Sample data only; not a real system event.",
                evidence_status="observed",
            ),
        ]
        self.show_events()

    def export_report(self):
        if not self.events:
            QMessageBox.information(
                self, "No Events", "Load Defender history or sample events first."
            )
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Incident Report",
            "annex-sentinel-report.pdf",
            "PDF files (*.pdf)",
        )
        if not filename:
            return

        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        try:
            output = export_incident_report(
                self.events, self.flags, Path(filename)
            )
            QMessageBox.information(
                self, "Report Exported", f"Saved report to:\n{output}"
            )
        except Exception as exc:
            QMessageBox.critical(
                self, "Export Failed", f"Could not export report:\n{exc}"
            )


def main():
    app = QApplication(sys.argv)
    window = AnnexSentinelWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
