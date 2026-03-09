from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from afo_daemon.detection.models import SecurityEvent


class ThreatPane(Vertical):
    """Cyberpunk-styled threat display."""

    BORDER_TITLE = "◈ THREATS"
    BORDER_SUBTITLE = "F3 to toggle"

    def compose(self) -> ComposeResult:
        yield Static(
            "[dim #4a5568]"
            "  No active threats detected\n"
            "  [dim #2d333b]Monitoring incoming traffic...[/]"
            "[/]",
            id="threat_empty",
        )
        yield DataTable(id="threat_table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Time", "Source IP", "Type", "Status", "Conf")
        # Hide table initially since there are no threats
        table.display = False

    def add_threat(self, event: SecurityEvent, status: str = "Detected") -> None:
        # Show table, hide empty state
        empty = self.query_one("#threat_empty")
        table = self.query_one(DataTable)
        empty.display = False
        table.display = True

        table.add_row(
            event.timestamp.strftime("%H:%M:%S"),
            event.source_ip,
            event.type.value,
            status,
            f"{event.confidence:.0%}",
        )
