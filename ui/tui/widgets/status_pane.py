from textual.widgets import Static

from services.firewall import FirewallService


class StatusPane(Static):
    """Minimal status bar with colored indicators."""

    def __init__(self, service: FirewallService = None, id: str = None):
        super().__init__(id=id)
        self.service = service

    def on_mount(self) -> None:
        self._update_status()
        self.set_interval(5.0, self._update_status)

    def _update_status(self) -> None:
        if self.service:
            dry_run = getattr(self.service.backend, "dry_run", False)
            if dry_run:
                status_text = (
                    " [on #332800] [#ffd700]DRY RUN[/] [/]"
                    "  [dim #2d333b]│[/]  [dim #4a5568]Backend:[/] [#7d8590]nftables (simulated)[/]"
                )
            else:
                status_text = (
                    " [on #002b1a] [#00ff87]CONNECTED[/] [/]"
                    "  [dim #2d333b]│[/]  [dim #4a5568]Backend:[/] [#00d4ff]nftables[/]"
                )
        else:
            status_text = (
                " [on #2b0011] [#ff3366]DISCONNECTED[/] [/]"
            )

        self.update(status_text)
