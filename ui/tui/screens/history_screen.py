from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Label, Static

from services.firewall import FirewallService
from ui.tui.widgets.history_table import HistoryTable


class RollbackConfirmation(ModalScreen):
    """Modal to confirm rollback."""

    CSS = """
    RollbackConfirmation {
        align: center middle;
    }

    #dialog {
        padding: 1 2;
        background: $surface;
        border: thick $primary;
        width: 60;
        height: auto;
    }

    #buttons {
        width: 100%;
        align: center middle;
        height: 3;
        margin-top: 1;
    }

    Button {
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Confirm Rollback", classes="title")
            yield Static("Are you sure you want to rollback the last deployment?", id="message")
            with Horizontal(id="buttons"):
                yield Button("Yes, Rollback", variant="error", id="confirm")
                yield Button("Cancel", variant="primary", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)


class HistoryScreen(Screen):
    """Screen for viewing deployment history and performing rollbacks."""

    CSS = """
    HistoryScreen {
        align: center middle;
    }

    #main_container {
        width: 90%;
        height: 90%;
        border: solid $accent;
        background: $surface;
    }

    #controls {
        height: 3;
        dock: bottom;
        padding: 0 1;
    }
    """

    def __init__(self, service: FirewallService = None):
        super().__init__()
        self.service = service

    def compose(self) -> ComposeResult:
        with Vertical(id="main_container"):
            yield Label("Deployment History", classes="title")
            yield HistoryTable(id="history_table")
            with Horizontal(id="controls"):
                yield Button("Rollback Last Change", variant="warning", id="rollback_btn")
                yield Button("Close", variant="primary", id="close_btn")

    async def on_mount(self) -> None:
        """Load history."""
        await self.refresh_history()

    async def refresh_history(self) -> None:
        if self.service:
            try:
                # We need to fetch logs.
                # Since list_logs isn't in service yet, we'll try to call it (assuming it will be added)
                # or fallback to empty list.
                if hasattr(self.service, "list_deployment_logs"):
                    logs = await self.service.list_deployment_logs()
                    table = self.query_one(HistoryTable)
                    await table.update_history(logs)
            except Exception:
                pass

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_btn":
            self.app.pop_screen()
        elif event.button.id == "rollback_btn":
            confirmed = await self.app.push_screen_wait(RollbackConfirmation())
            if confirmed:
                await self.perform_rollback()

    async def perform_rollback(self) -> None:
        if self.service:
            success = await self.service.rollback(steps=1, user="tui_user")
            if success:
                self.notify("Rollback successful.")
                await self.refresh_history()
            else:
                self.notify("Rollback failed.", severity="error")
        else:
            self.notify("Service not connected.", severity="warning")
