from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input

from services.firewall import FirewallService
from ui.tui.widgets.rules_table import RulesTable


class RulesScreen(Screen):
    """Screen for managing firewall rules."""

    def __init__(self, service: FirewallService = None):
        super().__init__()
        self.service = service

    def compose(self) -> ComposeResult:
        yield Vertical(
            Input(placeholder="Filter rules...", id="filter_input"),
            RulesTable(id="rules_table"),
        )

    async def on_mount(self) -> None:
        """Load initial rules."""
        if self.service:
            try:
                # In a real app, this would be an async call
                # For Phase 2 dev, we can pass mocked service or None
                rules = await self.service.list_rules()
                table = self.query_one("#rules_table", RulesTable)
                await table.update_rules(rules)
            except Exception:
                pass  # Handle gracefully (e.g., service not connected)

    async def on_input_changed(self, message: Input.Changed) -> None:
        """Filter rules based on input."""
        # Simple client-side filter logic would go here
        # Or re-query service with filter
        pass
