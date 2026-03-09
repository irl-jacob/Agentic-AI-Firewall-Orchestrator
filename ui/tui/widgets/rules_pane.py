from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, TabbedContent, TabPane

from services.firewall import FirewallService
from ui.tui.widgets.history_table import HistoryTable
from ui.tui.widgets.rules_table import RulesTable


class RulesPane(Vertical):
    """Cyberpunk-styled rules pane with tabs."""

    BORDER_TITLE = "◈ RULES"
    BORDER_SUBTITLE = "F2 to toggle"

    def __init__(self, service: FirewallService = None, id: str = None):
        super().__init__(id=id)
        self.service = service

    def compose(self) -> ComposeResult:
        yield Input(placeholder="⌕ Filter rules...", id="filter_input")
        with TabbedContent("Active Rules", "Deploy History"):
            with TabPane("Active Rules", id="tab_active"):
                yield RulesTable(id="rules_table")
            with TabPane("Deploy History", id="tab_history"):
                yield HistoryTable(id="history_table")

    async def on_mount(self) -> None:
        await self.refresh_rules()

    async def refresh_rules(self) -> None:
        if self.service:
            try:
                rules = await self.service.list_rules()
                table = self.query_one("#rules_table", RulesTable)
                await table.update_rules(rules)
            except Exception:
                pass

    async def on_input_changed(self, message: Input.Changed) -> None:
        pass
