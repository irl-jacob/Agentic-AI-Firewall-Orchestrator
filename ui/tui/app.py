import os

from dotenv import load_dotenv
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from backend.nftables import NftablesBackend
from db.database import get_session
from services.firewall import FirewallService
from services.multi_firewall import MultiFirewallManager
from ui.tui.screens.model_selector import ModelSelectorScreen
from ui.tui.widgets.chat_pane import ChatPane
from ui.tui.widgets.rules_pane import RulesPane
from ui.tui.widgets.status_pane import StatusPane
from ui.tui.widgets.threat_pane import ThreatPane


class Header(Static):
    """Clean header with essential info only."""

    def __init__(self, service: FirewallService = None, ollama_model: str = ""):
        super().__init__()
        self.service = service
        self.ollama_model = ollama_model

    def on_mount(self) -> None:
        self._update_header()
        self.set_interval(2.0, self._update_header)

    def set_model(self, model: str) -> None:
        """Update the displayed model."""
        self.ollama_model = model
        self._update_header()

    def _update_header(self) -> None:
        mode = "DRY" if (self.service and getattr(self.service.backend, "dry_run", False)) else "LIVE"
        mode_color = "yellow" if mode == "DRY" else "green"

        model_display = self.ollama_model[:30] if self.ollama_model else "default"

        self.update(
            f" AFO  |  Model: {model_display}  |  Mode: [{mode_color}]{mode}[/]"
        )


class Footer(Static):
    """Simple footer with key shortcuts."""

    def on_mount(self) -> None:
        self.update(
            " F1:Model  F2:Rules  F3:Threats  F4:Mode  ^R:Refresh  Q:Quit"
        )


class AFOApp(App):
    """AFO - Autonomous Firewall Orchestrator TUI."""

    TITLE = "AFO"

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        dock: top;
        height: 1;
        background: $panel;
        color: $text;
        padding: 0 1;
    }

    Footer {
        dock: bottom;
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }

    StatusPane {
        dock: bottom;
        height: 1;
        background: $surface;
        padding: 0 1;
    }

    #main_area {
        height: 1fr;
    }

    ChatPane {
        width: 1fr;
        height: 100%;
        border: solid $primary;
    }

    #side_panel {
        width: 45%;
        height: 100%;
        display: none;
    }

    #side_panel.visible {
        display: block;
    }

    RulesPane {
        height: 1fr;
        border: solid $primary;
        display: none;
    }

    RulesPane.visible {
        display: block;
    }

    ThreatPane {
        height: 1fr;
        border: solid $primary;
        display: none;
    }

    ThreatPane.visible {
        display: block;
    }

    #chat_log {
        height: 1fr;
        background: $surface;
        padding: 1 2;
    }

    #thinking_indicator {
        dock: bottom;
        height: 1;
        background: $surface;
        padding: 0 2;
    }

    #chat_input {
        dock: bottom;
        height: 3;
        background: $panel;
        border: solid $primary;
        padding: 0 1;
        margin: 0 1;
    }

    #chat_input:focus {
        border: solid $accent;
    }

    #filter_input {
        dock: top;
        height: 3;
        background: $panel;
        border: solid $primary;
        padding: 0 1;
    }

    #filter_input:focus {
        border: solid $accent;
    }

    DataTable {
        height: 1fr;
        background: $surface;
    }

    DataTable > .datatable--header {
        background: $panel;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: $boost;
    }

    TabbedContent {
        height: 1fr;
    }

    TabPane {
        padding: 0;
    }

    RulePreview {
        align: center middle;
    }

    #preview_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $accent;
        width: 70;
        height: auto;
        max-height: 28;
    }

    #preview_title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
    }

    #preview_request {
        padding: 0 0 1 0;
    }

    #preview_risk {
        padding: 0 0 1 0;
    }

    #preview_command {
        background: $surface;
        border: solid $primary;
        padding: 1;
        margin: 0 0 1 0;
    }

    #preview_details {
        color: $text-muted;
        padding: 0 0 1 0;
    }

    #preview_buttons {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }

    #btn_approve {
        margin: 0 2 0 0;
        min-width: 20;
    }

    #btn_reject {
        min-width: 20;
    }

    DeleteConfirm {
        align: center middle;
    }

    #delete_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $error;
        width: 55;
        height: auto;
    }

    #delete_title {
        text-align: center;
        text-style: bold;
        color: $error;
        padding: 0 0 1 0;
    }

    #delete_text {
        padding: 0 0 1 0;
        text-align: center;
    }

    #delete_buttons {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }

    #btn_confirm_delete {
        margin: 0 2 0 0;
        min-width: 15;
    }

    #btn_cancel_delete {
        min-width: 15;
    }

    #threat_empty {
        color: $text-muted;
        text-align: center;
        padding: 2;
    }

    /* Firewall Selector Modal */
    FirewallSelector, FirewallSelectorCompact {
        align: center middle;
    }

    #firewall_selector_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $accent;
        width: 60;
        height: auto;
        max-height: 25;
    }

    #selector_title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
    }

    #selector_subtitle {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }

    #firewall_list {
        padding: 1 0;
        height: auto;
    }

    #no_firewalls {
        text-align: center;
        color: $text-muted;
        padding: 2;
    }

    .firewall_button {
        width: 100%;
        margin: 0 0 1 0;
    }

    #selector_buttons {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }

    /* Config Apply Modal */
    ConfigApplyConfirm {
        align: center middle;
    }

    #config_apply_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $accent;
        width: 70;
        height: auto;
        max-height: 30;
    }

    #config_apply_title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }

    #config_subtitle {
        padding: 0 0 1 0;
        color: $text-muted;
    }

    #config_delete, #config_add, #config_geoip, #config_domains {
        padding: 0 0 0 2;
    }

    #config_warning {
        text-align: center;
        text-style: bold;
        color: $warning;
        padding: 1 0;
    }

    #config_violation {
        color: $error;
        padding: 0 0 0 2;
    }

    #config_error {
        text-align: center;
        color: $error;
        padding: 1 0;
    }

    #config_warning_text {
        text-align: center;
        color: $warning;
        padding: 1 0;
    }

    #config_buttons {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }

    #btn_confirm_config {
        margin: 0 2 0 0;
        min-width: 15;
    }

    #btn_cancel_config {
        min-width: 15;
    }

    /* Config Remove Modal */
    ConfigRemoveConfirm {
        align: center middle;
    }

    #config_remove_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $error;
        width: 60;
        height: auto;
    }

    #config_remove_title {
        text-align: center;
        text-style: bold;
        color: $error;
        padding: 0 0 1 0;
    }

    #config_remove_warning {
        text-align: center;
        padding: 0 0 1 0;
    }

    #config_remove_error {
        text-align: center;
        color: $warning;
        padding: 1 0;
    }

    #config_remove_buttons {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }

    #btn_confirm_remove {
        margin: 0 2 0 0;
        min-width: 20;
    }

    #btn_cancel_remove {
        min-width: 15;
    }

    /* Config Result Modal */
    ConfigApplyResult, ConfigRemoveResult {
        align: center middle;
    }

    #config_result_dialog {
        padding: 1 2;
        background: $panel;
        border: solid $accent;
        width: 60;
        height: auto;
    }

    #config_result_title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
    }

    #config_result_text {
        text-align: center;
        padding: 1 0;
    }

    #btn_ok_result {
        width: 100%;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("tab", "focus_next", "Next"),
        Binding("shift+tab", "focus_previous", "Prev"),
        Binding("f1", "select_model", "Model", priority=True),
        Binding("f2", "toggle_rules", "Rules", priority=True),
        Binding("f3", "toggle_threats", "Threats", priority=True),
        Binding("f4", "toggle_mode", "Mode", priority=True),
        Binding("escape", "close_panel", "Close", priority=True),
        Binding("ctrl+r", "refresh_rules", "Refresh"),
    ]

    def __init__(self, service: FirewallService = None, ollama_model: str = "", multi_manager = None):
        super().__init__()
        self.service = service
        self.ollama_model = ollama_model
        self.multi_manager = multi_manager

    def on_mount(self) -> None:
        if not self.ollama_model:
            self.action_select_model()

    def action_select_model(self) -> None:
        def on_model_selected(model: str | None) -> None:
            if model:
                self.ollama_model = model
                os.environ["OLLAMA_MODEL"] = model
                header = self.query_one(Header)
                header.set_model(model)
                self.notify(f"Model: {model}")

        self.push_screen(ModelSelectorScreen(self.ollama_model), on_model_selected)

    def compose(self) -> ComposeResult:
        yield Header(service=self.service, ollama_model=self.ollama_model)

        with Horizontal(id="main_area"):
            yield ChatPane(service=self.service, multi_manager=self.multi_manager, id="chat_pane")

            with Vertical(id="side_panel"):
                yield RulesPane(service=self.service, id="rules_pane")
                yield ThreatPane(id="threat_pane")

        yield StatusPane(service=self.service, id="status_pane")
        yield Footer()

    def action_toggle_rules(self) -> None:
        side = self.query_one("#side_panel")
        rules = self.query_one(RulesPane)
        threats = self.query_one(ThreatPane)

        if rules.has_class("visible"):
            rules.remove_class("visible")
            if not threats.has_class("visible"):
                side.remove_class("visible")
        else:
            side.add_class("visible")
            rules.add_class("visible")
            threats.remove_class("visible")

    def action_toggle_threats(self) -> None:
        side = self.query_one("#side_panel")
        rules = self.query_one(RulesPane)
        threats = self.query_one(ThreatPane)

        if threats.has_class("visible"):
            threats.remove_class("visible")
            if not rules.has_class("visible"):
                side.remove_class("visible")
        else:
            side.add_class("visible")
            threats.add_class("visible")
            rules.remove_class("visible")

    def action_close_panel(self) -> None:
        self.query_one("#side_panel").remove_class("visible")
        self.query_one(RulesPane).remove_class("visible")
        self.query_one(ThreatPane).remove_class("visible")

    def action_focus_next(self) -> None:
        self.screen.focus_next()

    def action_focus_previous(self) -> None:
        self.screen.focus_previous()

    async def action_refresh_rules(self) -> None:
        try:
            rules_pane = self.query_one(RulesPane)
            await rules_pane.refresh_rules()
        except Exception:
            pass

    def action_toggle_mode(self) -> None:
        if not self.service:
            self.notify("No service connected", severity="error")
            return

        backend = self.service.backend
        if not hasattr(backend, 'toggle_dry_run'):
            self.notify("Backend doesn't support mode switching", severity="error")
            return

        new_mode = backend.toggle_dry_run()

        header = self.query_one(Header)
        header._update_header()

        if new_mode:
            self.notify("Switched to DRY RUN mode", severity="warning", timeout=3)
        else:
            self.notify("Switched to LIVE mode", severity="warning", timeout=3)


async def main():
    """Main entry point with model selection."""

    # Initialize database first
    from db.database import init_db
    try:
        await init_db()
        print("✓ Database initialized")
    except Exception as e:
        print(f"⚠ Database initialization warning: {e}")

    # Check if model already set in environment
    current_model = os.environ.get("OLLAMA_MODEL", "")

    # If no model selected, show selector first
    if not current_model:
        from ui.tui.screens.model_selector import select_ollama_model_async
        selected_model = await select_ollama_model_async(current_model)
        if selected_model:
            current_model = selected_model
            os.environ["OLLAMA_MODEL"] = current_model
        else:
            # User cancelled model selection
            print("No model selected. Exiting.")
            return

    # Get database session
    session_gen = get_session()
    session = await anext(session_gen)

    # Initialize multi-firewall manager
    multi_manager = MultiFirewallManager(session)

    # Configure backends based on environment variables
    backend_type = os.environ.get("AFO_BACKEND", "nftables").lower()
    force_dry_run = os.environ.get("AFO_DRY_RUN", "0") == "1"

    # Primary backend (for backward compatibility)
    primary_backend = None

    if backend_type == "opnsense":
        from backend.opnsense import OPNsenseMCPBackend
        backend = OPNsenseMCPBackend(dry_run=force_dry_run)
        try:
            await backend.connect()
            multi_manager.add_backend(
                "opnsense-primary",
                backend,
                description="Primary OPNsense Firewall",
                enabled=True
            )
            primary_backend = backend
            print("✓ OPNsense backend connected")
        except Exception as e:
            print(f"[AFO] Warning: Could not connect to OPNsense MCP: {e}")
            print("[AFO] Falling back to local nftables backend...")
            # Fallback to nftables when OPNsense is unavailable
            backend = NftablesBackend(dry_run=force_dry_run)
            multi_manager.add_backend(
                "nftables-fallback",
                backend,
                description="Local NFTables (Fallback)",
                enabled=True
            )
            primary_backend = backend
            print("✓ Fallback to nftables backend")
    else:
        backend = NftablesBackend()
        if force_dry_run:
            backend = NftablesBackend(dry_run=True)
        else:
            try:
                status = await backend.get_status()
                if "Error" in status or "Active" not in status:
                    backend = NftablesBackend(dry_run=True)
            except Exception:
                backend = NftablesBackend(dry_run=True)

        multi_manager.add_backend(
            "nftables-local",
            backend,
            description="Local nftables Firewall",
            enabled=True
        )
        primary_backend = backend
        print("✓ nftables backend initialized")

    # Add additional backends from environment (optional)
    # Format: AFO_EXTRA_BACKENDS=opnsense:host1:key1:secret1,nftables:host2
    extra_backends = os.environ.get("AFO_EXTRA_BACKENDS", "")
    if extra_backends:
        for backend_config in extra_backends.split(","):
            parts = backend_config.strip().split(":")
            if len(parts) >= 2:
                backend_name = parts[0]
                backend_host = parts[1]

                if backend_name == "opnsense" and len(parts) >= 4:
                    from backend.opnsense import OPNsenseMCPBackend
                    extra_backend = OPNsenseMCPBackend(
                        host=backend_host,
                        api_key=parts[2],
                        api_secret=parts[3],
                        dry_run=force_dry_run
                    )
                    try:
                        await extra_backend.connect()
                        multi_manager.add_backend(
                            f"opnsense-{backend_host}",
                            extra_backend,
                            description=f"OPNsense at {backend_host}",
                            enabled=True
                        )
                        print(f"✓ Additional OPNsense backend connected: {backend_host}")
                    except Exception as e:
                        print(f"⚠ Could not connect to {backend_host}: {e}")

    # Create primary service for backward compatibility
    service = FirewallService(primary_backend, session)

    # Start the rule scheduler for auto-expiring temporary rules
    from services.rule_scheduler import get_scheduler
    scheduler = get_scheduler()
    await scheduler.start()

    app = AFOApp(service=service, ollama_model=current_model, multi_manager=multi_manager)
    await app.run_async()

    # Stop scheduler on exit
    await scheduler.stop()

    # Cleanly close all backend connections
    for backend_config in multi_manager.list_backends():
        if hasattr(backend_config.backend, 'disconnect'):
            try:
                await backend_config.backend.disconnect()
            except Exception:
                pass


def sync_main():
    """Synchronous entry point for CLI with model selection."""
    import asyncio

    load_dotenv()

    # Check if model already set in environment
    current_model = os.environ.get("OLLAMA_MODEL", "")

    # If no model selected, show selector first
    if not current_model:
        from ui.tui.screens.model_selector import select_ollama_model
        selected_model = select_ollama_model(current_model)
        if selected_model:
            current_model = selected_model
            os.environ["OLLAMA_MODEL"] = current_model
        else:
            # User cancelled model selection
            print("No model selected. Exiting.")
            return

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    sync_main()
