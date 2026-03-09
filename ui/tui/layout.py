from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Footer, Header, Placeholder


class ChatPane(Container):
    """Pane for natural language interaction."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Placeholder("Chat Interface", id="chat_placeholder")


class RulesPane(Container):
    """Pane for displaying and managing firewall rules."""

    def compose(self) -> ComposeResult:
        yield Placeholder("Rules Table", id="rules_placeholder")


class StatusPane(Container):
    """Pane for showing system status."""

    def compose(self) -> ComposeResult:
        yield Placeholder("System Status", id="status_placeholder")


class MainLayout(Container):
    """The main layout of the application."""

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal():
            with Vertical(id="left_pane"):
                yield ChatPane(id="chat_pane")
                yield StatusPane(id="status_pane")

            with Vertical(id="right_pane"):
                yield RulesPane(id="rules_pane")

        yield Footer()
