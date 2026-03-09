"""Firewall selector modal for choosing deployment targets."""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, Static

from services.multi_firewall import MultiFirewallManager


class FirewallSelector(ModalScreen[list[str]]):
    """Modal to select which firewall(s) to deploy a rule to."""

    def __init__(self, manager: MultiFirewallManager, **kwargs):
        super().__init__(**kwargs)
        self.manager = manager
        self.checkboxes: dict[str, Checkbox] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="firewall_selector_dialog"):
            yield Static("Select Firewall Target(s)", id="selector_title")
            yield Static(
                "Choose which firewall(s) to deploy this rule to:",
                id="selector_subtitle"
            )

            with Vertical(id="firewall_list"):
                backends = self.manager.list_backends()
                if not backends:
                    yield Label("No firewalls configured", id="no_firewalls")
                else:
                    for backend_config in backends:
                        checkbox = Checkbox(
                            f"{backend_config.name} - {backend_config.description or 'No description'}",
                            value=True,  # Default to selected
                            id=f"cb_{backend_config.name}"
                        )
                        self.checkboxes[backend_config.name] = checkbox
                        yield checkbox

            with Horizontal(id="selector_buttons"):
                yield Button("Deploy", id="btn_deploy", variant="primary")
                yield Button("Cancel", id="btn_cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_deploy":
            # Get selected backends
            selected = [
                name for name, cb in self.checkboxes.items()
                if cb.value
            ]
            self.dismiss(selected)
        else:
            self.dismiss([])


class FirewallSelectorCompact(ModalScreen[str]):
    """Compact modal for selecting a single firewall (for simpler UX)."""

    def __init__(self, manager: MultiFirewallManager, **kwargs):
        super().__init__(**kwargs)
        self.manager = manager

    def compose(self) -> ComposeResult:
        with Vertical(id="firewall_selector_dialog"):
            yield Static("Select Firewall", id="selector_title")

            backends = self.manager.list_backends()
            if not backends:
                yield Label("No firewalls configured", id="no_firewalls")
                with Horizontal(id="selector_buttons"):
                    yield Button("OK", id="btn_ok", variant="primary")
            else:
                for backend_config in backends:
                    yield Button(
                        f"{backend_config.name}\n{backend_config.description or ''}",
                        id=f"btn_{backend_config.name}",
                        classes="firewall_button"
                    )

                with Horizontal(id="selector_buttons"):
                    yield Button("Cancel", id="btn_cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_cancel" or event.button.id == "btn_ok":
            self.dismiss("")
        elif event.button.id.startswith("btn_"):
            # Extract backend name from button id
            backend_name = event.button.id[4:]  # Remove "btn_" prefix
            self.dismiss(backend_name)
