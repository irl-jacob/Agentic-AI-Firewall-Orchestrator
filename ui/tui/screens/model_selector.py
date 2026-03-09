"""Ollama model selector overlay for AFO TUI.

Provides a modal interface to select the Ollama model before
launching the main AFO interface.
"""

import os
from typing import Optional

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def get_available_models() -> list[dict]:
    """Fetch available models from Ollama."""
    try:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        resp = httpx.get(f"{host}/api/tags", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("models", [])
            # Sort by name
            models.sort(key=lambda x: x.get("name", ""))
            return models
    except Exception:
        pass
    return []


def format_model_info(model: dict) -> str:
    """Format model info for display."""
    name = model.get("name", "unknown")
    size = model.get("size", 0)

    # Format size nicely
    if size > 1_000_000_000:
        size_str = f"{size / 1_000_000_000:.1f}GB"
    elif size > 1_000_000:
        size_str = f"{size / 1_000_000:.1f}MB"
    else:
        size_str = f"{size / 1_000:.1f}KB"

    return f"{name} [{size_str}]"


class ModelSelectorScreen(ModalScreen[Optional[str]]):
    """Modal screen for selecting Ollama model."""

    DEFAULT_CSS = """
    ModelSelectorScreen {
        align: center middle;
    }
    
    #selector_container {
        width: 80;
        height: auto;
        max-height: 35;
        background: #0d1117;
        border: round #00d4ff;
        padding: 1 2;
    }
    
    #selector_title {
        text-align: center;
        text-style: bold;
        color: #00d4ff;
        padding: 0 0 1 0;
    }
    
    #selector_subtitle {
        text-align: center;
        color: #7d8590;
        padding: 0 0 1 0;
    }
    
    #connection_status {
        text-align: center;
        padding: 0 0 1 0;
    }
    
    #connection_status.connected {
        color: #00ff87;
    }
    
    #connection_status.error {
        color: #ff3366;
    }
    
    #connection_status.warning {
        color: #ffd700;
    }
    
    #model_list {
        height: 15;
        border: round #1b2332;
        background: #06090f;
        padding: 0;
    }
    
    ListItem {
        padding: 0 1;
        color: #e6edf3;
    }
    
    ListItem:hover {
        background: #1b2332;
    }
    
    ListItem.--highlight {
        background: #003d66;
        color: #00d4ff;
    }
    
    #custom_model_container {
        height: auto;
        padding: 1 0 0 0;
    }
    
    #custom_model_label {
        color: #7d8590;
        padding: 0 0 0 0;
    }
    
    #custom_model_input {
        height: 3;
        background: #0d1117;
        color: #e6edf3;
        border: round #1b2332;
        padding: 0 1;
    }
    
    #custom_model_input:focus {
        border: round #00d4ff;
    }
    
    #button_container {
        height: 3;
        align: center middle;
        padding: 1 0 0 0;
    }
    
    #btn_select {
        background: #002b1a;
        color: #00ff87;
        border: tall #00ff87;
        margin: 0 1 0 0;
        min-width: 20;
    }
    
    #btn_select:hover {
        background: #004d33;
    }
    
    #btn_select:disabled {
        background: #1b2332;
        color: #4a5568;
        border: tall #4a5568;
    }
    
    #btn_cancel {
        background: #2b0011;
        color: #ff3366;
        border: tall #ff3366;
        margin: 0 0 0 1;
        min-width: 20;
    }
    
    #btn_cancel:hover {
        background: #4d001a;
    }
    
    #current_selection {
        text-align: center;
        color: #7d8590;
        padding: 1 0 0 0;
    }
    
    #help_text {
        text-align: center;
        color: #4a5568;
        padding: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "select", "Select"),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
    ]

    def __init__(self, current_model: str = ""):
        super().__init__()
        self.current_model = current_model or os.environ.get("OLLAMA_MODEL", "")
        self.models: list[dict] = []
        self.selected_model: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="selector_container"):
            yield Label("◈ SELECT OLLAMA MODEL", id="selector_title")
            yield Label("Choose an AI model for firewall rule generation", id="selector_subtitle")

            # Connection status
            status_label = Label("Checking Ollama connection...", id="connection_status")
            yield status_label

            # Model list
            yield ListView(id="model_list")

            # Custom model input
            with Vertical(id="custom_model_container"):
                yield Label("Or enter custom model name:", id="custom_model_label")
                yield Input(
                    placeholder="e.g., llama3.2:latest",
                    id="custom_model_input"
                )

            # Current selection display
            if self.current_model:
                yield Label(
                    f"Currently selected: [bold]{self.current_model}[/]",
                    id="current_selection"
                )

            # Buttons
            with Horizontal(id="button_container"):
                yield Button(
                    "✓ Select Model",
                    id="btn_select",
                    disabled=True
                )
                yield Button("✗ Cancel", id="btn_cancel")

            yield Label(
                "[dim]↑↓ to navigate • Enter to select • Esc to cancel[/]",
                id="help_text"
            )

    def on_mount(self) -> None:
        """Load models when screen mounts."""
        self.load_models()

    def load_models(self) -> None:
        """Fetch and display available models."""
        status = self.query_one("#connection_status", Label)
        model_list = self.query_one("#model_list", ListView)

        self.models = get_available_models()

        if not self.models:
            status.update("⚠ No models found or Ollama not running")
            status.add_class("warning")
            # Enable custom input
            self.query_one("#custom_model_input", Input).focus()
            return

        status.update(f"✓ Connected to Ollama ({len(self.models)} models available)")
        status.add_class("connected")

        # Populate list
        for model in self.models:
            display_text = format_model_info(model)
            model_list.append(ListItem(Label(display_text)))

        # Highlight current model if in list
        if self.current_model:
            for i, model in enumerate(self.models):
                if model.get("name") == self.current_model:
                    model_list.index = i
                    break

        model_list.focus()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Handle model selection from list."""
        if event.item and self.models:
            idx = self.query_one("#model_list", ListView).index
            if 0 <= idx < len(self.models):
                self.selected_model = self.models[idx].get("name")
                self.query_one("#btn_select", Button).disabled = False

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle double-click/enter on list item."""
        self.action_select()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle custom model input."""
        if event.input.id == "custom_model_input":
            value = event.value.strip()
            if value:
                self.selected_model = value
                self.query_one("#btn_select", Button).disabled = False
            else:
                # Revert to list selection if any
                list_view = self.query_one("#model_list", ListView)
                if list_view.index is not None and self.models:
                    self.selected_model = self.models[list_view.index].get("name")
                    self.query_one("#btn_select", Button).disabled = False
                else:
                    self.query_one("#btn_select", Button).disabled = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn_select":
            self.action_select()
        elif event.button.id == "btn_cancel":
            self.action_cancel()

    def action_select(self) -> None:
        """Confirm selection and dismiss."""
        # Check if custom input has value
        custom_input = self.query_one("#custom_model_input", Input)
        custom_value = custom_input.value.strip()

        if custom_value:
            self.selected_model = custom_value
        elif self.selected_model is None and self.models:
            # Use currently highlighted model
            list_view = self.query_one("#model_list", ListView)
            if list_view.index is not None:
                self.selected_model = self.models[list_view.index].get("name")

        if self.selected_model:
            self.dismiss(self.selected_model)

    def action_cancel(self) -> None:
        """Cancel and dismiss with None."""
        self.dismiss(None)

    def action_cursor_up(self) -> None:
        """Move selection up."""
        list_view = self.query_one("#model_list", ListView)
        if list_view.index is not None and list_view.index > 0:
            list_view.index -= 1
            list_view.action_cursor_up()

    def action_cursor_down(self) -> None:
        """Move selection down."""
        list_view = self.query_one("#model_list", ListView)
        if list_view.index is not None and list_view.index < len(self.models) - 1:
            list_view.index += 1
            list_view.action_cursor_down()


class ModelSelectorApp(App[Optional[str]]):
    """Standalone app for model selection."""

    CSS = """
    Screen {
        background: #06090f;
    }
    """

    def __init__(self, current_model: str = ""):
        super().__init__()
        self.current_model = current_model
        self.selected_model: str | None = None

    def on_mount(self) -> None:
        """Show model selector on mount."""
        self.push_screen(ModelSelectorScreen(self.current_model), self._on_model_selected)

    def _on_model_selected(self, model: str | None) -> None:
        """Handle model selection result."""
        self.selected_model = model
        self.exit(model)


def select_ollama_model(current_model: str = "") -> str | None:
    """Show model selector and return selected model.
    
    Args:
        current_model: Currently selected model (if any)
    
    Returns:
        Selected model name or None if cancelled
    """
    app = ModelSelectorApp(current_model=current_model)
    return app.run()


async def select_ollama_model_async(current_model: str = "") -> str | None:
    """Async version of model selector.
    
    Args:
        current_model: Currently selected model (if any)
    
    Returns:
        Selected model name or None if cancelled
    """
    app = ModelSelectorApp(current_model=current_model)
    return await app.run_async()


if __name__ == "__main__":
    # Test the selector
    selected = select_ollama_model()
    if selected:
        print(f"Selected model: {selected}")
    else:
        print("No model selected")
