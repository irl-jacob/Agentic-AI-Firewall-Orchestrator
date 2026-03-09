from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from backend.models import Action, PolicyRule


def _risk_level(rule: PolicyRule) -> tuple[str, str, str]:
    """Assess risk level of a rule. Returns (label, color, bar)."""
    if rule.action in (Action.DROP, Action.REJECT):
        if not rule.source and not rule.destination:
            return "CRITICAL", "#ff3366", "█████"
        if not rule.source or not rule.destination:
            return "HIGH", "#ff6b35", "████░"
        if rule.port in (22, 443, 80, 53):
            return "HIGH", "#ff6b35", "████░"
        return "MEDIUM", "#ffd700", "███░░"
    return "LOW", "#00ff87", "██░░░"


class RulePreview(ModalScreen):
    """Modern rule review modal."""

    DEFAULT_CSS = """
    RulePreview {
        align: center middle;
    }
    """

    def __init__(self, rule: PolicyRule, nft_command: str = ""):
        super().__init__()
        self.rule = rule
        self.nft_command = nft_command

    def on_mount(self) -> None:
        """Ensure modal is properly focused when shown."""
        try:
            approve_button = self.query_one("#btn_approve", Button)
            self.set_focus(approve_button)
        except Exception:
            # If button not found, focus the dialog itself
            dialog = self.query_one("#preview_dialog")
            if dialog:
                self.set_focus(dialog)

    def compose(self) -> ComposeResult:
        risk_label, risk_color, risk_bar = _risk_level(self.rule)

        if self.nft_command:
            nft_display = self.nft_command
        else:
            parts = ["nft add rule inet filter"]
            chain = "input" if self.rule.direction.value == "INBOUND" else "output"
            parts.append(chain)
            if self.rule.source:
                parts.append(f"ip saddr {self.rule.source}")
            if self.rule.destination:
                parts.append(f"ip daddr {self.rule.destination}")
            if self.rule.protocol.value != "ANY":
                parts.append(self.rule.protocol.value.lower())
            if self.rule.port:
                parts.append(f"dport {self.rule.port}")
            parts.append(self.rule.action.value.lower())
            nft_display = " ".join(parts)

        details_lines = []
        details_lines.append(f"[#4a5568]Action:[/]     [bold #e6edf3]{self.rule.action.value}[/]")
        details_lines.append(f"[#4a5568]Direction:[/]  [#c9d1d9]{self.rule.direction.value}[/]")
        details_lines.append(f"[#4a5568]Protocol:[/]   [#c9d1d9]{self.rule.protocol.value}[/]")
        details_lines.append(f"[#4a5568]Port:[/]       [#c9d1d9]{self.rule.port or 'Any'}[/]")
        details_lines.append(f"[#4a5568]Source:[/]     [#c9d1d9]{self.rule.source or 'Any'}[/]")
        details_lines.append(f"[#4a5568]Dest:[/]       [#c9d1d9]{self.rule.destination or 'Any'}[/]")

        with Vertical(id="preview_dialog"):
            yield Static(
                "⚠  Review Firewall Rule Change",
                id="preview_title",
            )

            yield Static(
                f"[#7d8590]Request:[/] [bold #e6edf3]{self.rule.description or self.rule.name}[/]",
                id="preview_request",
            )

            yield Static(
                f"[#7d8590]Risk:[/]  [{risk_color}]{risk_bar}[/]  "
                f"[bold {risk_color}]{risk_label}[/]",
                id="preview_risk",
            )

            yield Static("\n".join(details_lines), id="preview_details")

            yield Static(nft_display, id="preview_command")

            with Horizontal(id="preview_buttons"):
                yield Button(
                    "✓ Approve & Deploy",
                    variant="success",
                    id="btn_approve",
                )
                yield Button(
                    "✗ Reject",
                    variant="error",
                    id="btn_reject",
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses with proper logging."""
        button_id = event.button.id
        print(f"DEBUG: Button pressed - ID: {button_id}")
        if button_id == "btn_approve":
            print("DEBUG: Approving rule")
            self.dismiss(True)
        elif button_id == "btn_reject":
            print("DEBUG: Rejecting rule via button")
            self.dismiss(False)
        else:
            # Unknown button - log and default to reject
            print(f"DEBUG: Unknown button pressed: {button_id}, rejecting")
            self.dismiss(False)

    def key_escape(self, event) -> None:
        """Handle escape key - reject the rule."""
        print("DEBUG: Escape key pressed, rejecting rule")
        self.dismiss(False)
