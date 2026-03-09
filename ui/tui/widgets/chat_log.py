from datetime import datetime

from textual.widgets import RichLog

WELCOME_MESSAGE = """\
[bold #00d4ff]
     _    _____ ___
    / \\  |  ___|/ _ \\
   / _ \\ | |_ | | | |
  / ___ \\|  _|| |_| |
 /_/   \\_\\_|   \\___/
[/]
 [dim #4a5568]Autonomous Firewall Orchestrator[/]
 [dim #2d333b]─────────────────────────────────[/]
 [#7d8590]Type a command or question below.[/]
 [dim #4a5568]Examples:[/]
   [#00d4ff]block SSH from 10.0.0.5[/]
   [#00d4ff]open port 443[/]
   [#00d4ff]what's my network config?[/]
"""


class ChatLog(RichLog):
    """Modern chat log with aligned messages and welcome splash."""

    def on_mount(self) -> None:
        self.markup = True
        self.wrap = True
        self.write(WELCOME_MESSAGE)

    def add_message(self, role: str, content: str) -> None:
        ts = datetime.now().strftime("%H:%M")

        if role == "user":
            label = "YOU"
            visible = f"{ts}  {content}  {label} >"
            width = self.content_size.width if self.content_size.width > 0 else 80
            pad = max(0, width - len(visible))
            self.write(
                f"{' ' * pad}[dim #4a5568]{ts}[/]  [#e6edf3]{content}[/]  [on #001a2e] [bold #00d4ff]{label}[/] [/]"
            )

        elif role == "assistant":
            self.write(
                f"[on #0d1a00] [bold #00ff87]AFO[/] [/] [dim #4a5568]{ts}[/]  [#c9d1d9]{content}[/]"
            )

        elif role == "system":
            if "success" in content.lower() or "deployed" in content.lower():
                self.write(f"  [on #002b1a] [#00ff87]✓[/] [/] [#00ff87]{content}[/]")
            elif "fail" in content.lower() or "error" in content.lower():
                self.write(f"  [on #2b0011] [#ff3366]✗[/] [/] [#ff3366]{content}[/]")
            elif "deploying" in content.lower() or "approved" in content.lower():
                self.write(f"  [on #332800] [#ffd700]⟳[/] [/] [#ffd700]{content}[/]")
            elif "rejected" in content.lower():
                self.write(f"  [on #2b0011] [#ff3366]✗[/] [/] [#ff3366]{content}[/]")
            else:
                self.write(f"  [dim #4a5568]● {content}[/]")

        else:
            self.write(f"[bold #7d8590]{role}:[/] {content}")
