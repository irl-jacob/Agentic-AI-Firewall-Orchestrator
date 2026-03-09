from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input

from backend.models import Action, Direction, PolicyRule, Protocol
from services.firewall import FirewallService
from ui.tui.widgets.chat_log import ChatLog
from ui.tui.widgets.rule_preview import RulePreview


class ChatScreen(Screen):
    """Standalone chat screen (legacy, kept for compatibility)."""

    def __init__(self, service: FirewallService = None):
        super().__init__()
        self.service = service

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ChatLog(id="chat_log")
            yield Input(placeholder="› Enter command...", id="chat_input")

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        user_input = message.value
        if not user_input.strip():
            return

        log = self.query_one(ChatLog)
        log.add_message("user", user_input)
        self.query_one(Input).value = ""

        self.run_worker(self._handle_chat(user_input))

    async def _handle_chat(self, user_input: str) -> None:
        log = self.query_one(ChatLog)

        try:
            import asyncio

            from agents.firewall_agent import chat
            result = await asyncio.to_thread(chat, user_input)
        except Exception as e:
            log.add_message("system", f"Agent error: {e}")
            return

        if result["type"] == "chat":
            log.add_message("assistant", result["response"])

        elif result["type"] == "rule":
            if not result.get("success", True):
                log.add_message("system", f"Error: {result.get('error', 'Unknown')}")
                return

            log.add_message("assistant", result.get("explanation", "Rule generated."))

            rule_data = result["rule"]
            try:
                action_str = rule_data.get("action", "DROP").lower()
                action_map = {
                    "accept": Action.ACCEPT, "allow": Action.ACCEPT, "pass": Action.ACCEPT,
                    "drop": Action.DROP, "deny": Action.DROP, "block": Action.DROP,
                    "reject": Action.REJECT,
                }
                action = action_map.get(action_str, Action.DROP)

                direction_str = rule_data.get("chain", "input").upper()
                direction = Direction.INBOUND if direction_str != "OUTPUT" else Direction.OUTBOUND

                protocol_str = rule_data.get("protocol", "TCP")
                try:
                    protocol = Protocol(protocol_str.upper()) if protocol_str else Protocol.ANY
                except ValueError:
                    protocol = Protocol.ANY

                rule = PolicyRule(
                    name=(rule_data.get("comment") or "generated_rule").replace(" ", "_")[:20],
                    description=rule_data.get("comment"),
                    action=action,
                    direction=direction,
                    protocol=protocol,
                    port=rule_data.get("port"),
                    source=rule_data.get("source"),
                    destination=rule_data.get("destination"),
                    priority=100,
                )

                nft_cmd = result.get("nft_command", "")
                approved = await self.app.push_screen_wait(RulePreview(rule, nft_command=nft_cmd))

                if approved:
                    log.add_message("system", "User approved rule. Deploying...")
                    if self.service:
                        success, message = await self.service.deploy_rule(rule, user="tui_user")
                        if success:
                            log.add_message("system", "Rule deployed successfully.")
                        else:
                            log.add_message("system", f"Deployment failed: {message}")
                    else:
                        log.add_message("system", "Service not connected (Dry Run).")
                else:
                    log.add_message("system", "User rejected rule.")

            except Exception as e:
                log.add_message("system", f"Failed to parse rule: {e}")
