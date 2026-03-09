import random

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.timer import Timer
from textual.widgets import Input, Static

from backend.models import Action, Direction, PolicyRule, Protocol
from services.firewall import FirewallService
from ui.tui.widgets.chat_log import ChatLog
from ui.tui.widgets.rule_preview import RulePreview

THINKING_MESSAGES = [
    "Parsing neural input stream...",
    "Querying threat intelligence...",
    "Cross-referencing nftables ruleset...",
    "Scanning network topology...",
    "Analyzing firewall state matrix...",
    "Decrypting intent vectors...",
    "Mapping protocol signatures...",
    "Correlating packet flow data...",
    "Resolving address space...",
    "Probing interface configurations...",
    "Computing rule dependency graph...",
    "Evaluating security posture...",
    "Traversing chain hierarchy...",
    "Indexing knowledge fragments...",
    "Synthesizing response payload...",
    "Validating against safety policies...",
    "Inspecting connection states...",
    "Processing semantic tokens...",
    "Calibrating response parameters...",
    "Running conflict detection scan...",
]


class ThinkingIndicator(Static):
    """Animated thinking indicator that cycles through messages."""

    def __init__(self, **kwargs):
        super().__init__("", **kwargs)
        self._timer: Timer | None = None
        self._used: list[str] = []

    def on_mount(self) -> None:
        self.display = False

    def start(self) -> None:
        self._used = []
        self._cycle()
        self.display = True
        self._timer = self.set_interval(0.8, self._cycle)

    def stop(self) -> None:
        if self._timer:
            self._timer.stop()
            self._timer = None
        self.display = False
        self.update("")

    def _cycle(self) -> None:
        available = [m for m in THINKING_MESSAGES if m not in self._used]
        if not available:
            self._used = []
            available = THINKING_MESSAGES
        msg = random.choice(available)
        self._used.append(msg)
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        frame = frames[len(self._used) % len(frames)]
        self.update(f"  [#b44aff]{frame}[/] [dim italic #7d8590]{msg}[/]")


class ChatPane(Vertical):
    """Cyberpunk-styled chat pane with thinking indicators."""

    BORDER_TITLE = "◈ NEURAL LINK"
    BORDER_SUBTITLE = "Natural Language → Firewall Rules"

    def __init__(self, service: FirewallService = None, multi_manager = None, id: str = None):
        super().__init__(id=id)
        self.service = service
        self.multi_manager = multi_manager

    def compose(self) -> ComposeResult:
        yield ChatLog(id="chat_log")
        yield ThinkingIndicator(id="thinking_indicator")
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
        thinking = self.query_one(ThinkingIndicator)

        # ── Check for operations commands first (no LLM needed) ──
        if self.service:
            try:
                from agents.operations import handle_operation
                ops_result = await handle_operation(user_input, self.service.backend)
                if ops_result is not None:
                    log.add_message("assistant", ops_result["response"])
                    return
            except Exception as e:
                log.add_message("system", f"Operation error: {e}")
                return

        thinking.start()

        try:
            import asyncio

            from agents.firewall_agent import chat
            result = await asyncio.to_thread(chat, user_input)

        except Exception as e:
            thinking.stop()
            log.add_message("system", f"Agent error: {e}")
            return

        thinking.stop()

        # ── Handle response by type ──
        if result["type"] == "chat":
            log.add_message("assistant", result["response"])

        elif result["type"] == "rule":
            if not result.get("success", True):
                error_msg = result.get("error", "Unknown error generating rule")
                log.add_message("system", f"Error: {error_msg}")
                return

            log.add_message("assistant", result.get("explanation", "Rule generated."))

            rule_data = result["rule"]
            try:
                action_str = rule_data.get("action", "DROP").lower()
                action_map = {
                    "accept": Action.ACCEPT,
                    "allow": Action.ACCEPT,
                    "pass": Action.ACCEPT,
                    "drop": Action.DROP,
                    "deny": Action.DROP,
                    "block": Action.DROP,
                    "reject": Action.REJECT,
                }
                action = action_map.get(action_str, Action.DROP)

                direction_str = rule_data.get("chain", "input").upper()
                if direction_str == "INPUT":
                    direction = Direction.INBOUND
                elif direction_str == "OUTPUT":
                    direction = Direction.OUTBOUND
                else:
                    direction = Direction.INBOUND

                protocol_str = rule_data.get("protocol", "TCP")
                if protocol_str:
                    try:
                        protocol = Protocol(protocol_str.upper())
                    except ValueError:
                        protocol = Protocol.ANY
                else:
                    protocol = Protocol.ANY

                rule = PolicyRule(
                    id=None,
                    name=(rule_data.get("comment") or "generated_rule").replace(" ", "_")[:20],
                    description=rule_data.get("comment"),
                    action=action,
                    direction=direction,
                    protocol=protocol,
                    port=rule_data.get("port"),
                    source=rule_data.get("source"),
                    destination=rule_data.get("destination"),
                    priority=100,
                    enabled=True,
                    ttl_seconds=result.get("ttl_seconds"),
                    is_temporary=bool(result.get("ttl_seconds")),
                )

                nft_cmd = result.get("nft_command", "")

                # Debug logging for modal
                log.add_message("system", "Showing rule preview modal...")
                log.add_message("system", f"Rule: {rule.name} ({rule.action.value} {rule.protocol.value})")

                approved = False
                try:
                    # Create the modal
                    modal = RulePreview(rule, nft_command=nft_cmd)
                    log.add_message("system", "Modal created, pushing to screen...")

                    # Push the modal and wait for result
                    approved = await self.app.push_screen_wait(modal)
                    log.add_message("system", f"Modal dismissed with result: {approved}")
                except Exception as modal_error:
                    import traceback
                    error_msg = f"Modal error: {type(modal_error).__name__}: {modal_error}"
                    log.add_message("system", error_msg)
                    print(f"DEBUG: {error_msg}")
                    traceback.print_exc()
                    approved = False

                if approved:
                    log.add_message("system", "User approved rule. Deploying...")
                    if self.service:
                        thinking.start()
                        success, message = await self.service.deploy_rule(rule, user="tui_user")
                        thinking.stop()
                        if success:
                            log.add_message("system", "Rule deployed successfully.")
                            try:
                                from ui.tui.widgets.rules_pane import RulesPane
                                rules_pane = self.app.query_one(RulesPane)
                                await rules_pane.refresh_rules()
                            except Exception:
                                pass
                        else:
                            log.add_message("system", f"Deployment failed: {message}")
                    else:
                        log.add_message("system", "Service not connected (Dry Run).")
                else:
                    log.add_message("system", "User rejected rule.")

            except Exception as e:
                import traceback
                error_detail = f"Failed to parse rule: {type(e).__name__}: {e}"
                log.add_message("system", error_detail)
                # Log full traceback to console for debugging
                traceback.print_exc()

        elif result["type"] == "delete":
            if not result.get("success", True):
                error_msg = result.get("error", "Unknown error preparing deletion")
                log.add_message("system", f"Error: {error_msg}")
                return

            log.add_message("assistant", result.get("explanation", "Preparing to delete rule..."))

            rule_data = result["rule"]
            target_desc = result.get("target_description", "the specified rule")

            try:
                # Build rule object for matching
                action_str = rule_data.get("action", "DROP").lower()
                action_map = {
                    "accept": Action.ACCEPT,
                    "allow": Action.ACCEPT,
                    "pass": Action.ACCEPT,
                    "drop": Action.DROP,
                    "deny": Action.DROP,
                    "block": Action.DROP,
                    "reject": Action.REJECT,
                }
                action = action_map.get(action_str, Action.DROP)

                direction_str = rule_data.get("chain", "input").upper()
                if direction_str == "INPUT":
                    direction = Direction.INBOUND
                elif direction_str == "OUTPUT":
                    direction = Direction.OUTBOUND
                else:
                    direction = Direction.INBOUND

                protocol_str = rule_data.get("protocol", "TCP")
                if protocol_str:
                    try:
                        protocol = Protocol(protocol_str.upper())
                    except ValueError:
                        protocol = Protocol.ANY
                else:
                    protocol = Protocol.ANY

                rule = PolicyRule(
                    id=None,
                    name=(rule_data.get("comment") or "generated_rule").replace(" ", "_")[:20],
                    description=rule_data.get("comment"),
                    action=action,
                    direction=direction,
                    protocol=protocol,
                    port=rule_data.get("port"),
                    source=rule_data.get("source"),
                    destination=rule_data.get("destination"),
                    priority=100,
                    enabled=True
                )

                # Ask user to confirm deletion
                from textual.containers import Horizontal, Vertical
                from textual.screen import ModalScreen
                from textual.widgets import Static

                class DeleteConfirm(ModalScreen[bool]):
                    """Modal to confirm rule deletion."""

                    def __init__(self, target: str, **kwargs):
                        super().__init__(**kwargs)
                        self.target = target

                    def compose(self) -> ComposeResult:
                        with Vertical(id="delete_dialog"):
                            yield Static(f"Delete rule blocking {self.target}?", id="delete_title")
                            yield Static("This will remove the existing block rule from the firewall.", id="delete_text")
                            with Horizontal(id="delete_buttons"):
                                from textual.widgets import Button
                                yield Button("✓ Delete", id="btn_confirm_delete", variant="error")
                                yield Button("✗ Cancel", id="btn_cancel_delete", variant="primary")

                    def on_button_pressed(self, event) -> None:
                        if event.button.id == "btn_confirm_delete":
                            self.dismiss(True)
                        else:
                            self.dismiss(False)

                approved = await self.app.push_screen_wait(DeleteConfirm(target_desc))

                if approved:
                    log.add_message("system", f"Deleting rule for {target_desc}...")
                    if self.service:
                        thinking.start()
                        success, message = await self.service.delete_rule(rule, user="tui_user")
                        thinking.stop()
                        if success:
                            log.add_message("system", "Rule deleted successfully.")
                            try:
                                from ui.tui.widgets.rules_pane import RulesPane
                                rules_pane = self.app.query_one(RulesPane)
                                await rules_pane.refresh_rules()
                            except Exception:
                                pass
                        else:
                            log.add_message("system", f"Deletion failed: {message}")
                    else:
                        log.add_message("system", "Service not connected (Dry Run).")
                else:
                    log.add_message("system", "Deletion cancelled.")

            except Exception as e:
                log.add_message("system", f"Failed to process deletion: {e}")

        # ── Handle Phase 3 Slash Commands ──
        elif result["type"] in ["geoip_block", "geoip_allow"]:
            # GeoIP commands
            log.add_message("assistant", result.get("response", ""))

            countries = result.get("countries", [])
            country_names = result.get("country_names", [])

            if not countries:
                log.add_message("system", "No valid countries specified.")
                return

            # Ask for confirmation
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Button, Static

            class GeoIPConfirm(ModalScreen[bool]):
                def __init__(self, action: str, countries: list[str], **kwargs):
                    super().__init__(**kwargs)
                    self.action = action
                    self.countries = countries

                def compose(self) -> ComposeResult:
                    with Vertical(id="geoip_dialog"):
                        yield Static(f"{self.action} traffic from: {', '.join(self.countries)}", id="geoip_title")
                        yield Static(f"This will affect all traffic from these countries.", id="geoip_text")
                        with Horizontal(id="geoip_buttons"):
                            yield Button("✓ Confirm", id="btn_confirm_geoip", variant="primary")
                            yield Button("✗ Cancel", id="btn_cancel_geoip")

                def on_button_pressed(self, event) -> None:
                    if event.button.id == "btn_confirm_geoip":
                        self.dismiss(True)
                    else:
                        self.dismiss(False)

            action_text = "Block" if result["type"] == "geoip_block" else "Allow only"
            approved = await self.app.push_screen_wait(GeoIPConfirm(action_text, country_names))

            if approved:
                log.add_message("system", f"Executing GeoIP command for: {', '.join(country_names)}")

                if self.service:
                    thinking.start()
                    try:
                        from services.geoip import get_geoip_service
                        geoip = get_geoip_service(self.service.backend)

                        if result["type"] == "geoip_block":
                            rule_ids = await geoip.block_countries(countries)
                        else:
                            rule_ids = await geoip.allow_countries_only(countries)

                        thinking.stop()

                        if rule_ids:
                            log.add_message("system", f"✓ Created {len(rule_ids)} GeoIP rules")
                            log.add_message("system", f"Rule IDs: {', '.join(rule_ids)}")

                            # Refresh rules pane
                            try:
                                from ui.tui.widgets.rules_pane import RulesPane
                                rules_pane = self.app.query_one(RulesPane)
                                await rules_pane.refresh_rules()
                            except Exception:
                                pass
                        else:
                            log.add_message("system", "⚠️ No rules were created")
                    except Exception as e:
                        thinking.stop()
                        log.add_message("system", f"Error: {e}")
                else:
                    log.add_message("system", "Service not connected (Dry Run).")
            else:
                log.add_message("system", "GeoIP command cancelled.")

        elif result["type"] in ["domain_block", "domain_block_category", "domain_unblock"]:
            # Domain blocking commands
            log.add_message("assistant", result.get("response", ""))

            domain = result.get("domain")
            category = result.get("category")

            # Ask for confirmation
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Button, Static

            class DomainConfirm(ModalScreen[bool]):
                def __init__(self, action: str, target: str, **kwargs):
                    super().__init__(**kwargs)
                    self.action = action
                    self.target = target

                def compose(self) -> ComposeResult:
                    with Vertical(id="domain_dialog"):
                        yield Static(f"{self.action}: {self.target}", id="domain_title")
                        yield Static("This will affect DNS resolution.", id="domain_text")
                        with Horizontal(id="domain_buttons"):
                            yield Button("✓ Confirm", id="btn_confirm_domain", variant="primary")
                            yield Button("✗ Cancel", id="btn_cancel_domain")

                def on_button_pressed(self, event) -> None:
                    if event.button.id == "btn_confirm_domain":
                        self.dismiss(True)
                    else:
                        self.dismiss(False)

            if result["type"] == "domain_block":
                action_text = "Block domain"
                target = domain
            elif result["type"] == "domain_block_category":
                action_text = "Block category"
                target = category
            else:
                action_text = "Unblock domain"
                target = domain

            approved = await self.app.push_screen_wait(DomainConfirm(action_text, target))

            if approved:
                log.add_message("system", f"Executing domain command: {action_text} {target}")

                if self.service:
                    thinking.start()
                    try:
                        from services.domain_blocker import get_domain_blocker

                        blocker = get_domain_blocker(self.service.backend)

                        if result["type"] == "domain_block":
                            success = await blocker.block_domain(domain)
                            if success:
                                log.add_message("system", f"✓ Blocked domain: {domain}")
                            else:
                                log.add_message("system", f"⚠️ Failed to block domain: {domain}")

                        elif result["type"] == "domain_block_category":
                            result_data = await blocker.block_category(category)
                            if result_data["success"]:
                                log.add_message("system", f"✓ Blocked {result_data['blocked_count']} domains in category: {category}")
                            else:
                                log.add_message("system", f"⚠️ Failed to block category: {result_data.get('error', 'Unknown error')}")

                        else:  # unblock
                            success = await blocker.unblock_domain(domain)
                            if success:
                                log.add_message("system", f"✓ Unblocked domain: {domain}")
                            else:
                                log.add_message("system", f"⚠️ Failed to unblock domain: {domain}")

                        thinking.stop()

                        # Refresh rules pane
                        try:
                            from ui.tui.widgets.rules_pane import RulesPane
                            rules_pane = self.app.query_one(RulesPane)
                            await rules_pane.refresh_rules()
                        except Exception:
                            pass

                    except Exception as e:
                        thinking.stop()
                        log.add_message("system", f"Error: {e}")
                else:
                    log.add_message("system", "Service not connected (Dry Run).")
            else:
                log.add_message("system", "Domain command cancelled.")

        elif result["type"] in ["bulk_delete_port", "bulk_delete_ip", "bulk_delete_temporary"]:
            # Bulk delete commands
            log.add_message("assistant", result.get("response", ""))

            port = result.get("port")
            ip = result.get("ip")

            # Ask for confirmation
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Button, Static

            class BulkDeleteConfirm(ModalScreen[bool]):
                def __init__(self, description: str, **kwargs):
                    super().__init__(**kwargs)
                    self.description = description

                def compose(self) -> ComposeResult:
                    with Vertical(id="bulk_dialog"):
                        yield Static(f"Bulk Delete: {self.description}", id="bulk_title")
                        yield Static("⚠️ This will delete multiple rules!", id="bulk_warning")
                        with Horizontal(id="bulk_buttons"):
                            yield Button("✓ Delete All", id="btn_confirm_bulk", variant="error")
                            yield Button("✗ Cancel", id="btn_cancel_bulk")

                def on_button_pressed(self, event) -> None:
                    if event.button.id == "btn_confirm_bulk":
                        self.dismiss(True)
                    else:
                        self.dismiss(False)

            if result["type"] == "bulk_delete_port":
                desc = f"All rules for port {port}"
            elif result["type"] == "bulk_delete_ip":
                desc = f"All rules for IP {ip}"
            else:
                desc = "All temporary rules"

            approved = await self.app.push_screen_wait(BulkDeleteConfirm(desc))

            if approved:
                log.add_message("system", f"Executing bulk delete: {desc}")

                if self.service:
                    thinking.start()
                    try:
                        from services.bulk_operations import get_bulk_operations

                        bulk_ops = get_bulk_operations(self.service.backend)

                        if result["type"] == "bulk_delete_port":
                            result_data = await bulk_ops.delete_rules_by_port(port)
                        elif result["type"] == "bulk_delete_ip":
                            result_data = await bulk_ops.delete_rules_by_ip(ip)
                        else:  # bulk_delete_temporary
                            result_data = await bulk_ops.delete_temporary_rules()

                        thinking.stop()

                        if result_data.success:
                            log.add_message("system", f"✓ Deleted {result_data.succeeded} rules")
                            if result_data.failed > 0:
                                log.add_message("system", f"⚠️ Failed to delete {result_data.failed} rules")
                            if result_data.affected_rules:
                                log.add_message("system", f"Affected: {', '.join(result_data.affected_rules[:5])}")
                        else:
                            log.add_message("system", f"⚠️ Bulk delete failed")
                            if result_data.errors:
                                log.add_message("system", f"Errors: {result_data.errors[0]}")

                        # Refresh rules pane
                        try:
                            from ui.tui.widgets.rules_pane import RulesPane
                            rules_pane = self.app.query_one(RulesPane)
                            await rules_pane.refresh_rules()
                        except Exception:
                            pass

                    except Exception as e:
                        thinking.stop()
                        log.add_message("system", f"Error: {e}")
                else:
                    log.add_message("system", "Service not connected (Dry Run).")
            else:
                log.add_message("system", "Bulk delete cancelled.")

        elif result["type"] in ["bulk_enable", "bulk_disable"]:
            # Bulk enable/disable commands
            log.add_message("assistant", result.get("response", ""))
            port = result.get("port")
            action = "Enable" if result["type"] == "bulk_enable" else "Disable"

            # Ask for confirmation
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Button, Static

            class BulkActionConfirm(ModalScreen[bool]):
                def __init__(self, action: str, port: int, **kwargs):
                    super().__init__(**kwargs)
                    self.action = action
                    self.port = port

                def compose(self) -> ComposeResult:
                    with Vertical(id="bulk_action_dialog"):
                        yield Static(f"{self.action} all rules for port {self.port}", id="bulk_action_title")
                        yield Static(f"This will {self.action.lower()} multiple rules.", id="bulk_action_text")
                        with Horizontal(id="bulk_action_buttons"):
                            yield Button(f"✓ {self.action}", id="btn_confirm_action", variant="primary")
                            yield Button("✗ Cancel", id="btn_cancel_action")

                def on_button_pressed(self, event) -> None:
                    if event.button.id == "btn_confirm_action":
                        self.dismiss(True)
                    else:
                        self.dismiss(False)

            approved = await self.app.push_screen_wait(BulkActionConfirm(action, port))

            if approved:
                log.add_message("system", f"Executing: {action} all rules for port {port}")

                if self.service:
                    thinking.start()
                    try:
                        from services.bulk_operations import get_bulk_operations

                        bulk_ops = get_bulk_operations(self.service.backend)

                        if result["type"] == "bulk_enable":
                            result_data = await bulk_ops.enable_rules_by_filter(port=port)
                        else:
                            result_data = await bulk_ops.disable_rules_by_filter(port=port)

                        thinking.stop()

                        if result_data.success:
                            log.add_message("system", f"✓ {action}d {result_data.succeeded} rules")
                            if result_data.failed > 0:
                                log.add_message("system", f"⚠️ Failed to {action.lower()} {result_data.failed} rules")
                        else:
                            log.add_message("system", f"⚠️ Bulk {action.lower()} failed")

                        # Refresh rules pane
                        try:
                            from ui.tui.widgets.rules_pane import RulesPane
                            rules_pane = self.app.query_one(RulesPane)
                            await rules_pane.refresh_rules()
                        except Exception:
                            pass

                    except Exception as e:
                        thinking.stop()
                        log.add_message("system", f"Error: {e}")
                else:
                    log.add_message("system", "Service not connected (Dry Run).")
            else:
                log.add_message("system", f"Bulk {action.lower()} cancelled.")

        elif result["type"] in ["rate_stats", "rate_whitelist_add", "rate_whitelist_remove"]:
            # Rate limiter commands
            log.add_message("assistant", result.get("response", ""))

            if result["type"] == "rate_stats":
                # Show rate limiter statistics
                if self.service:
                    thinking.start()
                    try:
                        from services.rate_limiter import get_rate_limiter

                        limiter = get_rate_limiter(self.service.backend)
                        stats = limiter.get_stats()

                        thinking.stop()

                        log.add_message("system", "Rate Limiter Statistics:")
                        log.add_message("system", f"  • Enabled: {'Yes' if stats['enabled'] else 'No'}")
                        log.add_message("system", f"  • IPs Tracked: {stats['total_ips_tracked']}")
                        log.add_message("system", f"  • Blocked IPs: {stats['blocked_ips']}")
                        log.add_message("system", f"  • Whitelist Size: {stats['whitelist_size']}")
                        log.add_message("system", f"  • Max Requests/Min: {stats['config']['max_req_per_min']}")
                        log.add_message("system", f"  • Max Requests/Hour: {stats['config']['max_req_per_hour']}")
                        log.add_message("system", f"  • Block Duration: {stats['config']['block_duration']}s")

                    except Exception as e:
                        thinking.stop()
                        log.add_message("system", f"Error: {e}")
                else:
                    log.add_message("system", "Service not connected (Dry Run).")

            elif result["type"] in ["rate_whitelist_add", "rate_whitelist_remove"]:
                ip = result.get("ip")
                action = "add" if result["type"] == "rate_whitelist_add" else "remove"

                # Ask for confirmation
                from textual.containers import Horizontal, Vertical
                from textual.screen import ModalScreen
                from textual.widgets import Button, Static

                class WhitelistConfirm(ModalScreen[bool]):
                    def __init__(self, action: str, ip: str, **kwargs):
                        super().__init__(**kwargs)
                        self.action = action
                        self.ip = ip

                    def compose(self) -> ComposeResult:
                        with Vertical(id="whitelist_dialog"):
                            yield Static(f"{self.action.capitalize()} {self.ip} to/from whitelist", id="whitelist_title")
                            yield Static(f"Whitelisted IPs are never auto-blocked.", id="whitelist_text")
                            with Horizontal(id="whitelist_buttons"):
                                yield Button("✓ Confirm", id="btn_confirm_whitelist", variant="primary")
                                yield Button("✗ Cancel", id="btn_cancel_whitelist")

                    def on_button_pressed(self, event) -> None:
                        if event.button.id == "btn_confirm_whitelist":
                            self.dismiss(True)
                        else:
                            self.dismiss(False)

                approved = await self.app.push_screen_wait(WhitelistConfirm(action, ip))

                if approved:
                    if self.service:
                        thinking.start()
                        try:
                            from services.rate_limiter import get_rate_limiter

                            limiter = get_rate_limiter(self.service.backend)

                            if action == "add":
                                limiter.add_to_whitelist(ip)
                                log.add_message("system", f"✓ Added {ip} to whitelist")
                            else:
                                limiter.remove_from_whitelist(ip)
                                log.add_message("system", f"✓ Removed {ip} from whitelist")

                            thinking.stop()

                        except Exception as e:
                            thinking.stop()
                            log.add_message("system", f"Error: {e}")
                    else:
                        log.add_message("system", "Service not connected (Dry Run).")
                else:
                    log.add_message("system", "Whitelist operation cancelled.")

        elif result["type"] in ["config_list", "config_preview"]:
            # Config list/preview - just show the response
            log.add_message("assistant", result.get("response", ""))

        elif result["type"] == "config_apply":
            # Config apply command
            log.add_message("assistant", result.get("response", ""))

            preset_name = result.get("preset_name")
            if not preset_name:
                log.add_message("system", "No preset name specified.")
                return

            if not self.service:
                log.add_message("system", "Service not connected (Dry Run).")
                return

            # Get preview first
            thinking.start()
            try:
                from services.config_manager import get_config_manager
                config_mgr = get_config_manager(
                    self.service.backend,
                    self.service.session,
                    self.service.safety_enforcer
                )

                preview = await config_mgr.preview_preset(preset_name)
                thinking.stop()

                # Show confirmation modal with preview
                from textual.containers import Horizontal, Vertical
                from textual.screen import ModalScreen
                from textual.widgets import Button, Static

                class ConfigApplyConfirm(ModalScreen[bool]):
                    def __init__(self, preview_data: dict, **kwargs):
                        super().__init__(**kwargs)
                        self.preview = preview_data

                    def compose(self) -> ComposeResult:
                        with Vertical(id="config_apply_dialog"):
                            yield Static(f"Apply Preset: {self.preview['preset_name']}", id="config_apply_title")

                            if self.preview.get("has_violations"):
                                yield Static("⚠️ SAFETY VIOLATIONS DETECTED", id="config_warning")
                                for violation in self.preview.get("safety_violations", []):
                                    yield Static(f"  • {violation}", id="config_violation")
                                yield Static("This preset cannot be applied.", id="config_error")
                                yield Button("✗ Cancel", id="btn_cancel_config", variant="error")
                            else:
                                yield Static("This will:", id="config_subtitle")
                                yield Static(f"  • Delete {self.preview.get('rules_to_delete', 0)} existing rules", id="config_delete")
                                yield Static(f"  • Add {self.preview.get('rules_to_add', 0)} new rules", id="config_add")
                                if self.preview.get("geoip_blocks", 0) > 0:
                                    yield Static(f"  • Block {self.preview['geoip_blocks']} countries", id="config_geoip")
                                if self.preview.get("domain_blocks", 0) > 0:
                                    yield Static(f"  • Block {self.preview['domain_blocks']} domains", id="config_domains")
                                yield Static("⚠️ This will replace ALL existing rules!", id="config_warning_text")
                                with Horizontal(id="config_buttons"):
                                    yield Button("✓ Apply", id="btn_confirm_config", variant="primary")
                                    yield Button("✗ Cancel", id="btn_cancel_config")

                    def on_button_pressed(self, event) -> None:
                        if event.button.id == "btn_confirm_config":
                            self.dismiss(True)
                        else:
                            self.dismiss(False)

                approved = await self.app.push_screen_wait(ConfigApplyConfirm(preview))

                if not approved:
                    log.add_message("system", "Configuration apply cancelled.")
                    return

                # Apply the preset
                thinking.start()
                success, message = await config_mgr.apply_preset(preset_name, user="tui_user")
                thinking.stop()

                # Show result modal
                class ConfigApplyResult(ModalScreen[bool]):
                    def __init__(self, success: bool, message: str, **kwargs):
                        super().__init__(**kwargs)
                        self.success = success
                        self.message = message

                    def compose(self) -> ComposeResult:
                        with Vertical(id="config_result_dialog"):
                            if self.success:
                                yield Static("✓ Configuration Applied", id="config_result_title")
                                yield Static(self.message, id="config_result_text")
                            else:
                                yield Static("✗ Configuration Failed", id="config_result_title")
                                yield Static(self.message, id="config_result_text")
                            yield Button("OK", id="btn_ok_result", variant="primary")

                    def on_button_pressed(self, event) -> None:
                        self.dismiss(True)

                await self.app.push_screen_wait(ConfigApplyResult(success, message))

                if success:
                    # Refresh rules pane
                    try:
                        from ui.tui.widgets.rules_pane import RulesPane
                        rules_pane = self.app.query_one(RulesPane)
                        await rules_pane.refresh_rules()
                    except Exception:
                        pass

            except Exception as e:
                thinking.stop()
                log.add_message("system", f"Error: {e}")

        elif result["type"] == "config_remove":
            # Config remove command
            log.add_message("assistant", result.get("response", ""))

            if not self.service:
                log.add_message("system", "Service not connected (Dry Run).")
                return

            # Show confirmation modal
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Button, Static

            class ConfigRemoveConfirm(ModalScreen[bool]):
                def compose(self) -> ComposeResult:
                    with Vertical(id="config_remove_dialog"):
                        yield Static("Remove Active Configuration", id="config_remove_title")
                        yield Static("This will delete ALL firewall rules.", id="config_remove_warning")
                        yield Static("⚠️ Your firewall will have no rules after this operation!", id="config_remove_error")
                        with Horizontal(id="config_remove_buttons"):
                            yield Button("✓ Remove All Rules", id="btn_confirm_remove", variant="error")
                            yield Button("✗ Cancel", id="btn_cancel_remove")

                def on_button_pressed(self, event) -> None:
                    if event.button.id == "btn_confirm_remove":
                        self.dismiss(True)
                    else:
                        self.dismiss(False)

            approved = await self.app.push_screen_wait(ConfigRemoveConfirm())

            if not approved:
                log.add_message("system", "Configuration remove cancelled.")
                return

            # Remove the configuration
            thinking.start()
            try:
                from services.config_manager import get_config_manager
                config_mgr = get_config_manager(
                    self.service.backend,
                    self.service.session,
                    self.service.safety_enforcer
                )

                success, message = await config_mgr.remove_preset(user="tui_user")
                thinking.stop()

                # Show result modal
                class ConfigRemoveResult(ModalScreen[bool]):
                    def __init__(self, success: bool, message: str, **kwargs):
                        super().__init__(**kwargs)
                        self.success = success
                        self.message = message

                    def compose(self) -> ComposeResult:
                        with Vertical(id="config_result_dialog"):
                            if self.success:
                                yield Static("✓ Configuration Removed", id="config_result_title")
                                yield Static(self.message, id="config_result_text")
                            else:
                                yield Static("✗ Configuration Remove Failed", id="config_result_title")
                                yield Static(self.message, id="config_result_text")
                            yield Button("OK", id="btn_ok_result", variant="primary")

                    def on_button_pressed(self, event) -> None:
                        self.dismiss(True)

                await self.app.push_screen_wait(ConfigRemoveResult(success, message))

                if success:
                    # Refresh rules pane
                    try:
                        from ui.tui.widgets.rules_pane import RulesPane
                        rules_pane = self.app.query_one(RulesPane)
                        await rules_pane.refresh_rules()
                    except Exception:
                        pass

            except Exception as e:
                thinking.stop()
                log.add_message("system", f"Error: {e}")

        else:
            # Unknown response type
            log.add_message("system", f"Unknown response type: {result['type']}")
            log.add_message("assistant", result.get("response", "Command processed."))
