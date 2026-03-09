"""OPNsense backend using the opnsense-mcp-server for full firewall management."""

import json
import logging
import os
import shutil
import warnings

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol

logger = logging.getLogger(__name__)


class OPNsenseMCPBackend(FirewallBackend):
    """OPNsense firewall backend via the opnsense-mcp-server (MCP protocol).

    Launches the opnsense-mcp-server as a subprocess and communicates
    via MCP (Model Context Protocol) over stdio.  Provides 50+ tools
    for firewall, NAT, routing, VLAN, DNS, HAProxy, and more.

    Lifecycle
    ---------
    Call ``await backend.connect()`` once at startup (e.g. inside
    FirewallService.setup()) and ``await backend.disconnect()`` on
    shutdown.  All ``_call_tool`` calls share the same persistent
    Node.js process and authenticated OPNsense session.
    """

    def __init__(
        self,
        host: str | None = None,
        api_key: str | None = None,
        api_secret: str | None = None,
        verify_ssl: bool = False,
        interface: str | None = None,
        dry_run: bool = False,
        ssh_host: str | None = None,
        ssh_username: str | None = None,
        ssh_password: str | None = None,
        ssh_key_path: str | None = None,
    ):
        super().__init__()
        self.dry_run = dry_run
        # Read interface from parameter, environment, or default to "lan"
        self.interface = interface or os.environ.get("OPNSENSE_INTERFACE", "lan")

        # Build environment for the MCP server process
        self._env = {
            "OPNSENSE_HOST": host or os.environ.get("OPNSENSE_HOST", ""),
            "OPNSENSE_API_KEY": api_key or os.environ.get("OPNSENSE_API_KEY", ""),
            "OPNSENSE_API_SECRET": api_secret or os.environ.get("OPNSENSE_API_SECRET", ""),
            "OPNSENSE_VERIFY_SSL": str(verify_ssl).lower(),
        }

        # Optional SSH credentials for advanced features (NAT, CLI)
        ssh_host = ssh_host or os.environ.get("OPNSENSE_SSH_HOST", "")
        if ssh_host:
            self._env["OPNSENSE_SSH_HOST"] = ssh_host
            self._env["OPNSENSE_SSH_USERNAME"] = ssh_username or os.environ.get("OPNSENSE_SSH_USERNAME", "root")
            if ssh_password or os.environ.get("OPNSENSE_SSH_PASSWORD"):
                self._env["OPNSENSE_SSH_PASSWORD"] = ssh_password or os.environ.get("OPNSENSE_SSH_PASSWORD", "")
            if ssh_key_path or os.environ.get("OPNSENSE_SSH_KEY_PATH"):
                self._env["OPNSENSE_SSH_KEY_PATH"] = ssh_key_path or os.environ.get("OPNSENSE_SSH_KEY_PATH", "")

        # Resolve the MCP server command
        self._server_cmd = self._find_server_cmd()

        # Persistent session (lazy-initialized via connect())
        self._session: ClientSession | None = None
        self._stdio_ctx = None
        self._session_ctx = None

    @staticmethod
    def _find_server_cmd() -> str:
        """Find the opnsense-mcp-server binary."""
        # Check common install locations
        candidates = [
            os.path.expanduser("~/.local/bin/opnsense-mcp-server"),
            "/usr/local/bin/opnsense-mcp-server",
            shutil.which("opnsense-mcp-server") or "",
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        raise FileNotFoundError(
            "opnsense-mcp-server not found. Install with: npm install -g opnsense-mcp-server"
        )

    # ── Session lifecycle ─────────────────────────────────────────

    async def connect(self) -> None:
        """Open and initialise a persistent MCP session to OPNsense.

        Should be called once at application startup.  Subsequent
        connect() calls are no-ops if already connected.
        """
        if self._session is not None:
            return  # already connected

        server_params = StdioServerParameters(
            command="node",
            args=[self._server_cmd],
            env={**os.environ, **self._env},
        )
        # Enter the transport first so we can always clean it up on failure.
        self._stdio_ctx = stdio_client(server_params)
        read, write = await self._stdio_ctx.__aenter__()
        try:
            self._session_ctx = ClientSession(read, write)
            self._session = await self._session_ctx.__aenter__()
            # MCP handshake — may raise; clean up both contexts if so
            await self._session.initialize()
            logger.info("opnsense_mcp_session_opened")
        except Exception as exc:
            # Tear down in reverse order to avoid leaking the Node.js process
            try:
                if self._session_ctx is not None:
                    await self._session_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            try:
                await self._stdio_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None
            self._session_ctx = None
            self._stdio_ctx = None
            logger.error("opnsense_mcp_connect_failed", error=str(exc))
            raise

    async def disconnect(self) -> None:
        """Close the persistent MCP session and terminate the Node.js process."""
        session_ctx, stdio_ctx = self._session_ctx, self._stdio_ctx
        self._session = None
        self._session_ctx = None
        self._stdio_ctx = None
        try:
            if session_ctx is not None:
                await session_ctx.__aexit__(None, None, None)
        except Exception as exc:
            logger.warning("opnsense_mcp_session_exit_error", error=str(exc))
        finally:
            # Always attempt to kill the Node.js subprocess
            try:
                if stdio_ctx is not None:
                    await stdio_ctx.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("opnsense_mcp_stdio_exit_error", error=str(exc))
        logger.info("opnsense_mcp_session_closed")

    @asynccontextmanager
    async def session_scope(self):
        """Async context manager: connect on enter, disconnect on exit.

        Useful for short-lived scripts or tests that don't have an
        explicit startup/shutdown lifecycle::

            async with backend.session_scope():
                await backend.list_rules()
        """
        await self.connect()
        try:
            yield self
        finally:
            await self.disconnect()

    # ── Internal helpers ──────────────────────────────────────────

    async def _call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call an MCP tool on the persistent session and return parsed result."""
        from backend.mcp_retry import retry_with_backoff, translate_mcp_error, MCPHealthMonitor

        if self._session is None:
            warnings.warn(
                "_call_tool() called without an active session. "
                "Call await backend.connect() first.",
                stacklevel=2,
            )
            # Fallback: open a one-shot session so older code paths still work
            server_params = StdioServerParameters(
                command="node",
                args=[self._server_cmd],
                env={**os.environ, **self._env},
            )
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(name, arguments or {})
                    if result and result.content:
                        text = result.content[0].text
                        try:
                            return json.loads(text)
                        except (json.JSONDecodeError, TypeError):
                            return {"text": text}
                    return {}

        # Use persistent session with retry logic
        @retry_with_backoff(max_retries=3)
        async def _call_with_retry():
            try:
                result = await self._session.call_tool(name, arguments or {})
                if result and result.content:
                    text = result.content[0].text
                    try:
                        return json.loads(text)
                    except (json.JSONDecodeError, TypeError):
                        return {"text": text}
                return {}
            except Exception as e:
                # Translate error to user-friendly message
                user_message = translate_mcp_error(e)
                logger.error(f"MCP tool call failed: {name} - {user_message}")
                raise RuntimeError(user_message) from e

        return await _call_with_retry()

        result = await self._session.call_tool(name, arguments or {})
        # MCP returns a list of content blocks; extract text
        if result and result.content:
            text = result.content[0].text
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return {"text": text}
        return {}

    async def _apply_firewall_rules(self) -> None:
        """Activate staged firewall rule changes in OPNsense.

        OPNsense uses a two-phase commit model: a create/delete call
        *stages* the change, and an explicit apply call *activates* it.
        The tool name varies across MCP server versions, so we probe
        in order of preference and fall back gracefully.

        Raises
        ------
        RuntimeError
            If none of the apply tools succeed, so that the caller can
            surface the failure rather than silently returning True.
        """
        apply_tools = [
            "apply_firewall_rules",
            "firewall_apply",
            "reconfigure_firewall",
            "cli_apply_changes",
        ]
        last_error: str = "unknown"
        for tool_name in apply_tools:
            try:
                result = await self._call_tool(tool_name)
                if not result.get("error"):
                    logger.info("firewall_rules_applied", via=tool_name)
                    return
                last_error = str(result.get("error", "unknown"))
                logger.debug("apply_tool_returned_error", tool=tool_name, result=result)
            except Exception as exc:
                last_error = str(exc)
                logger.debug("apply_tool_failed", tool=tool_name, error=last_error)

        raise RuntimeError(
            f"All OPNsense apply tools failed — rule was staged but is NOT active. "
            f"Last error: {last_error}. Check Firewall → Automation → Filter to confirm."
        )

    # ── FirewallBackend interface ─────────────────────────────────

    async def list_rules(self) -> list[PolicyRule]:
        """List all firewall rules from OPNsense.

        NOTE: Rules created via the OPNsense Filter API (and therefore
        by AFO) are stored under **Firewall → Automation → Filter** in
        the OPNsense web UI, *not* under Firewall → Rules → WAN/LAN.
        The WAN/LAN rule pages show only manually created rules.
        """
        try:
            data = await self._call_tool("list_firewall_rules")
        except Exception as e:
            logger.error(f"list_rules failed: {e}")
            return []

        rules = []
        if isinstance(data, list):
            items = data
        else:
            items = data.get("rules", data.get("rows", []))

        for item in items:
            try:
                # Map OPNsense action to PolicyRule action
                action_str = str(item.get("action", "block")).lower()
                if action_str in ("pass", "accept", "allow"):
                    action = Action.ACCEPT
                elif action_str == "reject":
                    action = Action.REJECT
                else:
                    action = Action.DROP

                # Map direction
                dir_str = str(item.get("direction", "in")).lower()
                direction = Direction.OUTBOUND if dir_str == "out" else Direction.INBOUND

                # Map protocol
                proto_str = str(item.get("protocol", "any")).upper()
                try:
                    protocol = Protocol(proto_str)
                except ValueError:
                    protocol = Protocol.ANY

                # Parse port
                port_str = item.get("destination_port") or item.get("destinationPort") or item.get("port")
                port = None
                if port_str:
                    try:
                        port = int(str(port_str).split("-")[0].split(",")[0])
                    except (ValueError, IndexError):
                        pass

                rules.append(PolicyRule(
                    id=item.get("uuid") or item.get("id"),
                    name=item.get("description") or item.get("name") or "unnamed",
                    description=item.get("description"),
                    action=action,
                    direction=direction,
                    protocol=protocol,
                    source=item.get("source") or item.get("source_net"),
                    destination=item.get("destination") or item.get("destination_net"),
                    port=port,
                    enabled=item.get("enabled", True),
                ))
            except Exception as e:
                logger.warning(f"Skipping unparseable rule: {e}")
                continue

        return rules

    async def validate_rule(self, rule: PolicyRule) -> bool:
        """Validate rule (basic local checks)."""
        return bool(rule.action and rule.direction)

    async def deploy_rule(self, rule: PolicyRule) -> bool:
        """Create a firewall rule on OPNsense via MCP.

        The rule is staged via ``create_firewall_rule`` and then
        activated in the same session via ``_apply_firewall_rules()``.
        It will appear under **Firewall → Automation → Filter** in the
        OPNsense web UI.
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create rule: {rule.name}")
            return True

        # Check if session is connected
        if self._session is None:
            error_msg = "OPNsense backend not connected. Run 'await backend.connect()' first or check OPNsense connectivity."
            logger.error("deploy_rule_no_session", rule_name=rule.name)
            raise RuntimeError(error_msg)

        args = {
            "action": "pass" if rule.action == Action.ACCEPT else (
                "reject" if rule.action == Action.REJECT else "block"
            ),
            "interface": self.interface,
            "direction": "out" if rule.direction == Direction.OUTBOUND else "in",
            "protocol": rule.protocol.value.lower() if rule.protocol != Protocol.ANY else "any",
            "source": rule.source or "any",
            "destination": rule.destination or "any",
            "description": rule.description or rule.name,
            "enabled": rule.enabled,
        }

        if rule.port:
            args["destinationPort"] = str(rule.port)

        try:
            result = await self._call_tool("create_firewall_rule", args)
            if result.get("error"):
                error_msg = f"OPNsense API error: {result['error']}"
                logger.error("create_firewall_rule_error", error=result['error'], rule_name=rule.name)
                raise RuntimeError(error_msg)

            # Activate the staged rule — same session, same process
            await self._apply_firewall_rules()

            # Store the UUID on the rule for future reference
            uuid = result.get("uuid") or result.get("id")
            if uuid and rule.id is None:
                rule.id = uuid

            logger.info(f"Rule '{rule.name}' deployed on OPNsense (uuid={uuid})")
            return True
        except RuntimeError:
            # Re-raise RuntimeError with clear message
            raise
        except Exception as e:
            error_msg = f"OPNsense deployment failed: {str(e)}"
            logger.error("deploy_rule_exception", error=str(e), rule_name=rule.name)
            raise RuntimeError(error_msg) from e

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule by UUID."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete rule: {rule_id}")
            return True

        # Check if session is connected
        if self._session is None:
            error_msg = "OPNsense backend not connected. Cannot delete rule."
            logger.error("delete_rule_no_session", rule_id=rule_id)
            raise RuntimeError(error_msg)

        try:
            result = await self._call_tool("delete_firewall_rule", {"uuid": rule_id})
            if result.get("error"):
                error_msg = f"OPNsense API error: {result['error']}"
                logger.error("delete_firewall_rule_error", error=result['error'], rule_id=rule_id)
                raise RuntimeError(error_msg)

            # Activate the deletion — same session, same process
            await self._apply_firewall_rules()
            logger.info(f"Rule {rule_id} deleted from OPNsense")
            return True
        except RuntimeError:
            raise
        except Exception as e:
            error_msg = f"OPNsense delete failed: {str(e)}"
            logger.error("delete_rule_exception", error=str(e), rule_id=rule_id)
            raise RuntimeError(error_msg) from e

    async def rollback(self, steps: int = 1) -> bool:
        """Rollback not supported on OPNsense (no built-in versioning)."""
        logger.warning("rollback_not_supported", backend="opnsense")
        raise NotImplementedError("OPNsense does not support automatic rollback. Use snapshots via the web UI.")

    async def get_status(self) -> str:
        """Check connection to OPNsense."""
        if self.dry_run:
            return "Active (Dry Run)"

        # Check if session is connected
        if self._session is None:
            return "Disconnected - OPNsense backend not connected"

        try:
            result = await self._call_tool("test_connection")
            if result.get("connected") or result.get("status") == "connected" or result.get("success"):
                return "Active - Connected to OPNsense"
            return f"Connection issue: {result.get('text', result)}"
        except Exception as e:
            return f"Error: {e}"

    # ── Extended MCP tools (beyond base interface) ────────────────

    async def get_interfaces(self) -> dict:
        """Get OPNsense network interfaces."""
        return await self._call_tool("get_interfaces")

    async def get_arp_table(self) -> dict:
        """Get ARP table entries."""
        return await self._call_tool("get_arp_stats")

    async def routing_diagnostics(self, source: str, dest: str) -> dict:
        """Run routing diagnostics between networks."""
        return await self._call_tool("routing_diagnostics", {
            "sourceNetwork": source,
            "destNetwork": dest,
        })

    async def ssh_execute(self, command: str) -> dict:
        """Execute a CLI command on OPNsense via SSH."""
        return await self._call_tool("ssh_execute", {"command": command})

    async def create_backup(self) -> dict:
        """Create a configuration backup."""
        return await self._call_tool("create_backup")

    async def list_vlans(self) -> dict:
        """List configured VLANs."""
        return await self._call_tool("list_vlans")

    async def nat_list_outbound(self) -> dict:
        """List outbound NAT rules."""
        return await self._call_tool("nat_list_outbound")

    async def nat_fix_dmz(self, dmz_network: str, lan_network: str) -> dict:
        """Auto-fix DMZ NAT issues."""
        return await self._call_tool("nat_fix_dmz", {
            "dmzNetwork": dmz_network,
            "lanNetwork": lan_network,
        })

    async def list_dhcp_leases(self) -> dict:
        """List DHCP leases."""
        return await self._call_tool("list_dhcp_leases")

    async def block_domain(self, domain: str) -> tuple[bool, str]:
        """Block a domain via DNS blocklist."""
        result = await self._call_tool("block_domain", {"domain": domain})
        if isinstance(result, dict):
            success = result.get("success", False)
            message = result.get("message", "Domain blocked")
            return success, message
        return False, "Invalid response from backend"

    async def create_host_alias(self, name: str, hostname: str, description: str = "") -> tuple[bool, str]:
        """
        Create a host alias in OPNsense for domain blocking.

        Args:
            name: Alias name (e.g., "domain_block_google_com")
            hostname: Hostname to resolve (e.g., "google.com")
            description: Optional description

        Returns:
            Tuple of (success, message)
        """
        try:
            # Try MCP tool first
            try:
                result = await self._call_tool("create_alias", {
                    "name": name,
                    "type": "host",
                    "content": hostname,
                    "description": description or f"Host alias for {hostname}"
                })

                if isinstance(result, dict):
                    success = result.get("success", False)
                    message = result.get("message", "Alias created")
                    return success, message
            except Exception as mcp_error:
                logger.warning(f"MCP tool not available, using direct API: {mcp_error}")

            # Fallback to direct OPNsense API call
            import httpx

            # Get credentials from _env dictionary
            host = self._env.get("OPNSENSE_HOST")
            api_key = self._env.get("OPNSENSE_API_KEY")
            api_secret = self._env.get("OPNSENSE_API_SECRET")

            if not host or not api_key or not api_secret:
                return False, "OPNsense credentials not configured"

            # OPNsense API endpoint for aliases
            url = f"https://{host}/api/firewall/alias/addItem"

            # Prepare alias data
            alias_data = {
                "alias": {
                    "enabled": "1",
                    "name": name,
                    "type": "host",
                    "content": hostname,
                    "description": description or f"Host alias for {hostname}"
                }
            }

            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    url,
                    json=alias_data,
                    auth=(api_key, api_secret),
                    timeout=30.0
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("result") == "saved":
                        # Apply changes
                        apply_url = f"https://{host}/api/firewall/alias/reconfigure"
                        apply_response = await client.post(
                            apply_url,
                            auth=(api_key, api_secret),
                            timeout=30.0
                        )

                        if apply_response.status_code == 200:
                            logger.info(f"Created host alias: {name}")
                            return True, f"Host alias '{name}' created successfully"
                        else:
                            return True, f"Alias created but apply failed: {apply_response.text}"
                    else:
                        return False, f"Failed to save alias: {result}"
                else:
                    return False, f"API error: {response.status_code} - {response.text}"

        except Exception as e:
            logger.error(f"Failed to create host alias: {e}")
            return False, f"Error creating alias: {e}"

    async def create_geoip_alias(self, name: str, countries: list[str], description: str = "") -> tuple[bool, str]:
        """
        Create a GeoIP alias in OPNsense using direct API calls.

        Args:
            name: Alias name (e.g., "BlockedCountries")
            countries: List of ISO country codes (e.g., ["RU", "CN"])
            description: Optional description

        Returns:
            Tuple of (success, message)
        """
        try:
            # Try MCP tool first
            try:
                result = await self._call_tool("create_alias", {
                    "name": name,
                    "type": "geoip",
                    "content": countries,
                    "description": description or f"GeoIP alias for {', '.join(countries)}"
                })

                if isinstance(result, dict):
                    success = result.get("success", False)
                    message = result.get("message", "Alias created")
                    return success, message
            except Exception as mcp_error:
                logger.warning(f"MCP tool not available, using direct API: {mcp_error}")

            # Fallback to direct OPNsense API call
            import httpx

            if not self.host or not self.api_key or not self.api_secret:
                return False, "OPNsense credentials not configured"

            # OPNsense API endpoint for aliases
            url = f"https://{self.host}/api/firewall/alias/addItem"

            # Prepare alias data
            alias_data = {
                "alias": {
                    "enabled": "1",
                    "name": name,
                    "type": "geoip",
                    "content": ",".join(countries),
                    "description": description or f"GeoIP alias for {', '.join(countries)}"
                }
            }

            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    url,
                    json=alias_data,
                    auth=(self.api_key, self.api_secret),
                    timeout=30.0
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get("result") == "saved":
                        # Apply changes
                        apply_url = f"https://{self.host}/api/firewall/alias/reconfigure"
                        apply_response = await client.post(
                            apply_url,
                            auth=(self.api_key, self.api_secret),
                            timeout=30.0
                        )

                        if apply_response.status_code == 200:
                            logger.info(f"Created and applied GeoIP alias: {name}")
                            return True, f"GeoIP alias '{name}' created successfully"
                        else:
                            return True, f"Alias created but apply failed: {apply_response.text}"
                    else:
                        return False, f"Failed to save alias: {result}"
                else:
                    return False, f"API error: {response.status_code} - {response.text}"

        except Exception as e:
            logger.error(f"Failed to create GeoIP alias: {e}")
            return False, f"Error creating alias: {e}"

    async def list_aliases(self) -> list[dict]:
        """List all firewall aliases."""
        try:
            result = await self._call_tool("list_aliases")
            if isinstance(result, dict):
                return result.get("aliases", [])
            return []
        except Exception as e:
            logger.error(f"Failed to list aliases: {e}")
            return []

    async def delete_alias(self, name: str) -> tuple[bool, str]:
        """Delete a firewall alias."""
        try:
            result = await self._call_tool("delete_alias", {"name": name})
            if isinstance(result, dict):
                success = result.get("success", False)
                message = result.get("message", "Alias deleted")
                return success, message
            return False, "Invalid response"
        except Exception as e:
            logger.error(f"Failed to delete alias: {e}")
            return False, f"Error deleting alias: {e}"

    async def find_rules(self, **kwargs) -> dict:
        """Search firewall rules by criteria."""
        return await self._call_tool("find_firewall_rules", kwargs)
