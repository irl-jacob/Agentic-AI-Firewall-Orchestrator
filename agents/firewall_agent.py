"""Firewall orchestration agent using Ollama.

Uses a single unified prompt where the LLM classifies intent
(rule / answer / clarify) and responds accordingly.
"""

import json
import os
import re

import httpx

from backend.models import Action, Direction, PolicyRule, Protocol
from agents.language_normalizer import preprocess_input
from agents.prompts import RULE_GENERATION_PROMPT, SYSTEM_PROMPT
from db.vector_store import retrieve


def _handle_slash_command(cmd) -> dict:
    """
    Handle parsed slash command.

    Args:
        cmd: SlashCommand object

    Returns:
        Dict with response
    """
    # GeoIP commands
    if cmd.command == "geoip":
        if not cmd.args:
            return {
                "type": "chat",
                "response": "Usage: /geoip block <countries...> or /geoip allow <countries...>"
            }

        from services.geoip import normalize_country_name

        # Parse country names
        country_codes = []
        country_names = []
        for name in cmd.args:
            code = normalize_country_name(name)
            if code:
                country_codes.append(code)
                country_names.append(name)
            else:
                return {
                    "type": "chat",
                    "response": f"Unknown country: {name}"
                }

        if cmd.subcommand == "block":
            return {
                "type": "geoip_block",
                "countries": country_codes,
                "country_names": country_names,
                "response": f"Ready to block traffic from: {', '.join(country_names)}"
            }
        elif cmd.subcommand == "allow":
            return {
                "type": "geoip_allow",
                "countries": country_codes,
                "country_names": country_names,
                "response": f"Ready to allow traffic only from: {', '.join(country_names)}"
            }
        elif cmd.subcommand == "unblock":
            return {
                "type": "geoip_unblock",
                "countries": country_codes,
                "country_names": country_names,
                "response": f"Ready to remove blocks for: {', '.join(country_names)}"
            }

    # Domain commands
    elif cmd.command == "domain":
        if not cmd.args:
            return {
                "type": "chat",
                "response": "Usage: /domain block <domain> or /domain block category <category>"
            }

        if cmd.subcommand == "block":
            # Check if it's a category
            if cmd.args[0] == "category" and len(cmd.args) > 1:
                category = cmd.args[1]
                return {
                    "type": "domain_block_category",
                    "category": category,
                    "response": f"Ready to block domain category: {category}"
                }
            else:
                domain = cmd.args[0]
                return {
                    "type": "domain_block",
                    "domain": domain,
                    "response": f"Ready to block domain: {domain}"
                }
        elif cmd.subcommand == "unblock":
            domain = cmd.args[0]
            return {
                "type": "domain_unblock",
                "domain": domain,
                "response": f"Ready to unblock domain: {domain}"
            }

    # Bulk operations
    elif cmd.command == "bulk":
        if cmd.subcommand == "delete":
            if not cmd.args:
                return {
                    "type": "chat",
                    "response": "Usage: /bulk delete port <port>, /bulk delete ip <ip>, or /bulk delete temp"
                }

            target_type = cmd.args[0]
            if target_type == "port" and len(cmd.args) > 1:
                port = int(cmd.args[1])
                return {
                    "type": "bulk_delete_port",
                    "port": port,
                    "response": f"Ready to delete all rules for port {port}"
                }
            elif target_type == "ip" and len(cmd.args) > 1:
                ip = cmd.args[1]
                return {
                    "type": "bulk_delete_ip",
                    "ip": ip,
                    "response": f"Ready to delete all rules affecting {ip}"
                }
            elif target_type == "temp":
                return {
                    "type": "bulk_delete_temporary",
                    "response": "Ready to delete all temporary rules"
                }

        elif cmd.subcommand in ["enable", "disable"]:
            if not cmd.args or cmd.args[0] != "port" or len(cmd.args) < 2:
                return {
                    "type": "chat",
                    "response": f"Usage: /bulk {cmd.subcommand} port <port>"
                }

            port = int(cmd.args[1])
            return {
                "type": f"bulk_{cmd.subcommand}",
                "port": port,
                "response": f"Ready to {cmd.subcommand} all rules for port {port}"
            }

    # Rate limiter commands
    elif cmd.command == "rate":
        if cmd.subcommand == "stats":
            return {
                "type": "rate_stats",
                "response": "Fetching rate limiter statistics..."
            }
        elif cmd.subcommand == "whitelist":
            if len(cmd.args) < 2:
                return {
                    "type": "chat",
                    "response": "Usage: /rate whitelist add <ip> or /rate whitelist remove <ip>"
                }

            action = cmd.args[0]
            ip = cmd.args[1]

            if action == "add":
                return {
                    "type": "rate_whitelist_add",
                    "ip": ip,
                    "response": f"Ready to add {ip} to rate limiter whitelist"
                }
            elif action == "remove":
                return {
                    "type": "rate_whitelist_remove",
                    "ip": ip,
                    "response": f"Ready to remove {ip} from rate limiter whitelist"
                }

    # Configuration preset commands
    elif cmd.command == "config":
        if cmd.subcommand == "list":
            return {
                "type": "config_list",
                "response": "Available preset configurations:\n• Home/Basic - Simple home protection\n• Development/Testing - Minimal restrictions\n• Public WiFi/Cafe - Client isolation\n• IoT/Smart Home - Device segmentation"
            }
        elif cmd.subcommand == "apply":
            preset_name = cmd.args[0] if cmd.args else None
            return {
                "type": "config_apply",
                "preset_name": preset_name,
                "response": "Select a configuration preset to apply"
            }
        elif cmd.subcommand == "remove":
            return {
                "type": "config_remove",
                "response": "Remove active configuration?"
            }
        elif cmd.subcommand == "preview":
            if not cmd.args:
                return {
                    "type": "chat",
                    "response": "Usage: /config preview <preset_name>"
                }
            preset_name = cmd.args[0]
            return {
                "type": "config_preview",
                "preset_name": preset_name,
                "response": f"Preview configuration: {preset_name}"
            }

    return {
        "type": "chat",
        "response": "Command not implemented. Type /help for available commands."
    }


def _call_ollama(system_msg: str, user_msg: str) -> str:
    """Call Ollama chat API directly with optimized parameters."""
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b")
    resp = httpx.post(
        f"{host}/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 512,
                "num_ctx": 8192,
            },
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _get_rag_context(query: str) -> str:
    docs = retrieve(query, n_results=3)
    if not docs:
        return "No reference documentation available."

    parts = []
    total = 0
    for doc in docs:
        text = doc["text"]
        if total + len(text) > 1500:
            break
        section = doc["section"]
        if section:
            parts.append(f"### {section}")
        parts.append(text)
        parts.append("")
        total += len(text)

    return "\n".join(parts)


def _get_network_summary() -> str:
    try:
        from afo_mcp.tools.network import get_network_context

        ctx = get_network_context()
        data = ctx.model_dump()

        parts = [f"Hostname: {data['hostname']}"]
        for iface in data["interfaces"]:
            addrs = iface["ipv4_addresses"]
            if addrs and iface["state"] == "UP":
                parts.append(f"  {iface['name']}: {', '.join(addrs)}")

        return "\n".join(parts[:6])  # Limit to 5 interfaces
    except Exception as e:
        return f"Network context unavailable: {e}"


def _parse_network_interfaces() -> list[dict]:
    """Parse network interfaces into structured data."""
    try:
        from afo_mcp.tools.network import get_network_context
        ctx = get_network_context()
        data = ctx.model_dump()

        interfaces = []
        for iface in data["interfaces"]:
            if iface["ipv4_addresses"] or iface["ipv6_addresses"]:
                interfaces.append({
                    "name": iface["name"],
                    "ipv4": iface["ipv4_addresses"],
                    "ipv6": iface["ipv6_addresses"],
                    "state": iface["state"],
                    "is_loopback": iface["name"] == "lo" or iface["name"].startswith("loop"),
                    "is_docker": iface["name"].startswith("docker") or iface["name"].startswith("br-"),
                    "is_physical": not any(x in iface["name"] for x in ["lo", "docker", "br-", "virbr", "veth", "tailscale"])
                })
        return interfaces
    except Exception:
        return []


def _analyze_ip_question(query: str) -> dict:
    """Analyze what type of IP question the user is asking."""
    query_lower = query.lower()

    analysis = {
        "wants_public_ip": any(x in query_lower for x in ["public", "external", "internet", "wan", "my ip", "current ip"]),
        "wants_internal_ip": any(x in query_lower for x in ["internal", "private", "local", "lan"]),
        "wants_specific_interface": None,
        "wants_primary": any(x in query_lower for x in ["primary", "main", "default"]),
        "wants_all": any(x in query_lower for x in ["all", "list", "show me", "interfaces"]),
        "context": "general"
    }

    # Check for specific interface mentions
    common_interfaces = ["eth0", "eth1", "ens160", "ens192", "wlan0", "wifi", "docker0", "tailscale", "lo"]
    for iface in common_interfaces:
        if iface in query_lower:
            analysis["wants_specific_interface"] = iface
            break

    # Determine primary intent
    if analysis["wants_specific_interface"]:
        analysis["context"] = "specific_interface"
    elif analysis["wants_public_ip"] and not analysis["wants_internal_ip"]:
        analysis["context"] = "public"
    elif analysis["wants_internal_ip"] and not analysis["wants_public_ip"]:
        analysis["context"] = "internal"
    elif analysis["wants_all"]:
        analysis["context"] = "all_interfaces"
    else:
        analysis["context"] = "primary"

    return analysis


def _get_primary_interface(interfaces: list[dict]) -> dict | None:
    """Get the primary (default) network interface."""
    # Prefer physical interfaces that are UP
    physical_up = [i for i in interfaces if i["is_physical"] and i["state"] == "UP"]
    if physical_up:
        return physical_up[0]

    # Fall back to any non-loopback, non-docker interface
    normal_ifaces = [i for i in interfaces if not i["is_loopback"] and not i["is_docker"]]
    if normal_ifaces:
        return normal_ifaces[0]

    return None


def _get_public_ip_hint() -> str:
    """Provide instructions for getting public IP."""
    return "To get your public IP address, you can:\n• Run: curl ifconfig.me\n• Check your router's admin panel\n• Use an online service like icanhazip.com"


def _generate_contextual_ip_response(query: str, interfaces: list[dict]) -> str:
    """Generate a contextual response based on the query analysis."""
    analysis = _analyze_ip_question(query)

    if analysis["context"] == "specific_interface" and analysis["wants_specific_interface"]:
        # User asked about a specific interface
        target_name = analysis["wants_specific_interface"]
        # Handle variations like "wifi" -> "wlan0"
        if target_name == "wifi":
            target_name = "wlan"

        for iface in interfaces:
            if target_name in iface["name"].lower():
                ips = iface["ipv4"] + iface["ipv6"]
                if ips:
                    return f"Interface {iface['name']} ({iface['state']}):\n{chr(10).join(['  • ' + ip for ip in ips[:3]])}"
                else:
                    return f"Interface {iface['name']} has no IP addresses assigned."

        return f"Interface '{analysis['wants_specific_interface']}' not found. Available interfaces: {', '.join([i['name'] for i in interfaces[:5]])}"

    elif analysis["context"] == "public":
        # User wants public IP
        primary = _get_primary_interface(interfaces)
        if primary and primary["ipv4"]:
            private_ip = primary["ipv4"][0]
            return f"Your private/internal IP is: {private_ip}\n\n{_get_public_ip_hint()}"
        else:
            return f"Unable to determine your network configuration.\n\n{_get_public_ip_hint()}"

    elif analysis["context"] == "primary":
        # User wants their primary/current IP
        primary = _get_primary_interface(interfaces)
        if primary:
            ips = primary["ipv4"] + primary["ipv6"]
            if ips:
                main_ip = ips[0]
                ip_type = "IPv4" if "." in main_ip else "IPv6"
                response = f"Your primary {ip_type} address is: {main_ip}\n(Interface: {primary['name']}, State: {primary['state']})"

                # Add additional IPs if available
                if len(ips) > 1:
                    response += f"\n\nAdditional addresses on {primary['name']}:\n"
                    response += chr(10).join([f"  • {ip}" for ip in ips[1:3]])

                return response

        return "Unable to determine your primary IP address."

    elif analysis["context"] == "internal":
        # User specifically wants internal/private IPs
        private_interfaces = [i for i in interfaces if not i["is_loopback"]]
        if private_interfaces:
            response = "Your internal/private IP addresses:\n"
            for iface in private_interfaces[:3]:
                if iface["ipv4"]:
                    response += f"\n{iface['name']} ({iface['state']}):\n"
                    response += chr(10).join([f"  • {ip}" for ip in iface["ipv4"][:2]])
            return response
        return "No internal IP addresses found."

    else:
        # Default: show summary of all interfaces
        response = "Network Interface Summary:\n"
        for iface in interfaces[:5]:
            ips = iface["ipv4"] + iface["ipv6"]
            if ips:
                main_ip = ips[0][:30]  # Truncate if too long
                response += f"\n• {iface['name']}: {main_ip}"
                if len(ips) > 1:
                    response += f" (+{len(ips)-1} more)"
                response += f" [{iface['state']}]"

        response += "\n\nAsk me about a specific interface (e.g., 'what is eth0 IP') for more details."
        return response


def _extract_json(text: str) -> dict | None:
    """Extract JSON from LLM response."""
    # 1. Try code blocks
    code_match = re.search(r"```(?:json)?\s*\n?(\{.*?\})\s*```", text, re.DOTALL)
    if code_match:
        try:
            return json.loads(code_match.group(1))
        except json.JSONDecodeError:
            pass

    # 2. Find first { to last }
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_str = text[start : end + 1]
            return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    # 3. Fallback: parse "key: value; key: value" format (some models output this)
    if ":" in text and ("action" in text.lower() or "intent" in text.lower()):
        try:
            result = {}
            for part in text.split(";"):
                part = part.strip()
                if ":" in part:
                    key, _, val = part.partition(":")
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip().strip('"').strip("'")
                    if val.lower() == "null" or val == "":
                        val = None
                    result[key] = val
            if result:
                return result
        except Exception:
            pass

    return None


def _extract_ip_from_text(text: str) -> str | None:
    """Extract IP address from user input text as fallback."""
    # Match IPv4 addresses
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    match = re.search(ipv4_pattern, text)
    if match:
        return match.group(0)
    return None


def _generate_nft_command(rule: PolicyRule) -> str:
    """Generate nft command string from PolicyRule."""
    # Build nft command
    action = "drop" if rule.action == Action.DROP else ("reject" if rule.action == Action.REJECT else "accept")
    chain = "output" if rule.direction == Direction.OUTBOUND else "input"

    parts = [f"nft add rule inet filter {chain}"]

    if rule.protocol and rule.protocol != Protocol.ANY:
        parts.append(f"{rule.protocol.value.lower()}")

    if rule.source:
        parts.append(f"ip saddr {rule.source}")

    if rule.destination:
        parts.append(f"ip daddr {rule.destination}")

    if rule.port:
        parts.append(f"dport {rule.port}")

    parts.append(action)

    return " ".join(parts)


def _build_firewall_rule(data: dict) -> PolicyRule | None:
    """Convert parsed JSON to a PolicyRule model."""
    try:
        # Handle nested structure: some LLMs return {"rule": {...}} instead of flat structure
        if "rule" in data and isinstance(data["rule"], dict):
            # Merge nested rule data with top-level, preferring nested values
            rule_data = data["rule"]
            data = {**data, **rule_data}

        # Handle different field names (LLM might use 'target' instead of 'action')
        action_str = data.get("action") or data.get("target", "drop")
        action_str = action_str.lower()
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

        protocol_str = data.get("protocol")
        protocol = Protocol.ANY  # Default to ANY
        if protocol_str:
            protocol_map = {
                "tcp": Protocol.TCP,
                "udp": Protocol.UDP,
                "icmp": Protocol.ICMP,
                "icmpv6": Protocol.ICMPV6,
                "any": Protocol.ANY,
            }
            protocol = protocol_map.get(protocol_str.lower(), Protocol.ANY)

        # Handle alternative field names
        source_address = data.get("source_address") or data.get("source")
        destination_address = data.get("destination_address") or data.get("destination") or data.get("dest")

        # Ensure comment is never None - generate one from the rule details
        comment = data.get("comment")
        if not comment:
            # Auto-generate comment based on rule details
            parts = []
            if action_str:
                parts.append(action_str.capitalize())
            if protocol_str and protocol_str.lower() != "any":
                parts.append(protocol_str.upper())
            if data.get("destination_port") or data.get("source_port"):
                port = data.get("destination_port") or data.get("source_port")
                parts.append(f"port {port}")
            if source_address:
                parts.append(f"from {source_address}")
            if destination_address:
                parts.append(f"to {destination_address}")
            comment = " ".join(parts) if parts else "Firewall rule"

        # Map chain to direction
        chain_str = data.get("chain", "input").lower()
        if chain_str == "output":
            direction = Direction.OUTBOUND
        else:
            direction = Direction.INBOUND

        # Get port (prefer destination_port)
        port = data.get("destination_port") or data.get("source_port")
        if port and isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                port = None

        # Handle TTL (Time-To-Live) for temporary rules
        ttl_seconds = data.get("ttl_seconds")
        is_temporary = False

        if ttl_seconds and isinstance(ttl_seconds, (int, float)) and ttl_seconds > 0:
            is_temporary = True
            # Update comment to indicate temporary nature
            if comment and "temporary" not in comment.lower():
                comment = f"[TEMP] {comment} (expires in {int(ttl_seconds // 60)}m)"

        rule = PolicyRule(
            id=data.get("id"),
            name=(comment or "generated_rule").replace(" ", "_")[:50],
            description=comment,
            action=action,
            direction=direction,
            protocol=protocol,
            source=source_address,
            destination=destination_address,
            port=port,
            priority=data.get("priority", 100),
            enabled=data.get("enabled", True),
        )
        return rule
    except Exception as e:
        import logging
        logging.error(f"Failed to build firewall rule: {e}", exc_info=True)
        return None


def chat(user_input: str, history: list[dict] | None = None) -> dict:
    """Handle any user input — the LLM decides the intent.

    The LLM classifies the input as one of:
      - "rule": generate a firewall rule
      - "delete": remove a firewall rule
      - "answer": respond to a question
      - "clarify": ask the user for more information

    Returns:
        Dict with 'type' ('rule', 'chat', 'delete', or 'clarify') and relevant data.
    """
    # ── SLASH COMMANDS: Deterministic handling without LLM ──
    from agents.slash_commands import parse_slash_command, format_slash_command_help, is_slash_command

    if is_slash_command(user_input):
        if user_input.strip() in ["/help", "/"]:
            return {
                "type": "chat",
                "response": format_slash_command_help()
            }

        cmd = parse_slash_command(user_input)
        if cmd:
            return _handle_slash_command(cmd)
        else:
            return {
                "type": "chat",
                "response": "Invalid slash command. Type /help for available commands."
            }

    # Normalize typos and detect urgency FIRST
    from agents.typo_normalizer import get_typo_normalizer

    typo_normalizer = get_typo_normalizer()
    normalized_input, typo_metadata = typo_normalizer.normalize(user_input)
    urgency_level = typo_normalizer.get_urgency_level(user_input)

    # Use normalized input for processing
    if typo_metadata["typos_fixed"]:
        # Log typo corrections (could be shown to user)
        pass

    # Store urgency for later use
    is_urgent = urgency_level in ["medium", "high"]

    # Check for clarification needs (before expensive LLM call)
    from agents.clarification import get_clarification_manager

    clarification_manager = get_clarification_manager()
    clarification_request = clarification_manager.needs_clarification(normalized_input)

    if clarification_request:
        prompt = clarification_manager.create_clarification_prompt(clarification_request)
        return {
            "type": "clarify",
            "response": prompt,
            "clarification_request": {
                "type": clarification_request.type.value,
                "question": clarification_request.question,
                "options": clarification_request.options,
                "context": clarification_request.context,
                "original_input": clarification_request.original_input
            }
        }

    # Handle common questions with hardcoded AFO responses
    normalized = normalized_input.lower().strip()

    # Greetings - respond instantly
    greetings = ["hi", "hello", "hey", "sup", "yo", "howdy", "greetings"]
    if normalized in greetings:
        return {
            "type": "chat",
            "response": "Hey! I'm AFO, your firewall assistant. Try commands like 'block SSH from 10.0.0.5' or ask me anything about networking."
        }

    # Identity questions - always respond as AFO
    identity_phrases = ["what are you", "who are you", "what is your purpose",
                        "what can you do", "who built you", "what do you do"]
    if any(phrase in normalized for phrase in identity_phrases):
        return {
            "type": "chat",
            "response": "I am AFO (Autonomous Firewall Orchestrator), a cybersecurity assistant that helps you manage nftables firewall rules using natural language. I can:\n\n• Create, delete, and modify firewall rules\n• Analyze your network configuration\n• Explain firewall concepts\n• Help secure your server\n\nTry commands like 'block SSH from 10.0.0.5' or 'open port 443'."
        }

    # IP address questions - provide contextual responses based on query analysis
    is_ip_question = (
        ("ip" in normalized or "address" in normalized or "interface" in normalized) and
        any(word in normalized for word in ["my", "current", "connected", "show", "what", "whats", "what's", "which", "all", "list"])
    )

    if is_ip_question:
        interfaces = _parse_network_interfaces()
        if interfaces:
            contextual_response = _generate_contextual_ip_response(user_input, interfaces)
            return {
                "type": "chat",
                "response": contextual_response
            }

        return {
            "type": "chat",
            "response": "I'm unable to retrieve your network interface information. This might be due to container restrictions or missing network access. Check the Rules panel (F2) for network details, or ask me about firewall rules instead."
        }

    # ── Phase 3: GeoIP Commands ──
    # Detect country-based blocking commands
    country_block_patterns = [
        r'block\s+(?:all\s+)?(?:traffic\s+)?from\s+([a-zA-Z\s,]+?)(?:\s+and\s+([a-zA-Z\s]+))?(?:\s|$)',
        r'block\s+([a-zA-Z\s,]+?)(?:\s+and\s+([a-zA-Z\s]+))?\s+(?:traffic|country|countries)',
    ]

    for pattern in country_block_patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            from services.geoip import normalize_country_name
            countries_str = match.group(1)
            # Parse country names
            country_names = [c.strip() for c in re.split(r',|\sand\s', countries_str)]
            country_codes = []

            for name in country_names:
                code = normalize_country_name(name)
                if code:
                    country_codes.append(code)

            if country_codes:
                return {
                    "type": "geoip_block",
                    "countries": country_codes,
                    "country_names": country_names,
                    "response": f"Ready to block traffic from: {', '.join(country_names)}"
                }

    # ── Phase 3: Domain Blocking Commands ──
    domain_patterns = [
        r'block\s+(?:domain\s+)?([a-zA-Z0-9\-\.]+\.(?:com|net|org|io|co|uk|de|fr|jp|cn|ru))',
        r'block\s+(facebook|twitter|instagram|youtube|netflix|tiktok|reddit)',
        r'block\s+(social\s+media|streaming|gaming|gambling|ads?|adult)',
    ]

    for pattern in domain_patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            from services.domain_blocker import detect_category_from_text
            target = match.group(1)

            # Check if it's a category
            category = detect_category_from_text(normalized)
            if category:
                return {
                    "type": "domain_block_category",
                    "category": category,
                    "response": f"Ready to block domain category: {category}"
                }
            else:
                # Single domain
                return {
                    "type": "domain_block",
                    "domain": target,
                    "response": f"Ready to block domain: {target}"
                }

    # ── Phase 3: Bulk Operations Commands ──
    bulk_delete_patterns = [
        r'delete\s+all\s+rules\s+(?:for\s+)?port\s+(\d+)',
        r'remove\s+all\s+rules\s+(?:for\s+)?port\s+(\d+)',
        r'delete\s+all\s+(?:rules\s+)?(?:for|affecting)\s+([0-9\.]+)',
        r'remove\s+all\s+(?:rules\s+)?(?:for|affecting)\s+([0-9\.]+)',
        r'delete\s+all\s+temporary\s+rules',
        r'clear\s+all\s+temp(?:orary)?\s+rules',
    ]

    for pattern in bulk_delete_patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            if "temporary" in normalized or "temp" in normalized:
                return {
                    "type": "bulk_delete_temporary",
                    "response": "Ready to delete all temporary rules"
                }
            elif "port" in normalized:
                port = int(match.group(1))
                return {
                    "type": "bulk_delete_port",
                    "port": port,
                    "response": f"Ready to delete all rules for port {port}"
                }
            else:
                ip = match.group(1)
                return {
                    "type": "bulk_delete_ip",
                    "ip": ip,
                    "response": f"Ready to delete all rules affecting {ip}"
                }

    # Bulk enable/disable patterns
    if "enable all" in normalized or "disable all" in normalized:
        action = "enable" if "enable all" in normalized else "disable"

        # Check for port filter
        port_match = re.search(r'port\s+(\d+)', normalized)
        if port_match:
            port = int(port_match.group(1))
            return {
                "type": f"bulk_{action}",
                "port": port,
                "response": f"Ready to {action} all rules for port {port}"
            }

    # Parse duration from input (e.g. "for 5 minutes", "for 30s")
    from services.rule_scheduler import parse_duration
    ttl_seconds = None
    duration_match = re.search(
        r'\bfor\s+(\d+\s*(?:seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b(?:\s+\d+\s*(?:seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b)*)',
        normalized_input, re.IGNORECASE,
    )
    if duration_match:
        ttl_seconds = parse_duration(duration_match.group(1))
        # Strip the duration phrase so it doesn't confuse the LLM
        normalized_input = normalized_input[:duration_match.start()].rstrip() + normalized_input[duration_match.end():]

    # Parse time-based schedule (e.g. "during business hours", "on weekends")
    from agents.time_parser import parse_time_expression
    time_schedule = parse_time_expression(normalized_input)
    if time_schedule:
        # Note: Time-based rules require scheduler integration
        # For now, we'll include it in the explanation
        pass

    # Preprocess input to normalize directional language
    normalized_input, clarification = preprocess_input(normalized_input)

    # If input is ambiguous, ask for clarification immediately
    if clarification:
        return {
            "type": "chat",
            "response": f"I'm not sure about the direction: {clarification}\n\nPlease specify 'from' (incoming) or 'to' (outgoing).",
        }

    # Use normalized input for processing
    user_input = normalized_input

    # Skip expensive RAG retrieval — the model doesn't need reference docs
    # for most rule generation or question answering
    network_context = _get_network_summary()

    system_msg = SYSTEM_PROMPT.format(network_context=network_context)

    prompt = RULE_GENERATION_PROMPT % user_input

    # Add time schedule context if present
    if time_schedule:
        prompt += f"\n\nNote: User wants this rule active {time_schedule.description}"

    try:
        response = _call_ollama(system_msg, prompt)
    except httpx.TimeoutException:
        return {
            "type": "chat",
            "response": "The model timed out. This may be due to limited system resources. Try a shorter request or check Ollama status.",
        }
    except Exception as e:
        return {
            "type": "chat",
            "response": f"LLM connection failed: {e}. Is Ollama running?",
        }

    # Parse the JSON response
    parsed = _extract_json(response)

    if parsed is None:
        # Check if response contains iptables-style output instead of JSON
        response_lower = response.lower()
        if "iptables" in response_lower or "-a input" in response_lower or "-j drop" in response_lower or "-j accept" in response_lower:
            # LLM generated iptables syntax instead of JSON - retry with clearer instruction
            return {
                "type": "chat",
                "response": "I see you're trying to create a firewall rule, but I generated it in iptables format instead of nftables. Let me clarify: AFO uses nftables (the modern Linux firewall). Please try rephrasing your request with the IP address and port clearly specified, like 'block SSH from 10.0.0.5'.",
            }

        # Check if response looks like a raw nftables command without JSON wrapper
        if response.strip().startswith("nft ") or "add rule" in response_lower:
            return {
                "type": "chat",
                "response": "I generated an nftables command, but I need to format it properly. Please try rephrasing your request more clearly, like 'block port 22 from 10.0.0.5'.",
            }

        # LLM didn't return JSON — treat raw text as a chat response
        # Strip any markdown artifacts
        clean = response.strip().strip("`").strip()
        if clean:
            return {"type": "chat", "response": clean}
        return {
            "type": "chat",
            "response": "I couldn't process that request. Could you rephrase it?",
        }

    intent = (parsed.get("intent") or "").lower()

    # ── Fix misclassified rules: model says "answer" but response is a rule dict ──
    if intent in ("answer", "clarify") and isinstance(parsed.get("response"), dict):
        resp_dict = parsed["response"]
        if "action" in resp_dict or "chain" in resp_dict or "source_address" in resp_dict:
            # Model put rule data inside response — treat as rule intent
            parsed = {**parsed, **resp_dict}
            intent = "rule"

    # ── Intent: ANSWER or CLARIFY ──
    # Also handle case where intent is missing but there's a response field
    if intent in ("answer", "clarify") or (not intent and parsed.get("response")):
        resp = parsed.get("response", "")
        # Handle case where response is a dict instead of string
        if isinstance(resp, dict):
            # Try to extract meaningful info from the dict
            if "ip" in resp or "ip_address" in resp:
                ip = resp.get("ip") or resp.get("ip_address", "unknown")
                if ip in ("your_ip_here", "your_current_ip_here") or not ip or ip == "unknown":
                    # Return actual network info instead of placeholder
                    network_ctx = _get_network_summary()
                    if network_ctx and ":" in network_ctx:
                        return {
                            "type": "chat",
                            "response": f"Here is your network info:\n{network_ctx}"
                        }
                    else:
                        resp = "I can see your network interfaces. Check the Rules panel (F2) for detailed network information."
                else:
                    resp = f"Your IP address is: {ip}"
            else:
                # Convert dict to readable string
                resp = "; ".join([f"{k}: {v}" for k, v in resp.items()])

        if not resp:
            resp = "I'm not sure how to respond to that. Could you rephrase?"

        # Check if response contains IP placeholder text and replace with real network info
        if isinstance(resp, str) and ("your_current_ip_here" in resp.lower() or "your_ip_here" in resp.lower()):
            network_ctx = _get_network_summary()
            if network_ctx and ":" in network_ctx:
                resp = f"Here is your network info:\n{network_ctx}"
            else:
                resp = "I can see your network interfaces. Check the Rules panel (F2) for detailed network information."

        return {"type": "chat", "response": resp}

    # If no intent field, try to infer from other fields
    if not intent:
        # Check if this looks like a rule creation request
        if "rule" in parsed or "action" in parsed or "target" in parsed or "chain" in parsed:
            # Treat as rule creation
            intent = "rule"
        # Check for IP-related questions
        elif "ip" in parsed or "ip_address" in parsed:
            ip = parsed.get("ip") or parsed.get("ip_address", "unknown")
            if ip in ("your_ip_here", "your_current_ip_here") or not ip or ip == "unknown":
                network_ctx = _get_network_summary()
                if network_ctx and ":" in network_ctx:
                    return {
                        "type": "chat",
                        "response": f"Here is your network info:\n{network_ctx}"
                    }
                return {
                    "type": "chat",
                    "response": "I can see your network interfaces. Check the Rules panel (F2) for detailed network information."
                }
            return {"type": "chat", "response": f"Your IP address is: {ip}"}
        else:
            # If we can't make sense of it, don't show raw JSON - give a generic helpful response
            return {"type": "chat", "response": "I received your request but I'm not sure how to answer that. Could you try rephrasing or ask about firewall rules?"}

    # ── Intent: RULE ──
    if intent == "rule":
        explanation = parsed.get("explanation", "No explanation provided.")

        # Fallback: If LLM didn't extract IP from "to X" or "from X", try to extract from user input
        if not parsed.get("source_address") and not parsed.get("destination_address"):
            extracted_ip = _extract_ip_from_text(user_input)
            if extracted_ip:
                # Check user input for direction hints
                user_lower = user_input.lower()

                # "to X" means destination (outbound)
                if " to " in user_lower or "outgoing" in user_lower:
                    parsed["destination_address"] = extracted_ip
                    if parsed.get("chain") in (None, "input", "INPUT"):
                        parsed["chain"] = "output"
                # "from X" means source (inbound)
                elif " from " in user_lower or "incoming" in user_lower:
                    parsed["source_address"] = extracted_ip
                    if parsed.get("chain") in (None, "output", "OUTPUT"):
                        parsed["chain"] = "input"
                else:
                    # Ambiguous - default to source (incoming) for blocking
                    parsed["source_address"] = extracted_ip

        rule = _build_firewall_rule(parsed)
        if rule is None:
            # Provide user-friendly error without raw JSON
            requested_action = parsed.get('action') or parsed.get('target', 'block')
            target = parsed.get('source_address') or parsed.get('destination_address') or 'unknown'
            return {
                "type": "chat",
                "response": f"I understood you want to {requested_action} traffic involving {target}, but I couldn't build a valid firewall rule from that request. Please try rephrasing with the IP address and port clearly specified.",
            }

        nft_command = _generate_nft_command(rule)

        # Assess risk level
        from agents.risk_analyzer import get_risk_analyzer

        risk_analyzer = get_risk_analyzer()
        risk_assessment = risk_analyzer.assess_rule(rule, user_input)

        # Check conflicts
        try:
            from afo_mcp.tools.conflicts import detect_conflicts
            conflicts = detect_conflicts(nft_command)
            conflicts_data = conflicts.model_dump()
        except Exception:
            conflicts_data = {"has_conflicts": False, "conflicts": [], "recommendations": []}

        rag_sources = [doc["section"] for doc in retrieve(user_input, n_results=3)]

        result = {
            "type": "rule",
            "success": True,
            "rule": rule.model_dump(),
            "nft_command": nft_command,
            "explanation": explanation,
            "validation": {
                "valid": True,
                "command": nft_command,
                "errors": [],
                "warnings": ["Validation deferred to backend."],
                "line_numbers": [],
            },
            "conflicts": conflicts_data,
            "rag_sources": rag_sources,
            "risk_assessment": {
                "level": risk_assessment.level.value,
                "reasons": risk_assessment.reasons,
                "requires_confirmation": risk_assessment.requires_confirmation,
                "warning_message": risk_assessment.warning_message,
                "bypass_on_urgency": risk_assessment.bypass_on_urgency
            }
        }

        # Attach TTL if user specified a duration
        if ttl_seconds and ttl_seconds > 0:
            from services.rule_scheduler import format_duration
            result["ttl_seconds"] = ttl_seconds
            result["explanation"] += f" (temporary — auto-expires in {format_duration(ttl_seconds)})"

        return result

    # ── Intent: DELETE ──
    if intent == "delete":
        # Build rule object to identify what to delete
        rule_to_delete = _build_firewall_rule(parsed)
        if rule_to_delete is None:
            return {
                "type": "chat",
                "response": "I couldn't determine which rule to delete. Please specify the IP, port, and direction more clearly.",
            }

        explanation = parsed.get("explanation", "Deleting rule.")

        return {
            "type": "delete",
            "success": True,
            "rule": rule_to_delete.model_dump(),
            "nft_command": _generate_nft_command(rule_to_delete),
            "explanation": explanation,
            "target_description": parsed.get("target_description", "Unspecified rule"),
        }

    # ── Unknown intent — fallback ──
    # Never show raw JSON to user - always provide a helpful response
    resp = parsed.get("response") or parsed.get("explanation")
    if resp:
        return {"type": "chat", "response": resp}

    # If we can't extract anything meaningful, give a helpful fallback
    return {"type": "chat", "response": "I understood your request but I'm not sure how to proceed. Try asking about firewall rules, network configuration, or type 'help' for assistance."}


# Keep generate_rule as a direct entry point for MCP/API callers
def generate_rule(user_input: str) -> dict:
    """Generate a firewall rule from natural language input."""
    result = chat(user_input)
    if result["type"] == "rule":
        return result
    return {
        "success": False,
        "error": result.get("response", "Could not generate rule"),
        "rag_sources": [],
    }
