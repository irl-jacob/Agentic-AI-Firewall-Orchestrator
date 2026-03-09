<div align="center">

# 🛡️ AFO - Agentic Firewall Orchestrator

**AI-powered firewall management using Model Context Protocol (MCP) and adaptive learning**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.14.5-00ADD8?style=for-the-badge&logo=fastapi&logoColor=white)](https://github.com/jlowin/fastmcp)
[![Textual](https://img.shields.io/badge/Textual-7.5.0-009485?style=for-the-badge&logo=python&logoColor=white)](https://textual.textualize.io/)
[![SQLModel](https://img.shields.io/badge/SQLModel-0.0.32-CC2927?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlmodel.tiangolo.com/)

[![Tests](https://img.shields.io/badge/Tests-403%2F495%20Passing-success?style=for-the-badge&logo=pytest)](./TEST_RESULTS.md)
[![Core Tests](https://img.shields.io/badge/Core%20Tests-83%2F83%20Passing-brightgreen?style=for-the-badge&logo=checkmarx)](./TEST_RESULTS.md)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=for-the-badge&logo=statuspage)](./TEST_RESULTS.md)

[Features](#-features) • [Quick Start](#-quick-start) • [Installation](#-installation) • [Documentation](#-documentation) • [Architecture](#-architecture)

</div>

---

## 🎯 Overview

AFO is an **agentic firewall orchestration platform** powered by Model Context Protocol (MCP). It combines AI agents, natural language processing, and adaptive learning to manage complex firewall configurations. The system uses MCP to expose 22+ tools that enable intelligent, agent-driven network security management.

### ✨ What Makes AFO Special

🤖 **MCP-Powered Architecture** - 22+ tools exposed via Model Context Protocol
🧠 **AI Agent System** - LLM-based agents process natural language and make decisions
🔍 **Web Search Validation** - AI-powered research before implementation
📚 **Adaptive Learning** - Automatically learns from logs and adapts behavior
⚡ **Preset Configurations** - Apply security profiles with one command
🎨 **Beautiful TUI** - Modern terminal interface built with Textual
🔒 **Safety First** - Built-in validation prevents dangerous configurations
🔌 **Multi-Backend** - Supports OPNsense, nftables, and iptables
📊 **Pattern Detection** - Discovers attack patterns and suggests rules

---

## 🚀 Quick Start

### One Command Launch

```bash
./afo
```

That's it! This launches the complete AFO system with:
- ✅ MCP server with 22+ agent tools
- ✅ Interactive TUI for natural language firewall management
- ✅ AI-powered adaptive learning system
- ✅ Real-time rule and threat monitoring
- ✅ Built-in safety features and rollback capability

### First Commands

```bash
/config list                # List available presets
/config preview home_basic  # Preview changes
/config apply home_basic    # Apply a preset
/help                       # Show all commands
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| **F1** | Model Selection |
| **F2** | Toggle Rules Panel |
| **F3** | Toggle Threats Panel |
| **F4** | Toggle DRY/LIVE Mode |
| **Ctrl+R** | Refresh Rules |
| **Q** | Quit |

---

## 🎁 Features

### 🔧 Core Capabilities

<table>
<tr>
<td width="50%">

**🎛️ Preset Configuration System**
- 4 ready-to-use security profiles
- One-command deployment
- Automatic rollback on failure
- Safety validation built-in

</td>
<td width="50%">

**🧠 Adaptive Learning**
- AI agents analyze patterns from logs
- LLM-powered insights and recommendations
- Auto-configuration modes with safety
- User feedback learning loop

</td>
</tr>
<tr>
<td width="50%">

**🌍 GeoIP Filtering**
- Block/allow by country
- Automatic IP list updates
- 2-letter country codes
- Bulk operations support

</td>
<td width="50%">

**🚫 Domain Blocking**
- DNS-level filtering
- Wildcard support
- Category blocking
- Host alias integration

</td>
</tr>
</table>

### 📦 Available Presets

| Preset | Description | Rules | Use Case |
|--------|-------------|-------|----------|
| 🏠 **home_basic** | Simple home protection | 8 | Home networks, basic security |
| 💻 **development** | Dev-friendly config | 7 | Development environments |
| ☕ **public_wifi** | Public WiFi security | 10 | Cafes, shared spaces |
| 🔌 **iot_smart_home** | IoT segmentation | 8 | Smart home devices |

### 🎯 Slash Commands

```bash
# Configuration Presets
/config list, apply, preview, remove

# GeoIP Filtering
/geoip block CN RU, allow US, unblock KP

# Domain Blocking
/domain block facebook.com, unblock twitter.com

# Bulk Operations
/bulk delete port 22, delete ip 10.0.0.5, delete temp

# Learning System
list_learned_patterns, approve_insight, get_learning_metrics

# Help
/help or /
```

---

## 📥 Installation

### Prerequisites

```bash
# Python 3.10 or higher
python --version

# Git
git --version
```

### Clone & Setup

```bash
# Clone repository
git clone https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator.git
cd Autonomous-Firewall-Orchestrator

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### Environment Configuration

```bash
# Backend Selection
AFO_BACKEND=opnsense        # or nftables, iptables
AFO_DRY_RUN=0               # 1 for dry-run mode

# OPNsense Configuration (if using OPNsense)
OPNSENSE_HOST=https://firewall.local
OPNSENSE_API_KEY=your_key
OPNSENSE_API_SECRET=your_secret

# Ollama Configuration (for NLP)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:3b

# Learning System
LEARNING_MODE=monitor       # monitor, cautious, aggressive, manual
```

### Verify Installation

```bash
# Run tests
python -m pytest tests/ -v

# Verify learning system
python verify_learning_system.py

# Verify logging
python verify_logging.py

# Launch application
./afo
```

---

## 🏗️ Architecture

### MCP-First Design

AFO is built on **Model Context Protocol (MCP)**, exposing all functionality through 22+ standardized tools that AI agents can discover and use. This enables seamless integration with Claude, other LLMs, and automation systems.

```
┌─────────────────────────────────────────┐
│  TUI Layer (Textual)                    │
│  - Natural language input               │
│  - Real-time monitoring                 │
│  - Interactive panels                   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  FastMCP Server (22+ Agent Tools) ⭐    │
│  ├─ Rule Management (5 tools)          │
│  ├─ Preset Configuration (5 tools)     │
│  ├─ Learning System (7 tools)          │
│  ├─ GeoIP Filtering (2 tools)          │
│  ├─ Domain Blocking (2 tools)          │
│  └─ Bulk Operations (3 tools)          │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  Core Services (Python)                 │
│  ├─ ConfigManager (Presets)            │
│  ├─ FirewallService (Rules)            │
│  ├─ LearningService (Adaptive AI)      │
│  ├─ GeoIPService (Country Blocking)    │
│  ├─ DomainBlocker (DNS Filtering)      │
│  └─ BulkOperations (Mass Management)   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  Backend Layer                          │
│  ├─ OPNsense (via MCP)                 │
│  ├─ nftables (Local)                   │
│  └─ iptables (Legacy)                  │
└─────────────────────────────────────────┘
```

### Why MCP?

- **Standardized Interface** - All tools follow MCP specification
- **AI-Native** - Designed for LLM agents to discover and use
- **Composable** - Tools can be chained and combined
- **Type-Safe** - Pydantic models ensure data validation
- **Extensible** - Easy to add new tools and capabilities

---

## 🧠 Learning System

AFO includes an **AI agent-based learning system** that automatically analyzes your firewall's behavior and suggests improvements through MCP tools.

### Features

- 🔍 **Pattern Detection** - AI agents discover attack patterns, false positives, and legitimate traffic
- 🤖 **LLM-Based Insights** - Uses Ollama to analyze patterns and generate recommendations
- 🛡️ **Safe Auto-Configuration** - Multiple operating modes with safety validation
- 📊 **User Feedback** - Learns from your corrections to improve accuracy
- 💾 **Persistent Memory** - Stores patterns in SQLite database
- 🔌 **MCP Integration** - 7 dedicated learning tools for agent interaction

### Operating Modes

| Mode | Description | Auto-Apply | Confidence Threshold |
|------|-------------|------------|---------------------|
| **Monitor** | Observes only, never applies | ❌ | N/A |
| **Cautious** | Very high confidence only | ✅ | >0.9 |
| **Aggressive** | High confidence insights | ✅ | >0.7 |
| **Manual** | Requires explicit approval | ❌ | N/A |

### Quick Start

```bash
# View learned patterns (via MCP)
list_learned_patterns(pattern_type="attack", min_confidence=0.7)

# View insights (via MCP)
list_insights(pending_only=True)

# Approve an insight (via MCP)
approve_insight(insight_id=1, user="admin")

# Get metrics (via MCP)
get_learning_metrics()
```

### Available MCP Learning Tools

| Tool | Description |
|------|-------------|
| `list_learned_patterns` | Query stored patterns by type and confidence |
| `get_pattern_details` | Get detailed information about a pattern |
| `list_insights` | List pending or all insights |
| `approve_insight` | Approve an insight for deployment |
| `reject_insight` | Reject an insight with reason |
| `get_learning_metrics` | Get learning system statistics |
| `configure_learning_mode` | Change operating mode |

---

## 🛠️ Tech Stack

### Core Technologies

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-00ADD8?style=flat-square&logo=protocol&logoColor=white)](https://modelcontextprotocol.io/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.14.5-00ADD8?style=flat-square&logo=fastapi&logoColor=white)](https://github.com/jlowin/fastmcp)
[![Textual](https://img.shields.io/badge/Textual-7.5.0-009485?style=flat-square&logo=python&logoColor=white)](https://textual.textualize.io/)
[![SQLModel](https://img.shields.io/badge/SQLModel-0.0.32-CC2927?style=flat-square&logo=sqlite&logoColor=white)](https://sqlmodel.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-2.0+-E92063?style=flat-square&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)

### AI & NLP

[![Ollama](https://img.shields.io/badge/Ollama-Latest-000000?style=flat-square&logo=ollama&logoColor=white)](https://ollama.ai/)
[![LangChain](https://img.shields.io/badge/LangChain-0.3+-1C3C3C?style=flat-square&logo=chainlink&logoColor=white)](https://www.langchain.com/)
[![Structlog](https://img.shields.io/badge/Structlog-Latest-FF6B6B?style=flat-square&logo=python&logoColor=white)](https://www.structlog.org/)

### Database & Storage

[![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0+-D71F00?style=flat-square&logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org/)

### Testing & Quality

[![Pytest](https://img.shields.io/badge/Pytest-9.0.2-0A9EDC?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org/)
[![Pytest-Asyncio](https://img.shields.io/badge/Pytest--Asyncio-1.3.0-0A9EDC?style=flat-square&logo=pytest&logoColor=white)](https://github.com/pytest-dev/pytest-asyncio)

### Firewall Backends

[![OPNsense](https://img.shields.io/badge/OPNsense-Latest-D94F00?style=flat-square&logo=opnsense&logoColor=white)](https://opnsense.org/)
[![nftables](https://img.shields.io/badge/nftables-Latest-FCC624?style=flat-square&logo=linux&logoColor=black)](https://netfilter.org/projects/nftables/)
[![iptables](https://img.shields.io/badge/iptables-Legacy-FCC624?style=flat-square&logo=linux&logoColor=black)](https://netfilter.org/projects/iptables/)


## 📚 Documentation

- [Test Results](./TEST_RESULTS.md) - Comprehensive test verification
- [Learning System](./docs/LEARNING_SYSTEM.md) - Adaptive learning documentation
- [Roadmap](./ROADMAP.md) - 7-phase development plan
- [Planning](./planning/) - Detailed phase documentation

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone repository
git clone https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator.git
cd Autonomous-Firewall-Orchestrator

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dev dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio

# Run tests
python -m pytest tests/ -v

# Run specific test suite
python -m pytest tests/test_mcp_tools.py -v
```

## 🐛 Troubleshooting

### Common Issues

**MCP Connection Error**
```bash
# Check dependencies
pip install mcp fastmcp

# Verify backend config
cat .env | grep AFO_BACKEND

# Try dry-run mode
AFO_DRY_RUN=1 ./afo
```

**GeoIP Library Missing**
```bash
pip install geoip2
```

**Backend Connection Failed**
```bash
# Check OPNsense accessibility
curl -k https://firewall.local

# Verify API credentials
cat .env | grep OPNSENSE

# Use dry-run for testing
AFO_DRY_RUN=1 ./afo
```

---
## 📸 Screenshots

<div align="center">

### Main Interface
<img src="https://github.com/irl-jacob/Agentic-AI-Firewall-Orchestrator/raw/42b73aa083392c4cbc7add56db4e470a1fd47ba4/screenshots/screenshot_20260310_013021.jpg" width="900">

### Rules & Monitoring Panel
<img src="https://github.com/irl-jacob/Agentic-AI-Firewall-Orchestrator/raw/42b73aa083392c4cbc7add56db4e470a1fd47ba4/screenshots/screenshot_20260310_013203.jpg" width="900">

### Learning & Insights System
<img src="https://github.com/irl-jacob/Agentic-AI-Firewall-Orchestrator/raw/42b73aa083392c4cbc7add56db4e470a1fd47ba4/screenshots/screenshot_20260310_013313.jpg" width="900">

### Configuration View
<img src="https://github.com/irl-jacob/Agentic-AI-Firewall-Orchestrator/raw/42b73aa083392c4cbc7add56db4e470a1fd47ba4/screenshots/screenshot_20260310_013411.jpg" width="900">

</div>

---
## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [FastMCP](https://github.com/jlowin/fastmcp) - Modern MCP server framework
- [Textual](https://textual.textualize.io/) - Beautiful TUI framework
- [OPNsense](https://opnsense.org/) - Open source firewall platform
- [Ollama](https://ollama.ai/) - Local LLM inference

---

## 📞 Support

- 🐛 [Report Issues](https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator/issues)
- 💬 [Discussions](https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator/discussions)
- 📧 Contact: [Your Email]

---

<div align="center">

**Made with ❤️ by Jacob**

[![GitHub Stars](https://img.shields.io/github/stars/irl-jacob/Autonomous-Firewall-Orchestrator?style=social)](https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/irl-jacob/Autonomous-Firewall-Orchestrator?style=social)](https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator/network/members)
[![GitHub Watchers](https://img.shields.io/github/watchers/irl-jacob/Autonomous-Firewall-Orchestrator?style=social)](https://github.com/irl-jacob/Autonomous-Firewall-Orchestrator/watchers)

</div>
=======
# Agentic-AI-Firewall-Orchestrator-
>>>>>>> 2696fd58ab00dc3daec7b91da075a81d9f3be612
