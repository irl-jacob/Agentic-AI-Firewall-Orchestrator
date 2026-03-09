# Autonomous Firewall Orchestrator (AFO) - Architecture Analysis

## 1. System Overview

**Autonomous Firewall Orchestrator (AFO)** is a natural-language-driven security tool designed to bridge the gap between human intent and complex firewall configurations. It allows administrators to manage network security using plain English commands properly translated into syntax-correct firewall rules (NFTables or OPNsense).

The system is built on a modular architecture that separates user interaction, business logic, AI processing, and low-level system execution.

### High-Level Architecture

```mermaid
graph TD
    User[User / Administrator] -->|Natural Language| TUI[Textual TUI]
    TUI -->|Commands| Service[Firewall Service]
    
    subgraph "Intelligence Layer"
        Agent[Firewall Agent]
        LLM[Ollama (Local LLM)]
        RAG[ChromaDB (Vector Store)]
        Agent <--> LLM
        Agent <--> RAG
    end
    
    subgraph "Core Logic"
        Service --> Agent
        Service --> DB[(SQLite Database)]
        Service --> Scheduler[Rule Scheduler]
    end
    
    subgraph "Backend Layer"
        Service --> Backend{Firewall Backend}
        Backend -->|Local| NFT[NFTables Backend]
        Backend -->|Remote| OPN[OPNsense MCP Backend]
    end
    
    NFT -->|Subprocess| LinuxKernel[Linux Kernel]
    OPN -->|MCP Protocol| MCPServer[OPNsense MCP Server]
```

---

## 2. Component Details

### 2.1 User Interface (TUI)
Located in `ui/tui/`, the frontend is a terminal-based user interface built with **Textual**.
- **`app.py`**: The main application entry point. Handles the global event loop and screen management.
- **Widgets**:
  - `ChatPane`: A reactive chat interface for interacting with the AI.
  - `RulesPane`: Real-time visualization of active firewall rules.
  - `ThreatPane`: Dashboard for security events ( IDS/IPS alerts).
  - `CyberHeader/Footer`: Status indicators for connectivity, AI model, and "Dry Run" mode.

### 2.2 Intelligence Layer
Located in `agents/`, this layer translates natural language into structured data.
- **`firewall_agent.py`**: The core brain. It:
  1.  Analyzes user intent (Rule Creation vs. Q&A).
  2.  Queries the **RAG system** (`db/vector_store.py`) to retrieve relevant documentation or context.
  3.  Constructs a prompt for the **Ollama** LLM.
  4.  Parses the LLM's JSON response into a valid `FirewallRule` object.
- **RAG (Retrieval-Augmented Generation)**: Uses `ChromaDB` to store and retrieve technical knowledge (e.g., man pages, custom docs) to result in hallucination-free rule generation.

### 2.3 Service Layer
Located in `services/`, this layer orchestrates business logic.
- **`firewall.py`**: The `FirewallService` class acts as the mediator between the UI and the Backend. It handles:
  - Session management.
  - Calling the backend to list/deploy/delete rules.
  - Logging actions to the database for audit trails.
- **`rule_scheduler.py`**: Manages temporary rules (e.g., "Allow port 22 for 1 hour"). A background task checks for expired rules and removes them automatically.

### 2.4 Backend Layer
Located in `backend/`, this abstract layer enables multi-platform support.
- **`base.py` (`FirewallBackend`)**: Defines the interface that all backends must implement (`list_rules`, `deploy_rule`, `delete_rule`, `get_status`).
- **`nftables.py`**:
  - Interacts directly with the local Linux kernel using the `nft` binary.
  - Parses JSON output from `nft -j list ruleset`.
- **`opnsense.py`**:
  - Implements the **Model Context Protocol (MCP)** Client.
  - Connects to an external `opnsense-mcp-server` process.
  - Maps AFO internal models to OPNsense API calls.
  - Supports advanced features like NAT, Routing, and System Diagnostics.

### 2.5 Persistence Layer
Located in `db/`, using **SQLModel** (SQLAlchemy + Pydantic) and **SQLite**.
- **`database.py`**: Manages async database connections (`aiosqlite`).
- **`models.py`**: Defines schemas for:
  - `PolicyRule`: The standardized rule format.
  - `DeploymentLog`: Audit log of all changes made to the system.

### 2.6 Daemon & Safety
Located in `afo_daemon/`.
- **`main.py`**: Implements a long-running background process meant for autonomous monitoring.
- **Concept**: Future phases will enable this daemon to ingest logs (syslog/auditd), analyze them with the LLM, and propose defensive rules automatically.

---

## 3. Key Workflows

### 3.1 Natural Language to Rule Deployment
1.  **User Input**: "Block incoming traffic from 192.168.1.100"
2.  **Agent Analysis**: `firewall_agent.py` sends prompt to Ollama.
3.  **JSON Generation**: LLM outputs:
    ```json
    {"action": "DROP", "source": "192.168.1.100", "chain": "INPUT"}
    ```
4.  **Validation**: AFO validates fields (IP format, valid action).
5.  **Dry Run** (Optional): If enabled, the system logs what *would* happen without executing.
6.  **Deployment**: `backend.deploy_rule()` is called.
    - If NFTables: Executes `nft add rule ...`
    - If OPNsense: Calls MCP tool `create_firewall_rule`.
7.  **Verification**: The UI refreshes the Rules Pane to show the new rule.

### 3.2 OPNsense Integration (via MCP)
AFO acts as an **MCP Client**. It spawns the `opnsense-mcp-server` node process and communicates via stdio.
1.  AFO reads credentials from `.env`.
2.  Starts `node opnsense-mcp-server` with environment variables.
3.  Sends JSON-RPC requests (e.g., `call_tool("list_firewall_rules")`).
4.  The MCP server calls the OPNsense REST API.
5.  Results are formatted back to AFO.

---

## 4. Technology Stack

| Component | Technology | Role |
|-----------|------------|------|
| **Language** | Python 3.11+ | Core Application |
| **Frontend** | Textual | Terminal User Interface (TUI) |
| **AI / LLM** | LangChain + Ollama | Natural Language Understanding |
| **Vector DB** | ChromaDB | RAG / Knowledge retrieval |
| **Database** | SQLite + SQLModel | State and Audit logging |
| **Protocol** | Model Context Protocol | Extension/Plugin system |
| **Backend** | NFTables / OPNsense | Firewall enforcement |

## 5. Directory Structure Analysis

```text
/mnt/Projects/AFO/
├── afo_daemopn/        # Background process for monitoring
│   ├── detection/      # Logic for detecting threats
│   └── intelligence/   # LLM analysis logic
├── afo_mcp/            # MCP Server definitions (if self-hosting)
├── agents/             # AI Agents
│   ├── firewall_agent.py   # Main NL processing agent
│   └── prompts.py          # System prompts for LLM
├── backend/            # Hardware/Software Abstraction Layer
│   ├── base.py         # Abstract Interface
│   ├── nftables.py     # Local Linux implementation
│   └── opnsense.py     # Remote OPNsense implementation
├── db/                 # Database
│   ├── database.py     # Connection logic
│   ├── models.py       # SQL Schemas
│   └── vector_store.py # RAG implementation
├── docs/               # Documentation
├── services/           # Business Logic
│   ├── firewall.py     # Service orchestrator
│   └── rule_scheduler.py # Temporary rule manager
├── tests/              # Pytest suite
├── ui/                 # User Interfaces
│   └── tui/            # Textual TUI implementation
├── .env                # Configuration
└── pyproject.toml      # Dependency management
```
