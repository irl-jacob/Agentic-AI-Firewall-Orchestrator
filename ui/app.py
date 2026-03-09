"""AFO Streamlit Dashboard - Human-in-the-loop firewall orchestration."""

import streamlit as st

from agents.firewall_agent import chat
from db.vector_store import ingest_docs


def _init_session_state():
    """Initialize Streamlit session state."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "pending_rules" not in st.session_state:
        st.session_state.pending_rules = []
    if "deployed_rules" not in st.session_state:
        st.session_state.deployed_rules = []
    if "docs_ingested" not in st.session_state:
        st.session_state.docs_ingested = False


def _sidebar():
    """Render the sidebar with settings and status."""
    import os

    st.sidebar.title("AFO Settings")

    # Model settings
    st.sidebar.subheader("Model")
    model = st.sidebar.text_input(
        "Ollama Model",
        value=os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b"),
    )
    os.environ["OLLAMA_MODEL"] = model

    ollama_host = st.sidebar.text_input(
        "Ollama Host",
        value=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
    )
    os.environ["OLLAMA_HOST"] = ollama_host

    # RAG
    st.sidebar.subheader("Knowledge Base")
    if st.sidebar.button("Re-ingest Docs"):
        with st.spinner("Ingesting docs into ChromaDB..."):
            count = ingest_docs()
            st.session_state.docs_ingested = True
            st.sidebar.success(f"Ingested {count} chunks")

    if st.session_state.docs_ingested:
        st.sidebar.success("Docs loaded")
    else:
        st.sidebar.warning("Docs not ingested yet")

    # Stats
    st.sidebar.subheader("Session Stats")
    st.sidebar.metric("Pending Rules", len(st.session_state.pending_rules))
    st.sidebar.metric("Deployed Rules", len(st.session_state.deployed_rules))


def _display_rule_card(result: dict, index: int):
    """Display a generated rule with approval controls."""
    with st.expander(f"Rule: {result.get('explanation', 'Unnamed rule')[:80]}", expanded=True):
        # nft command
        st.code(result["nft_command"], language="bash")

        # Explanation
        st.markdown(f"**Explanation:** {result.get('explanation', 'N/A')}")

        # Validation status
        validation = result.get("validation", {})
        if validation.get("valid"):
            st.success("Syntax validation: PASSED")
        else:
            errors = validation.get("errors", [])
            st.error(f"Syntax validation: FAILED - {'; '.join(errors)}")

        # Conflicts
        conflicts = result.get("conflicts", {})
        if conflicts.get("has_conflicts"):
            st.warning(
                f"Conflicts detected: {len(conflicts.get('conflicts', []))}"
            )
            for c in conflicts.get("conflicts", []):
                st.markdown(f"- **{c['type']}**: {c['explanation']}")
            for rec in conflicts.get("recommendations", []):
                st.info(f"Recommendation: {rec}")
        else:
            st.success("No conflicts detected")

        # RAG sources
        sources = result.get("rag_sources", [])
        if sources:
            st.caption(f"RAG sources: {', '.join(s for s in sources if s)}")

        # Approval buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Approve & Deploy", key=f"approve_{index}", type="primary"):
                _deploy_rule(result, index)
        with col2:
            if st.button("Reject", key=f"reject_{index}"):
                st.session_state.pending_rules.pop(index)
                st.rerun()


def _deploy_rule(result: dict, index: int):
    """Deploy an approved rule."""
    from afo_mcp.tools.deployer import deploy_policy

    rule_id = f"rule_{len(st.session_state.deployed_rules) + 1}"

    deployment = deploy_policy(
        rule_id=rule_id,
        rule_content=result["nft_command"],
        approved=True,
        enable_heartbeat=True,
    )

    deploy_data = deployment.model_dump()

    if deploy_data["success"]:
        st.success(f"Rule deployed successfully (ID: {rule_id})")
        st.session_state.deployed_rules.append({
            "rule_id": rule_id,
            "nft_command": result["nft_command"],
            "explanation": result.get("explanation", ""),
            "status": "deployed",
        })
    else:
        st.error(f"Deployment failed: {deploy_data.get('error', 'Unknown error')}")
        st.session_state.deployed_rules.append({
            "rule_id": rule_id,
            "nft_command": result["nft_command"],
            "explanation": result.get("explanation", ""),
            "status": f"failed: {deploy_data.get('error', '')}",
        })

    st.session_state.pending_rules.pop(index)
    st.rerun()


def _chat_interface():
    """Main chat interface."""
    st.header("Firewall Rule Generator")
    st.caption("Describe what you want in plain English. Examples:")
    st.caption('"Block all SSH access except from 192.168.1.0/24"')
    st.caption('"Allow HTTP and HTTPS traffic on eth0"')
    st.caption('"Drop all traffic from guest VLAN to database server"')

    # Display chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    if user_input := st.chat_input("Describe your firewall rule..."):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                result = chat(user_input, st.session_state.messages)

            if result["type"] == "rule" and result.get("success"):
                st.markdown(f"**Generated rule:** `{result['nft_command']}`")
                st.markdown(f"\n{result.get('explanation', '')}")

                # Add to pending rules for approval
                st.session_state.pending_rules.append(result)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": (
                        f"Generated rule: `{result['nft_command']}`\n\n"
                        f"{result.get('explanation', '')}\n\n"
                        "Review the rule below and approve or reject it."
                    ),
                })
            elif result["type"] == "rule" and not result.get("success"):
                error_msg = result.get("error", "Failed to generate rule")
                st.error(error_msg)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"Error: {error_msg}",
                })
            else:
                response = result.get("response", "I'm not sure how to help with that.")
                st.markdown(response)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response,
                })


def _pending_rules_panel():
    """Display pending rules awaiting approval."""
    if st.session_state.pending_rules:
        st.header("Pending Rules")
        for i, rule in enumerate(st.session_state.pending_rules):
            _display_rule_card(rule, i)


def _deployment_history():
    """Display deployment history."""
    if st.session_state.deployed_rules:
        st.header("Deployment History")
        for entry in reversed(st.session_state.deployed_rules):
            status_icon = "+" if entry["status"] == "deployed" else "-"
            st.markdown(
                f"**[{status_icon}] {entry['rule_id']}**: "
                f"`{entry['nft_command']}` - {entry['status']}"
            )


def main():
    """Main Streamlit app entry point."""
    st.set_page_config(
        page_title="AFO - Autonomous Firewall Orchestrator",
        page_icon="[shield]",
        layout="wide",
    )

    _init_session_state()

    st.title("AFO - Autonomous Firewall Orchestrator")
    st.caption("Natural Language to nftables - Verified Autonomous Firewall Management")

    _sidebar()

    # Auto-ingest docs on first load
    if not st.session_state.docs_ingested:
        try:
            ingest_docs()
            st.session_state.docs_ingested = True
        except Exception:
            pass

    # Main layout
    tab1, tab2, tab3 = st.tabs(["Chat", "Pending Rules", "History"])

    with tab1:
        _chat_interface()

    with tab2:
        _pending_rules_panel()

    with tab3:
        _deployment_history()


if __name__ == "__main__":
    main()
