from textual.widgets import DataTable


class HistoryTable(DataTable):
    """Table to display deployment history."""

    def on_mount(self) -> None:
        """Initialize the table columns."""
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_columns(
            "Timestamp",
            "Rule ID",
            "Action",
            "Status",
            "Details",
        )

    async def update_history(self, logs: list) -> None:
        """Update the table with a list of logs."""
        self.clear()

        for log in logs:
            # Assuming DeploymentLog model or similar
            # If using SQLAlchemy models, we might need to access attributes
            # Or convert to dict first.

            # Helper for safe access
            def get_val(obj, key):
                return getattr(obj, key, None) if hasattr(obj, key) else obj.get(key)

            self.add_row(
                str(get_val(log, "timestamp") or ""),
                str(get_val(log, "rule_id") or ""),
                "DEPLOY",  # Or map from type if we track other actions
                str(get_val(log, "status") or ""),
                str(get_val(log, "details") or ""),
            )
