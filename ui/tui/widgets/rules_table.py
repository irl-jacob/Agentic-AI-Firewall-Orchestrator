from textual.widgets import DataTable


class RulesTable(DataTable):
    """Cyberpunk-styled rules table."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_columns(
            "ID",
            "Name",
            "Action",
            "Dir",
            "Proto",
            "Port",
            "Source",
            "Destination",
        )

    async def update_rules(self, rules: list) -> None:
        self.clear()

        for rule in rules:
            def get_val(obj, key):
                return getattr(obj, key, None) if hasattr(obj, key) else obj.get(key)

            # Color-code action
            action_val = str(get_val(rule, "action") or "")
            action_display = action_val

            self.add_row(
                str(get_val(rule, "id") or "—"),
                str(get_val(rule, "name") or ""),
                action_display,
                str(get_val(rule, "direction") or "")[:3],
                str(get_val(rule, "protocol") or ""),
                str(get_val(rule, "port") or "*"),
                str(get_val(rule, "source") or "*"),
                str(get_val(rule, "destination") or "*"),
            )
