"""Textual-based terminal UI for InfraGuard."""

from __future__ import annotations

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical
    from textual.widgets import DataTable, Footer, Header, Label, Static

    class InfraGuardTUI(App):
        """Terminal UI for monitoring InfraGuard."""

        CSS = """
        Screen {
            layout: grid;
            grid-size: 2 3;
            grid-gutter: 1;
        }
        .stat-card {
            height: 5;
            border: solid green;
            padding: 1;
        }
        .stat-card .value {
            text-style: bold;
        }
        #request-log {
            column-span: 2;
            row-span: 2;
            border: solid $accent;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
        ]

        def __init__(self, config_path: str = ""):
            super().__init__()
            self.config_path = config_path

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static("Total Requests: -", id="stat-total", classes="stat-card")
            yield Static("Blocked: -", id="stat-blocked", classes="stat-card")
            yield DataTable(id="request-log")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#request-log", DataTable)
            table.add_columns("Time", "IP", "Method", "URI", "Result", "Reason")
            table.add_row("--:--:--", "0.0.0.0", "GET", "/", "allow", "Starting...")

        def action_refresh(self) -> None:
            self.notify("Refreshing...")

        def action_quit(self) -> None:
            self.exit()

except ImportError:
    # Textual not installed
    class InfraGuardTUI:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            raise ImportError(
                "Textual is required for the TUI. "
                "Install with: pip install infraguard[tui]"
            )

        def run(self):
            raise ImportError("Textual not installed")
