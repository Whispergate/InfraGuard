"""Textual-based terminal UI for InfraGuard."""

from __future__ import annotations

try:
    import httpx
    from textual import work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Grid, Horizontal, Vertical
    from textual.screen import Screen
    from textual.widgets import (
        Button,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        Static,
    )

    # ── API Client ────────────────────────────────────────────────────

    class APIClient:
        """Async HTTP client for the InfraGuard dashboard API."""

        def __init__(self, base_url: str, token: str = ""):
            self.base_url = base_url.rstrip("/")
            self.token = token
            self._client: httpx.AsyncClient | None = None

        def _get_client(self) -> httpx.AsyncClient:
            if self._client is None or self._client.is_closed:
                headers = {}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                self._client = httpx.AsyncClient(
                    base_url=self.base_url,
                    headers=headers,
                    timeout=10.0,
                    verify=False,
                )
            return self._client

        async def get_stats(self, hours: int = 24) -> dict:
            resp = await self._get_client().get(f"/api/stats?hours={hours}")
            resp.raise_for_status()
            return resp.json()

        async def get_requests(self, limit: int = 100) -> list[dict]:
            resp = await self._get_client().get(f"/api/requests?limit={limit}")
            resp.raise_for_status()
            data = resp.json()
            return data.get("requests", [])

        async def check_connection(self) -> bool:
            try:
                resp = await self._get_client().get("/api/stats?hours=1")
                return resp.status_code == 200
            except Exception:
                return False

        async def close(self) -> None:
            if self._client and not self._client.is_closed:
                await self._client.aclose()

    # ── Login Screen ──────────────────────────────────────────────────

    class LoginScreen(Screen):
        """Login screen to enter dashboard URL and API token."""

        CSS = """
        LoginScreen {
            align: center middle;
        }
        #login-box {
            width: 70;
            height: auto;
            border: solid $accent;
            padding: 1 2;
        }
        #login-title {
            text-align: center;
            text-style: bold;
            color: $accent;
            margin-bottom: 1;
        }
        #login-subtitle {
            text-align: center;
            color: $text-muted;
            margin-bottom: 1;
        }
        .login-label {
            margin-top: 1;
            color: $text;
        }
        #login-error {
            color: $error;
            text-align: center;
            margin-top: 1;
        }
        #connect-btn {
            margin-top: 1;
            width: 100%;
        }
        """

        BINDINGS = [Binding("escape", "quit", "Quit")]

        def __init__(
            self,
            default_url: str = "http://127.0.0.1:8080",
            default_token: str = "",
        ):
            super().__init__()
            self._default_url = default_url
            self._default_token = default_token

        def compose(self) -> ComposeResult:
            with Vertical(id="login-box"):
                yield Static("InfraGuard", id="login-title")
                yield Static("Connect to Dashboard API", id="login-subtitle")
                yield Label("Dashboard URL", classes="login-label")
                yield Input(
                    value=self._default_url,
                    placeholder="http://host:port",
                    id="url-input",
                )
                yield Label("API Token", classes="login-label")
                yield Input(
                    value=self._default_token,
                    placeholder="Bearer token (leave empty if auth disabled)",
                    password=True,
                    id="token-input",
                )
                yield Static("", id="login-error")
                yield Button("Connect", variant="primary", id="connect-btn")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "connect-btn":
                self._try_connect()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self._try_connect()

        @work
        async def _try_connect(self) -> None:
            url_input = self.query_one("#url-input", Input)
            token_input = self.query_one("#token-input", Input)
            error_label = self.query_one("#login-error", Static)
            btn = self.query_one("#connect-btn", Button)

            url = url_input.value.strip()
            token = token_input.value.strip()

            if not url:
                error_label.update("URL is required")
                return

            btn.disabled = True
            btn.label = "Connecting..."
            error_label.update("")

            client = APIClient(url, token)
            ok = await client.check_connection()

            if ok:
                self.app._api_client = client  # type: ignore[attr-defined]
                self.app.push_screen(DashboardScreen())
            else:
                await client.close()
                error_label.update("Connection failed. Check URL and token.")
                btn.disabled = False
                btn.label = "Connect"

        def action_quit(self) -> None:
            self.app.exit()

    # ── Dashboard Screen ──────────────────────────────────────────────

    class DashboardScreen(Screen):
        """Main dashboard showing live stats and request log."""

        CSS = """
        DashboardScreen {
            layout: grid;
            grid-size: 4 4;
            grid-gutter: 1;
            grid-rows: 5 1 1fr 1fr;
        }
        .stat-card {
            border: solid $accent;
            padding: 0 1;
            height: 5;
        }
        .stat-label {
            color: $text-muted;
        }
        .stat-value {
            text-style: bold;
            height: 2;
        }
        #stat-total .stat-value { color: $text; }
        #stat-allowed .stat-value { color: $success; }
        #stat-blocked .stat-value { color: $error; }
        #stat-ips .stat-value { color: $warning; }
        #status-bar {
            column-span: 4;
            height: 1;
            color: $text-muted;
        }
        #request-table {
            column-span: 4;
            row-span: 2;
            border: solid $accent;
        }
        .connected { color: $success; }
        .disconnected { color: $error; }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("escape", "go_back", "Back"),
        ]

        def compose(self) -> ComposeResult:
            yield Vertical(
                Static("Total Requests", classes="stat-label"),
                Static("-", id="val-total", classes="stat-value"),
                id="stat-total",
                classes="stat-card",
            )
            yield Vertical(
                Static("Allowed", classes="stat-label"),
                Static("-", id="val-allowed", classes="stat-value"),
                id="stat-allowed",
                classes="stat-card",
            )
            yield Vertical(
                Static("Blocked", classes="stat-label"),
                Static("-", id="val-blocked", classes="stat-value"),
                id="stat-blocked",
                classes="stat-card",
            )
            yield Vertical(
                Static("Unique IPs", classes="stat-label"),
                Static("-", id="val-ips", classes="stat-value"),
                id="stat-ips",
                classes="stat-card",
            )
            yield Static(
                "[@click=refresh]Connecting...[/]",
                id="status-bar",
            )
            yield DataTable(id="request-table")

        def on_mount(self) -> None:
            table = self.query_one("#request-table", DataTable)
            table.add_columns("Time", "Domain", "IP", "Method", "URI", "Result", "Reason")
            table.cursor_type = "row"
            self.refresh_data()
            self.set_interval(5, self.refresh_data)

        @work
        async def refresh_data(self) -> None:
            client: APIClient = self.app._api_client  # type: ignore[attr-defined]
            status = self.query_one("#status-bar", Static)

            try:
                stats = await client.get_stats(hours=24)
                requests = await client.get_requests(limit=100)

                # Update stat cards
                self.query_one("#val-total", Static).update(
                    str(stats.get("total_requests", 0))
                )
                allowed = stats.get("allowed_requests") or 0
                blocked = stats.get("blocked_requests") or 0
                self.query_one("#val-allowed", Static).update(str(allowed))
                self.query_one("#val-blocked", Static).update(str(blocked))
                self.query_one("#val-ips", Static).update(
                    str(stats.get("unique_ips", 0))
                )

                # Update request table
                table = self.query_one("#request-table", DataTable)
                table.clear()
                for row in requests:
                    ts = (row.get("timestamp") or "")
                    # Extract HH:MM:SS from ISO timestamp
                    time_str = ts[11:19] if len(ts) > 19 else ts
                    result = row.get("filter_result", "")
                    result_display = (
                        f"[green]{result}[/]"
                        if result == "allow"
                        else f"[red]{result}[/]"
                    )
                    reason = row.get("filter_reason") or ""
                    if len(reason) > 50:
                        reason = reason[:47] + "..."
                    table.add_row(
                        time_str,
                        row.get("domain", ""),
                        row.get("client_ip", ""),
                        row.get("method", ""),
                        row.get("uri", ""),
                        result_display,
                        reason,
                    )

                status.update(
                    f"[green]Connected[/] to {client.base_url}  |  "
                    f"Total: {stats.get('total_requests', 0)}  "
                    f"Blocked: {blocked}  "
                    f"[dim]Auto-refresh: 5s[/]"
                )

            except Exception:
                status.update(
                    f"[red]Disconnected[/] from {client.base_url}  |  "
                    f"[dim]Retrying in 5s...[/]"
                )

        def action_refresh(self) -> None:
            self.refresh_data()

        def action_quit(self) -> None:
            self.app.exit()

        def action_go_back(self) -> None:
            self.app.pop_screen()

    # ── Main App ──────────────────────────────────────────────────────

    class InfraGuardTUI(App):
        """Terminal UI for monitoring InfraGuard."""

        TITLE = "InfraGuard"

        CSS = """
        Screen {
            background: $surface;
        }
        """

        def __init__(
            self,
            config_path: str = "",
            api_url: str = "",
            api_token: str = "",
        ):
            super().__init__()
            self._config_path = config_path
            self._api_url = api_url
            self._api_token = api_token
            self._api_client: APIClient | None = None

        def on_mount(self) -> None:
            # Resolve defaults from config if available
            url = self._api_url
            token = self._api_token

            if self._config_path and (not url or not token):
                try:
                    from infraguard.config.loader import load_config

                    cfg = load_config(self._config_path)
                    if not url:
                        url = f"http://{cfg.api.bind}:{cfg.api.port}"
                    if not token and cfg.api.auth_token:
                        token = cfg.api.auth_token
                except Exception:
                    pass

            url = url or "http://127.0.0.1:8080"

            # If we have both URL and token, try auto-connect
            if url and token:
                self._api_client = APIClient(url, token)
                self.push_screen(DashboardScreen())
            else:
                self.push_screen(LoginScreen(default_url=url, default_token=token))

except ImportError:
    class InfraGuardTUI:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            raise ImportError(
                "Textual is required for the TUI. "
                "Install with: pip install infraguard[tui]"
            )

        def run(self):
            raise ImportError("Textual not installed")
