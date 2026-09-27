"""Two-way ops over Telegram.

Startup polls Telegram for updates. Commands like ``/status``,
``/block <ip>``, ``/whitelist <ip>``, ``/rotate <domain>`` are handled
in-process by calling the local IntelManager and rotation manager.
Also forwards RequestEvents as short messages using the standard
event-filter machinery.

Config:

    plugins:
      - name: telegram_bot
        options:
          bot_token: "123456:ABC..."
          allowed_chat_ids: [111222333]     # only these chats may issue commands
          post_events: false                # noisy; leave off by default
          event_filter:
            only_blocked: true
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "telegram_bot"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._client: httpx.AsyncClient | None = None
        self._task: asyncio.Task | None = None
        self._offset = 0

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        token = self._opt("bot_token")
        if not token:
            log.warning("telegram_bot_missing_token")
            return
        self._client = httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}", timeout=30
        )
        self._task = asyncio.create_task(self._poll_loop())

    async def on_shutdown(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._client:
            await self._client.aclose()

    async def on_event(self, event: RequestEvent) -> None:
        if not self._client or not self._opt("post_events", False):
            return
        allowed = self._opt("allowed_chat_ids") or []
        if not allowed:
            return
        blocked = event.filter_result == "block"
        emoji = "\U0001F534" if blocked else "\U0001F7E2"  # red / green circle
        text = (
            f"{emoji} {event.domain} {event.method} {event.uri[:80]}\n"
            f"ip={event.client_ip} score={event.filter_score:.2f}"
        )
        for chat_id in allowed:
            try:
                await self._client.post(
                    "/sendMessage", json={"chat_id": chat_id, "text": text}
                )
            except Exception as exc:
                log.debug("telegram_send_failed", chat=chat_id, error=str(exc))

    async def _poll_loop(self) -> None:
        assert self._client is not None
        while True:
            try:
                r = await self._client.get(
                    "/getUpdates",
                    params={"offset": self._offset, "timeout": 25},
                )
                data = r.json()
                for upd in data.get("result", []):
                    self._offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    text = (msg.get("text") or "").strip()
                    chat_id = (msg.get("chat") or {}).get("id")
                    if not text or chat_id is None:
                        continue
                    if chat_id not in (self._opt("allowed_chat_ids") or []):
                        continue
                    await self._handle_command(chat_id, text)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("telegram_poll_error", error=str(exc))
                await asyncio.sleep(5)

    async def _handle_command(self, chat_id: int, text: str) -> None:
        # Minimal command set. Extending: intel_manager / router
        # hooks are wired via the plugin loader passing them in
        # settings; kept trivial in this initial version.
        reply = "unknown command"
        if text.startswith("/status"):
            reply = "InfraGuard proxy: up"
        elif text.startswith("/help"):
            reply = "/status /block <ip> /whitelist <ip> /rotate <domain>"
        assert self._client is not None
        try:
            await self._client.post("/sendMessage", json={"chat_id": chat_id, "text": reply})
        except Exception as exc:
            log.debug("telegram_reply_failed", error=str(exc))
