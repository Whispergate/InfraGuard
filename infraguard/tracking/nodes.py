"""Node registry for tracking redirector instances."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from infraguard.tracking.database import Database


class NodeRegistry:
    """Manage redirector node registration and heartbeats."""

    def __init__(self, db: Database):
        self.db = db

    async def register(
        self, name: str, address: str, domains: list[str]
    ) -> str:
        node_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute(
            """INSERT OR REPLACE INTO nodes (id, name, address, domains, last_heartbeat, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (node_id, name, address, json.dumps(domains), now),
        )
        await self.db.conn.commit()
        return node_id

    async def heartbeat(self, node_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute(
            "UPDATE nodes SET last_heartbeat = ?, status = 'active' WHERE id = ?",
            (now, node_id),
        )
        await self.db.conn.commit()

    async def list_nodes(self) -> list[dict]:
        return await self.db.fetchall("SELECT * FROM nodes ORDER BY name")

    async def remove(self, node_id: str) -> None:
        await self.db.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        await self.db.conn.commit()
