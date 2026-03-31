"""Multi-instance API client with parallel fetch and merge logic."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

import httpx
import structlog

from infraguard.ui.command_post.config import InstanceConfig

log = structlog.get_logger()


class InstanceClient:
    """HTTP client for a single InfraGuard instance."""

    def __init__(self, config: InstanceConfig):
        self.name = config.name
        self.url = config.url.rstrip("/")
        self._token = config.token
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            self._client = httpx.AsyncClient(
                base_url=self.url,
                headers=headers,
                timeout=10.0,
                verify=False,
            )
        return self._client

    async def get_stats(self, hours: int = 24) -> dict[str, Any] | None:
        try:
            resp = await self._get_client().get(f"/api/stats?hours={hours}")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            log.warning("instance_fetch_error", instance=self.name, endpoint="stats")
            return None

    async def get_requests(self, limit: int = 50) -> list[dict] | None:
        try:
            resp = await self._get_client().get(f"/api/requests?limit={limit}")
            resp.raise_for_status()
            data = resp.json()
            return data.get("requests", [])
        except Exception:
            log.warning("instance_fetch_error", instance=self.name, endpoint="requests")
            return None

    async def check_health(self) -> bool:
        try:
            resp = await self._get_client().get("/api/stats?hours=1")
            return resp.status_code == 200
        except Exception:
            return False

    async def post_json(self, path: str, body: dict) -> dict | None:
        try:
            resp = await self._get_client().post(path, json=body)
            return resp.json()
        except Exception:
            return None

    async def delete_json(self, path: str, body: dict) -> dict | None:
        try:
            resp = await self._get_client().request("DELETE", path, json=body)
            return resp.json()
        except Exception:
            return None

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class MultiInstanceAggregator:
    """Fans out API calls to multiple InfraGuard instances and merges results."""

    def __init__(self, instances: list[InstanceConfig]):
        self.clients = [InstanceClient(cfg) for cfg in instances]

    async def get_instances_health(self) -> list[dict]:
        """Check health of all instances."""
        async def _check(client: InstanceClient) -> dict:
            healthy = await client.check_health()
            return {
                "name": client.name,
                "url": client.url,
                "status": "online" if healthy else "offline",
            }
        results = await asyncio.gather(*[_check(c) for c in self.clients])
        return list(results)

    async def get_merged_stats(self, hours: int = 24) -> dict[str, Any]:
        """Fetch stats from all instances and merge."""
        raw_results = await asyncio.gather(
            *[c.get_stats(hours) for c in self.clients]
        )

        total = 0
        allowed = 0
        blocked = 0
        all_ips: set[str] = set()
        domain_map: dict[str, dict] = {}
        blocked_ip_counts: dict[str, int] = defaultdict(int)

        for client, stats in zip(self.clients, raw_results):
            if stats is None:
                continue
            total += stats.get("total_requests", 0) or 0
            allowed += stats.get("allowed_requests", 0) or 0
            blocked += stats.get("blocked_requests", 0) or 0

            for domain in stats.get("domains", []):
                name = domain["domain"]
                if name not in domain_map:
                    domain_map[name] = {
                        "domain": name,
                        "total": 0, "allowed": 0, "blocked": 0,
                        "unique_ips": 0, "instance": client.name,
                    }
                domain_map[name]["total"] += domain.get("total", 0)
                domain_map[name]["allowed"] += domain.get("allowed", 0)
                domain_map[name]["blocked"] += domain.get("blocked", 0)
                domain_map[name]["unique_ips"] += domain.get("unique_ips", 0)

            for entry in stats.get("top_blocked_ips", []):
                blocked_ip_counts[entry["ip"]] += entry["count"]

        # Recalculate block rates
        domains = list(domain_map.values())
        for d in domains:
            d["block_rate"] = round(d["blocked"] / max(d["total"], 1), 3)

        # Sort blocked IPs
        top_blocked = sorted(
            [{"ip": ip, "count": cnt} for ip, cnt in blocked_ip_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        return {
            "total_requests": total,
            "allowed_requests": allowed,
            "blocked_requests": blocked,
            "unique_ips": len(all_ips) if all_ips else (total - blocked),
            "domains": domains,
            "top_blocked_ips": top_blocked,
        }

    async def get_merged_requests(self, limit: int = 50) -> list[dict]:
        """Fetch requests from all instances and interleave by timestamp."""
        raw_results = await asyncio.gather(
            *[c.get_requests(limit) for c in self.clients]
        )

        all_requests: list[dict] = []
        for client, requests in zip(self.clients, raw_results):
            if requests is None:
                continue
            for req in requests:
                req["_instance"] = client.name
                all_requests.append(req)

        # Sort by timestamp descending
        all_requests.sort(
            key=lambda r: r.get("timestamp", ""),
            reverse=True,
        )
        return all_requests[:limit]

    async def fan_out_post(self, path: str, body: dict, instance: str | None = None) -> list[dict]:
        """POST to one or all instances."""
        targets = self.clients if instance is None else [c for c in self.clients if c.name == instance]
        results = await asyncio.gather(*[c.post_json(path, body) for c in targets])
        return [r for r in results if r is not None]

    async def fan_out_delete(self, path: str, body: dict, instance: str | None = None) -> list[dict]:
        """DELETE to one or all instances."""
        targets = self.clients if instance is None else [c for c in self.clients if c.name == instance]
        results = await asyncio.gather(*[c.delete_json(path, body) for c in targets])
        return [r for r in results if r is not None]

    async def close(self) -> None:
        for client in self.clients:
            await client.close()
