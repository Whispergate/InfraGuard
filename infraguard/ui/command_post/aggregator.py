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
        self._verify_ssl = getattr(config, "verify_ssl", False)
        self.lat = getattr(config, "lat", None)
        self.lon = getattr(config, "lon", None)
        self._client: httpx.AsyncClient | None = None
        # Populated by check_health(): the exception string of the last
        # health probe, so the UI can render "why is this offline".
        self.last_error: str | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {}
            if self._token:
                # An unresolved ${VAR} placeholder points at a missing env
                # var - very common misconfig - log once so the operator
                # sees it in the CP log instead of blaming SSL.
                if self._token.startswith("${") and self._token.endswith("}"):
                    log.warning(
                        "instance_token_unresolved",
                        instance=self.name,
                        placeholder=self._token,
                    )
                headers["Authorization"] = f"Bearer {self._token}"
            # InfraGuard proxies typically serve a self-signed cert on the
            # dashboard port, so verification is off by default. Operators
            # who front their instance with a real CA can flip verify_ssl
            # to true in the CP's instances[] config.
            self._client = httpx.AsyncClient(
                base_url=self.url,
                headers=headers,
                timeout=10.0,
                verify=self._verify_ssl,
                follow_redirects=True,
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
        """Return True when the instance answers 200 to a cheap probe.
        Captures the failure reason into ``self.last_error`` so the CP UI
        can render it - very common ones: TLS verify (self-signed +
        verify_ssl:true), DNS (wrong service name), timeout, 401."""
        try:
            resp = await self._get_client().get("/api/stats?hours=1")
            if resp.status_code == 200:
                self.last_error = None
                return True
            if resp.status_code in (401, 403):
                self.last_error = (
                    f"HTTP {resp.status_code} - token rejected "
                    f"(check instances[].token)"
                )
            else:
                self.last_error = f"HTTP {resp.status_code}"
            return False
        except httpx.ConnectError as exc:
            self.last_error = f"connect failed: {exc}"
            return False
        except httpx.TimeoutException:
            self.last_error = "timeout after 10s"
            return False
        except Exception as exc:
            # ssl.SSLCertVerificationError etc. land here.
            reason = str(exc) or exc.__class__.__name__
            if "certificate" in reason.lower() or "ssl" in reason.lower():
                self.last_error = (
                    "TLS verify failed - set verify_ssl:false on this "
                    "instance if it uses a self-signed cert"
                )
            else:
                self.last_error = reason
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

    async def list_plugins(self) -> dict | None:
        """GET /api/plugins on this instance."""
        try:
            resp = await self._get_client().get("/api/plugins")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            log.warning("instance_fetch_error", instance=self.name, endpoint="plugins")
            return None

    async def toggle_plugin(self, name: str, enabled: bool) -> dict | None:
        """POST /api/plugins/{name}/enable|disable on this instance."""
        verb = "enable" if enabled else "disable"
        try:
            resp = await self._get_client().post(f"/api/plugins/{name}/{verb}")
            return resp.json()
        except Exception as exc:
            log.warning(
                "plugin_toggle_forward_failed",
                instance=self.name, plugin=name, enabled=enabled, error=str(exc),
            )
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
            entry: dict = {
                "name": client.name,
                "url": client.url,
                "status": "online" if healthy else "offline",
            }
            if not healthy and client.last_error:
                entry["error"] = client.last_error
            if client.lat is not None and client.lon is not None:
                entry["lat"] = client.lat
                entry["lon"] = client.lon
            return entry
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
        unique_ips_sum = 0
        domain_map: dict[str, dict] = {}
        blocked_ip_counts: dict[str, int] = defaultdict(int)
        allowed_ip_counts: dict[str, int] = defaultdict(int)
        # Remember the first geo signal we see for each IP so the Fleet
        # Map's dots have real coordinates. Instances without a GeoIP
        # DB drop the fields silently.
        blocked_ip_geo: dict[str, dict] = {}
        allowed_ip_geo: dict[str, dict] = {}

        for client, stats in zip(self.clients, raw_results):
            if stats is None:
                continue
            total += stats.get("total_requests", 0) or 0
            allowed += stats.get("allowed_requests", 0) or 0
            blocked += stats.get("blocked_requests", 0) or 0
            unique_ips_sum += stats.get("unique_ips", 0) or 0

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
                ip = entry["ip"]
                blocked_ip_counts[ip] += entry["count"]
                if ip not in blocked_ip_geo:
                    geo = {k: entry[k] for k in ("lat", "lon", "country", "city", "asn")
                           if k in entry and entry[k] is not None}
                    if geo:
                        blocked_ip_geo[ip] = geo

            for entry in stats.get("top_allowed_ips", []):
                ip = entry["ip"]
                allowed_ip_counts[ip] += entry["count"]
                if ip not in allowed_ip_geo:
                    geo = {k: entry[k] for k in ("lat", "lon", "country", "city", "asn")
                           if k in entry and entry[k] is not None}
                    if geo:
                        allowed_ip_geo[ip] = geo

        # Recalculate block rates
        domains = list(domain_map.values())
        for d in domains:
            d["block_rate"] = round(d["blocked"] / max(d["total"], 1), 3)

        # Sort blocked IPs, carrying the geo enrichment across so the
        # Command Post's Fleet Map can render each source as a red dot
        # without a second lookup round-trip.
        top_blocked = sorted(
            [{"ip": ip, "count": cnt, **blocked_ip_geo.get(ip, {})}
             for ip, cnt in blocked_ip_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        top_allowed = sorted(
            [{"ip": ip, "count": cnt, **allowed_ip_geo.get(ip, {})}
             for ip, cnt in allowed_ip_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        return {
            "total_requests": total,
            "allowed_requests": allowed,
            "blocked_requests": blocked,
            "unique_ips": unique_ips_sum,
            "domains": domains,
            "top_blocked_ips": top_blocked,
            "top_allowed_ips": top_allowed,
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

    async def list_plugins_all(self) -> list[dict]:
        """Fetch the plugin roster from every instance, tagged by instance."""
        async def _one(client: InstanceClient) -> dict:
            data = await client.list_plugins()
            return {
                "instance": client.name,
                "url": client.url,
                "reachable": data is not None,
                "data": data or {},
            }
        results = await asyncio.gather(*[_one(c) for c in self.clients])
        return list(results)

    async def toggle_plugin_all(
        self, name: str, enabled: bool, instance: str | None = None,
    ) -> list[dict]:
        """Toggle a plugin on one instance (by ``instance`` name) or all."""
        targets = self.clients if instance is None else [c for c in self.clients if c.name == instance]
        results = await asyncio.gather(*[c.toggle_plugin(name, enabled) for c in targets])
        return [
            {"instance": c.name, "url": c.url, "result": r}
            for c, r in zip(targets, results)
        ]

    async def close(self) -> None:
        for client in self.clients:
            await client.close()
