"""Statistics and aggregation queries for the tracking database."""

from __future__ import annotations

from dataclasses import dataclass

from infraguard.tracking.database import Database


@dataclass
class DomainStats:
    domain: str
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    unique_ips: int
    block_rate: float


@dataclass
class OverviewStats:
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    unique_ips: int
    domains: list[DomainStats]
    top_blocked_ips: list[tuple[str, int]]


class StatsQuery:
    """Run aggregation queries against the tracking database."""

    def __init__(self, db: Database):
        self.db = db

    async def overview(self, hours: int = 24) -> OverviewStats:
        time_filter = f"datetime('now', '-{hours} hours')"

        totals = await self.db.fetchone(
            f"""SELECT
                COUNT(*) as total,
                SUM(CASE WHEN filter_result = 'allow' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN filter_result = 'block' THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT client_ip) as unique_ips
            FROM requests WHERE timestamp > {time_filter}"""
        )

        domain_rows = await self.db.fetchall(
            f"""SELECT
                domain,
                COUNT(*) as total,
                SUM(CASE WHEN filter_result = 'allow' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN filter_result = 'block' THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT client_ip) as unique_ips
            FROM requests WHERE timestamp > {time_filter}
            GROUP BY domain"""
        )

        top_blocked = await self.db.fetchall(
            f"""SELECT client_ip, COUNT(*) as cnt
            FROM requests
            WHERE filter_result = 'block' AND timestamp > {time_filter}
            GROUP BY client_ip
            ORDER BY cnt DESC
            LIMIT 10"""
        )

        domains = [
            DomainStats(
                domain=r["domain"],
                total_requests=r["total"],
                allowed_requests=r["allowed"],
                blocked_requests=r["blocked"],
                unique_ips=r["unique_ips"],
                block_rate=r["blocked"] / max(r["total"], 1),
            )
            for r in domain_rows
        ]

        return OverviewStats(
            total_requests=totals["total"] if totals else 0,
            allowed_requests=totals["allowed"] if totals else 0,
            blocked_requests=totals["blocked"] if totals else 0,
            unique_ips=totals["unique_ips"] if totals else 0,
            domains=domains,
            top_blocked_ips=[(r["client_ip"], r["cnt"]) for r in top_blocked],
        )

    async def content_stats(self, hours: int = 24) -> list[dict]:
        """Aggregate content delivery statistics."""
        rows = await self.db.fetchall(
            """SELECT
                domain, uri,
                SUM(CASE WHEN filter_result = 'content_served' THEN 1 ELSE 0 END) as served,
                SUM(CASE WHEN filter_result = 'content_blocked' THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT client_ip) as unique_ips
            FROM requests
            WHERE filter_result IN ('content_served', 'content_blocked')
              AND timestamp > datetime('now', ?)
            GROUP BY domain, uri
            ORDER BY served DESC""",
            (f"-{hours} hours",),
        )
        return rows

    async def recent_requests(
        self, limit: int = 50, domain: str | None = None
    ) -> list[dict]:
        sql = "SELECT * FROM requests"
        params: tuple = ()
        if domain:
            sql += " WHERE domain = ?"
            params = (domain,)
        sql += " ORDER BY id DESC LIMIT ?"
        params = (*params, limit)
        return await self.db.fetchall(sql, params)
