"""Statistics and aggregation queries for the tracking database."""

from __future__ import annotations

from dataclasses import dataclass, field

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
    # Per-delivery breakdown; sum <= blocked_requests (leftovers were
    # bare drops with type=reset which count under blocked but not here).
    decoy_requests: int = 0
    tarpit_requests: int = 0
    redirect_requests: int = 0
    # Beacon-side geo, mirror of top_blocked_ips. Feeds the Command
    # Post Fleet Map's green "allowed" dots.
    top_allowed_ips: list[tuple[str, int]] = field(default_factory=list)


class StatsQuery:
    """Run aggregation queries against the tracking database."""

    def __init__(self, db: Database):
        self.db = db

    async def overview(self, hours: int = 24) -> OverviewStats:
        time_param = f"-{int(hours)} hours"

        # ``block`` here means "did not reach the C2 upstream" and now
        # includes the delivery-method verdicts the router writes for
        # decoy/tarpit/redirect/reset. The individual counts are kept
        # for the Overview KPI tile that breaks them out.
        _DROP_SQL = (
            "filter_result IN ('block','decoy','tarpit','redirect','reset')"
        )
        totals = await self.db.fetchone(
            f"""SELECT
                COUNT(*) as total,
                SUM(CASE WHEN filter_result = 'allow' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN {_DROP_SQL} THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN filter_result = 'decoy' THEN 1 ELSE 0 END) as decoy,
                SUM(CASE WHEN filter_result = 'tarpit' THEN 1 ELSE 0 END) as tarpit,
                SUM(CASE WHEN filter_result = 'redirect' THEN 1 ELSE 0 END) as redirect,
                COUNT(DISTINCT client_ip) as unique_ips
            FROM requests WHERE timestamp > datetime('now', ?)""",
            (time_param,),
        )

        domain_rows = await self.db.fetchall(
            f"""SELECT
                domain,
                COUNT(*) as total,
                SUM(CASE WHEN filter_result = 'allow' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN {_DROP_SQL} THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT client_ip) as unique_ips
            FROM requests WHERE timestamp > datetime('now', ?)
            GROUP BY domain""",
            (time_param,),
        )

        top_blocked = await self.db.fetchall(
            f"""SELECT client_ip, COUNT(*) as cnt
            FROM requests
            WHERE {_DROP_SQL} AND timestamp > datetime('now', ?)
            GROUP BY client_ip
            ORDER BY cnt DESC
            LIMIT 10""",
            (time_param,),
        )

        top_allowed = await self.db.fetchall(
            """SELECT client_ip, COUNT(*) as cnt
            FROM requests
            WHERE filter_result = 'allow' AND timestamp > datetime('now', ?)
            GROUP BY client_ip
            ORDER BY cnt DESC
            LIMIT 10""",
            (time_param,),
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
            decoy_requests=(totals["decoy"] or 0) if totals else 0,
            tarpit_requests=(totals["tarpit"] or 0) if totals else 0,
            redirect_requests=(totals["redirect"] or 0) if totals else 0,
            top_allowed_ips=[(r["client_ip"], r["cnt"]) for r in top_allowed],
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
        self,
        limit: int = 50,
        domain: str | None = None,
        filter_result: str | None = None,
    ) -> list[dict]:
        """Return recent request rows, most-recent first.

        ``filter_result`` accepts either a single verdict
        (``canary_hit``, ``allow``, ``block`` …) or a comma-separated
        list. Handy for the dashboard's Canary Hits panel, which only
        needs ``canary_hit`` rows and would otherwise miss them behind
        a wall of newer block traffic.
        """
        clauses: list[str] = []
        params: tuple = ()
        if domain:
            clauses.append("domain = ?")
            params = (*params, domain)
        if filter_result:
            values = [v.strip() for v in filter_result.split(",") if v.strip()]
            if values:
                placeholders = ",".join(["?"] * len(values))
                clauses.append(f"filter_result IN ({placeholders})")
                params = (*params, *values)
        sql = "SELECT * FROM requests"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params = (*params, limit)
        return await self.db.fetchall(sql, params)
