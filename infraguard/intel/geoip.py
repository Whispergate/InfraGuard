"""GeoIP lookup using MaxMind GeoLite2 databases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog

log = structlog.get_logger()


@dataclass
class GeoInfo:
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    asn: int | None = None
    org: str | None = None
    continent: str | None = None


class GeoIPLookup:
    """Wraps MaxMind GeoLite2 database lookups."""

    def __init__(self, db_path: str | None = None):
        self._reader = None
        if db_path and Path(db_path).exists():
            try:
                import maxminddb

                self._reader = maxminddb.open_database(db_path)
                log.info("geoip_loaded", path=db_path)
            except ImportError:
                log.warning("geoip_unavailable", reason="maxminddb not installed")
            except Exception:
                log.exception("geoip_load_error", path=db_path)

    def lookup(self, ip: str) -> GeoInfo:
        if not self._reader:
            return GeoInfo()
        try:
            data = self._reader.get(ip)
            if not data:
                return GeoInfo()
            country = data.get("country", {})
            city = data.get("city", {})
            continent = data.get("continent", {})
            traits = data.get("traits", {})
            return GeoInfo(
                country_code=country.get("iso_code"),
                country_name=country.get("names", {}).get("en"),
                city=city.get("names", {}).get("en"),
                asn=traits.get("autonomous_system_number"),
                org=traits.get("autonomous_system_organization"),
                continent=continent.get("code"),
            )
        except Exception:
            return GeoInfo()

    def close(self) -> None:
        if self._reader:
            self._reader.close()
