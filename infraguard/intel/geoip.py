"""GeoIP lookup using MaxMind GeoLite2 databases.

Supports three GeoLite2 database types:
- City   (GeoLite2-City.mmdb)    -- country, city, continent, coordinates
- ASN    (GeoLite2-ASN.mmdb)     -- autonomous system number and organization
- Country (GeoLite2-Country.mmdb) -- country only (lighter than City)

All three are optional. If a City DB is provided, Country is not needed.
ASN is separate and provides ASN/org lookups.
"""

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

    def __init__(
        self,
        city_db: str | None = None,
        asn_db: str | None = None,
        country_db: str | None = None,
    ):
        self._city_reader = None
        self._asn_reader = None
        self._country_reader = None

        try:
            import maxminddb
        except ImportError:
            if city_db or asn_db or country_db:
                log.warning("geoip_unavailable", reason="maxminddb not installed")
            return

        # City DB (has country, city, continent)
        if city_db and Path(city_db).exists():
            try:
                self._city_reader = maxminddb.open_database(city_db)
                log.info("geoip_loaded", type="city", path=city_db)
            except Exception:
                log.exception("geoip_load_error", type="city", path=city_db)

        # Country DB (fallback if no City DB)
        if country_db and Path(country_db).exists():
            try:
                self._country_reader = maxminddb.open_database(country_db)
                log.info("geoip_loaded", type="country", path=country_db)
            except Exception:
                log.exception("geoip_load_error", type="country", path=country_db)

        # ASN DB (separate - provides ASN + org)
        if asn_db and Path(asn_db).exists():
            try:
                self._asn_reader = maxminddb.open_database(asn_db)
                log.info("geoip_loaded", type="asn", path=asn_db)
            except Exception:
                log.exception("geoip_load_error", type="asn", path=asn_db)

    def lookup(self, ip: str) -> GeoInfo:
        info = GeoInfo()

        # Country + City from City DB or Country DB
        geo_reader = self._city_reader or self._country_reader
        if geo_reader:
            try:
                data = geo_reader.get(ip)
                if data:
                    country = data.get("country", {})
                    info.country_code = country.get("iso_code")
                    info.country_name = country.get("names", {}).get("en")
                    info.continent = data.get("continent", {}).get("code")
                    # City is only in the City DB
                    if self._city_reader:
                        info.city = data.get("city", {}).get("names", {}).get("en")
            except Exception:
                pass

        # ASN from ASN DB
        if self._asn_reader:
            try:
                data = self._asn_reader.get(ip)
                if data:
                    info.asn = data.get("autonomous_system_number")
                    info.org = data.get("autonomous_system_organization")
            except Exception:
                pass

        return info

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader, self._country_reader):
            if reader:
                reader.close()
