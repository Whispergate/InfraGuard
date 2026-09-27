"""Built-in CIDR / UA / keyword lists.

These are the seed lists InfraGuard has always shipped with. As of v0.5
they live in the ``rules/`` tree as plain text files so operators can
update signatures without a code release; the Python constants below are
kept as a fallback for environments where the ``rules/`` directory has
been stripped (single-file installs, tests) and as the source-of-truth
that seeds newly-generated ``rules/`` files.

Consumers should import these names as before - they resolve at import
time to whatever is on disk, with the Python fallback if the file is
missing.
"""

from __future__ import annotations

from infraguard.intel.rules_loader import load_grouped, load_list

# ---------------------------------------------------------------------------
# Compile-time fallbacks. Kept verbatim so removing the ``rules/`` tree
# leaves the tool functionally identical to prior releases.
# ---------------------------------------------------------------------------

_FALLBACK_SECURITY_VENDOR_CIDRS: list[str] = [
    # Shodan
    "66.240.192.0/18",
    "71.6.128.0/17",
    "198.20.64.0/18",
    # Censys
    "162.142.125.0/24",
    "167.94.138.0/24",
    "167.94.145.0/24",
    "167.94.146.0/24",
    "167.248.133.0/24",
    # BinaryEdge
    "37.9.12.0/24",
    # SecurityTrails
    "52.250.0.0/16",
    # VirusTotal
    "74.125.0.0/16",
    # ZoomEye
    "106.75.0.0/16",
    # Rapid7 (Project Sonar)
    "5.63.151.0/24",
    "71.6.233.0/24",
    # Shadowserver
    "64.62.202.0/24",
    "184.105.139.0/24",
    "184.105.247.0/24",
    # Palo Alto Networks
    "204.232.0.0/16",
    # CrowdStrike Falcon sandbox IPs (commonly seen)
    "54.208.0.0/15",
]

_FALLBACK_CLOUD_PROVIDER_CIDRS: dict[str, list[str]] = {
    "aws_common": [
        "3.0.0.0/8",
        "52.0.0.0/8",
        "54.0.0.0/8",
    ],
    "azure_common": [
        "13.64.0.0/11",
        "20.0.0.0/8",
        "40.64.0.0/10",
    ],
    "gcp_common": [
        "34.0.0.0/8",
        "35.184.0.0/13",
    ],
    "digitalocean": [
        "104.131.0.0/16",
        "137.184.0.0/16",
        "143.198.0.0/16",
        "157.245.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "161.35.0.0/16",
        "164.90.0.0/16",
        "167.71.0.0/16",
        "167.172.0.0/16",
        "174.138.0.0/16",
        "178.128.0.0/16",
        "178.62.0.0/16",
        "188.166.0.0/16",
        "206.189.0.0/16",
    ],
}

_FALLBACK_BOT_USER_AGENT_PATTERNS: list[str] = [
    "bot", "crawl", "spider", "scan", "Shodan", "Censys", "Nmap", "Nikto",
    "Nessus", "Qualys", "Acunetix", "Burp", "ZAP", "sqlmap", "dirbuster",
    "gobuster", "ffuf", "wfuzz", "nuclei", "httpx", "curl", "wget",
    "python-requests", "python-urllib", "Go-http-client", "Java/", "libwww",
    "Googlebot", "bingbot", "AhrefsBot", "SemrushBot", "DotBot", "MJ12bot",
    "BaiduSpider", "YandexBot", "PetalBot", "facebookexternalhit",
    "Twitterbot", "LinkedInBot",
]

_FALLBACK_BANNED_RDNS_KEYWORDS: list[str] = [
    "security", "scan", "crawl", "bot", "probe", "research", "censys",
    "shodan", "shadowserver", "binaryedge", "rapid7", "qualys", "nessus",
    "paloalto", "crowdstrike", "fireeye", "mandiant", "symantec", "mcafee",
    "trendmicro", "sophos", "kaspersky", "bitdefender", "malwarebytes",
    "fortinet", "checkpoint", "zscaler", "cyberark", "sentinelone",
    "carbonblack", "elastic",
]

_FALLBACK_BANNED_HEADER_KEYWORDS: list[str] = [
    "burp", "zap", "nikto", "nessus", "qualys", "acunetix", "sqlmap",
    "nmap", "masscan", "wpscan", "dirbuster",
]

# ---------------------------------------------------------------------------
# Public constants. These are resolved once at import; call ``reload()``
# to re-read the ``rules/`` tree from disk.
# ---------------------------------------------------------------------------

SECURITY_VENDOR_CIDRS: list[str] = []
CLOUD_PROVIDER_CIDRS: dict[str, list[str]] = {}
BOT_USER_AGENT_PATTERNS: list[str] = []
BANNED_RDNS_KEYWORDS: list[str] = []
BANNED_HEADER_KEYWORDS: list[str] = []


def reload() -> None:
    """Refresh the module-level constants from ``rules/*.txt``.

    Called at import; also safe to call from a SIGHUP or dashboard reload
    endpoint. Mutates the exported lists in place so existing references
    (e.g. filters that captured them at construction) also see the update
    when they copy on next construction.
    """
    SECURITY_VENDOR_CIDRS[:] = load_list(
        "scanner_cidrs.txt", fallback=_FALLBACK_SECURITY_VENDOR_CIDRS
    )
    CLOUD_PROVIDER_CIDRS.clear()
    CLOUD_PROVIDER_CIDRS.update(
        load_grouped("cloud_cidrs.txt", fallback=_FALLBACK_CLOUD_PROVIDER_CIDRS)
    )
    BOT_USER_AGENT_PATTERNS[:] = load_list(
        "scanner_uas.txt", fallback=_FALLBACK_BOT_USER_AGENT_PATTERNS
    )
    BANNED_RDNS_KEYWORDS[:] = load_list(
        "banned_rdns.txt", fallback=_FALLBACK_BANNED_RDNS_KEYWORDS
    )
    BANNED_HEADER_KEYWORDS[:] = load_list(
        "banned_headers.txt", fallback=_FALLBACK_BANNED_HEADER_KEYWORDS
    )


reload()
