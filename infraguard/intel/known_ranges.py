"""Built-in CIDR ranges for known security vendors, cloud scanners, and bots.

These ranges are commonly blocked during red team operations to prevent
blue team tools and security vendors from reaching the C2 teamserver.
Based on community-maintained lists (curi0usJack, etc.).
"""

from __future__ import annotations

# Security vendors, sandboxes, and threat intel platforms
SECURITY_VENDOR_CIDRS: list[str] = [
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

# Major cloud providers (operators may want to block these if beacons
# aren't expected from cloud infrastructure)
CLOUD_PROVIDER_CIDRS: dict[str, list[str]] = {
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

# Known bot and crawler User-Agent substrings
BOT_USER_AGENT_PATTERNS: list[str] = [
    "bot",
    "crawl",
    "spider",
    "scan",
    "Shodan",
    "Censys",
    "Nmap",
    "Nikto",
    "Nessus",
    "Qualys",
    "Acunetix",
    "Burp",
    "ZAP",
    "sqlmap",
    "dirbuster",
    "gobuster",
    "ffuf",
    "wfuzz",
    "nuclei",
    "httpx",
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "Go-http-client",
    "Java/",
    "libwww",
    "Googlebot",
    "bingbot",
    "AhrefsBot",
    "SemrushBot",
    "DotBot",
    "MJ12bot",
    "BaiduSpider",
    "YandexBot",
    "PetalBot",
    "facebookexternalhit",
    "Twitterbot",
    "LinkedInBot",
]

# Banned keywords in reverse DNS hostnames
BANNED_RDNS_KEYWORDS: list[str] = [
    "security",
    "scan",
    "crawl",
    "bot",
    "probe",
    "research",
    "censys",
    "shodan",
    "shadowserver",
    "binaryedge",
    "rapid7",
    "qualys",
    "nessus",
    "paloalto",
    "crowdstrike",
    "fireeye",
    "mandiant",
    "symantec",
    "mcafee",
    "trendmicro",
    "sophos",
    "kaspersky",
    "bitdefender",
    "malwarebytes",
    "fortinet",
    "checkpoint",
    "zscaler",
    "cyberark",
    "sentinelone",
    "carbonblack",
    "elastic",
]

# Banned keywords in HTTP header names and values
BANNED_HEADER_KEYWORDS: list[str] = [
    "burp",
    "zap",
    "nikto",
    "nessus",
    "qualys",
    "acunetix",
    "sqlmap",
    "nmap",
    "masscan",
    "wpscan",
    "dirbuster",
]
