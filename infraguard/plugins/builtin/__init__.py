"""Built-in InfraGuard plugins.

Short-name to fully-qualified module path. Config files and the
dashboard reference plugins by short name; the loader resolves each to
the module here and imports it. The dashboard's "add plugin" picker
enumerates this dict.
"""

_MODULES = [
    # alerters and SIEMs
    "discord",
    "elasticsearch",
    "generic_webhook",
    "pagerduty",
    "slack",
    "syslog",
    "telegram_bot",
    "wazuh",
    # detection / classification
    "greynoise",
    "ml_bot_classifier",
    "response_canary",
    "yara_scan",
    # fingerprint enrichers
    "geoip_enricher",
    "ja4_enricher",
    "p0f_fingerprint",
    "beacon_labeler",
    # request-side mutators / gates
    "js_challenge",
    "html_rewriter",
    "sig_strip",
    "cache_mimicry",
    "http_smuggling",
    "shadow_block",
    "slow_tarpit",
    "stager_rate_limit",
    "payload_shred",
    "payload_watermark",
    # observability / recording
    "prom_custom",
    "request_recorder",
    "timing_profiler",
]

BUILTIN_PLUGINS = {name: f"infraguard.plugins.builtin.{name}" for name in _MODULES}
