"""Built-in InfraGuard plugins."""

BUILTIN_PLUGINS = {
    "elasticsearch": "infraguard.plugins.builtin.elasticsearch",
    "wazuh": "infraguard.plugins.builtin.wazuh",
    "syslog": "infraguard.plugins.builtin.syslog",
    "discord": "infraguard.plugins.builtin.discord",
    "slack": "infraguard.plugins.builtin.slack",
    "generic_webhook": "infraguard.plugins.builtin.generic_webhook",
}
