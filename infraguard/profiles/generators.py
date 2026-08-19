"""Profile generators — produce native-format C2 profile text from wizard parameters.

Each generator accepts a dict of common + type-specific parameters and returns
a string in the profile's native format (CS DSL, JSON, TOML, YAML).  Every
generator validates its output by round-tripping through the corresponding
parser, so callers are guaranteed a well-formed profile.
"""

from __future__ import annotations

import json
from typing import Any


# ── Shared helpers ───────────────────────────────────────────────────────

def _esc_cs(s: str) -> str:
    """Escape a string for Cobalt Strike profile DSL (double-quoted)."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _get(params: dict, key: str, default: Any = None) -> Any:
    return params.get(key, default)


def _get_list(params: dict, key: str) -> list[str]:
    val = params.get(key, [])
    if isinstance(val, str):
        return [u.strip() for u in val.replace(",", "\n").split("\n") if u.strip()]
    return list(val) if val else []


def _get_headers(params: dict, key: str) -> dict[str, str]:
    val = params.get(key, {})
    if isinstance(val, list):
        result: dict[str, str] = {}
        for item in val:
            if isinstance(item, dict) and "name" in item and "value" in item:
                result[item["name"]] = item["value"]
        return result
    return dict(val) if val else {}


def _get_transforms(params: dict) -> list[dict[str, str]]:
    val = params.get("transforms", [])
    if not val:
        return []
    return [t if isinstance(t, dict) else {"action": str(t)} for t in val]


_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


# ── Cobalt Strike (.profile DSL) ────────────────────────────────────────

def _cs_transform_block(transforms: list[dict[str, str]], block_name: str) -> str:
    """Build a CS metadata/id/output block with transforms."""
    lines = [f"        {block_name} {{"]
    for t in transforms:
        action = t.get("action", "")
        value = t.get("value", "")
        if action in ("base64", "base64url", "mask", "netbios", "netbiosu"):
            lines.append(f"            {action};")
        elif action in ("prepend", "append"):
            lines.append(f'            {action} "{_esc_cs(value)}";')
        elif action == "strrep" and "|" in value:
            old, new = value.split("|", 1)
            lines.append(f'            strrep "{_esc_cs(old)}" "{_esc_cs(new)}";')
    return "\n".join(lines)


def generate_cobalt_strike_profile(params: dict) -> str:
    name = _get(params, "name", "Generated Profile")
    ua = _get(params, "useragent", _DEFAULT_UA)
    sleep = _get(params, "sleeptime", 60000)
    jitter = _get(params, "jitter", 0)
    get_uris = _get_list(params, "get_uris") or ["/activity"]
    post_uris = _get_list(params, "post_uris") or ["/submit.php"]
    stager_uris = _get_list(params, "stager_uris")
    client_headers = _get_headers(params, "client_headers")
    server_headers = _get_headers(params, "server_headers")
    msg_loc = _get(params, "message_location", "cookie")
    msg_name = _get(params, "message_name", "__session")
    transforms = _get_transforms(params)

    lines = [
        f'set sample_name "{_esc_cs(name)}";',
        f'set sleeptime "{sleep}";',
        f'set jitter    "{jitter}";',
        f'set useragent "{_esc_cs(ua)}";',
        "",
    ]

    # http-get block
    uri_str = " ".join(get_uris)
    lines.append("http-get {")
    lines.append(f'    set uri "{_esc_cs(uri_str)}";')
    lines.append("")
    lines.append("    client {")
    for hk, hv in client_headers.items():
        lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
    meta_block = _cs_transform_block(transforms, "metadata")
    lines.append(meta_block)
    if msg_loc == "cookie":
        lines.append(f'            prepend "{_esc_cs(msg_name)}=";')
        lines.append('            header "Cookie";')
    elif msg_loc == "header":
        lines.append(f'            header "{_esc_cs(msg_name)}";')
    elif msg_loc == "parameter":
        lines.append(f'            parameter "{_esc_cs(msg_name)}";')
    elif msg_loc == "uri-append":
        lines.append("            uri-append;")
    else:
        lines.append("            print;")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    server {")
    for hk, hv in server_headers.items():
        lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
    lines.append("        output {")
    lines.append("            print;")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # http-post block
    post_uri_str = " ".join(post_uris)
    lines.append("http-post {")
    lines.append(f'    set uri "{_esc_cs(post_uri_str)}";')
    lines.append("")
    lines.append("    client {")
    for hk, hv in client_headers.items():
        lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
    lines.append("        id {")
    if msg_loc == "cookie":
        lines.append(f'            prepend "{_esc_cs(msg_name)}=";')
        lines.append('            header "Cookie";')
    elif msg_loc == "header":
        lines.append(f'            header "{_esc_cs(msg_name)}";')
    elif msg_loc == "parameter":
        lines.append(f'            parameter "{_esc_cs(msg_name)}";')
    else:
        lines.append("            base64;")
        lines.append('            header "X-Request-ID";')
    lines.append("        }")
    lines.append("        output {")
    lines.append("            print;")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    server {")
    for hk, hv in server_headers.items():
        lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
    lines.append("        output {")
    lines.append("            print;")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")

    # http-stager block (optional)
    if stager_uris:
        lines.append("")
        lines.append("http-stager {")
        if len(stager_uris) >= 1:
            lines.append(f'    set uri_x86 "{_esc_cs(stager_uris[0])}";')
        if len(stager_uris) >= 2:
            lines.append(f'    set uri_x64 "{_esc_cs(stager_uris[1])}";')
        lines.append("    client {")
        for hk, hv in client_headers.items():
            lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
        lines.append("    }")
        lines.append("    server {")
        for hk, hv in server_headers.items():
            lines.append(f'        header "{_esc_cs(hk)}" "{_esc_cs(hv)}";')
        lines.append("        output {")
        lines.append("            print;")
        lines.append("        }")
        lines.append("    }")
        lines.append("}")

    content = "\n".join(lines) + "\n"

    from infraguard.profiles.cobalt_strike import parse_cobalt_strike_profile
    parse_cobalt_strike_profile(content)
    return content


# ── Sliver (JSON) ───────────────────────────────────────────────────────

def generate_sliver_profile(params: dict) -> str:
    paths = _get_list(params, "sliver_paths") or _get_list(params, "get_uris") or ["api", "assets"]
    files = _get_list(params, "sliver_files") or ["index", "default", "page"]
    extensions = _get_list(params, "sliver_extensions") or [".js", ".php", ".html", ".png"]
    ua = _get(params, "useragent", _DEFAULT_UA)
    server_headers = _get_headers(params, "server_headers")

    header_list = []
    for hk, hv in server_headers.items():
        header_list.append({"name": hk, "value": hv, "probability": 100})

    cookies = [_get(params, "message_name", "PHPSESSID")]

    profile = {
        "implant_config": {
            "paths": paths,
            "files": files,
            "extensions": extensions,
            "user_agent": ua,
        },
        "server_config": {
            "headers": header_list,
            "cookies": cookies,
        },
    }

    content = json.dumps(profile, indent=2) + "\n"

    from infraguard.profiles.sliver import parse_sliver_profile
    parse_sliver_profile(content)
    return content


# ── Brute Ratel (JSON) ──────────────────────────────────────────────────

def generate_brute_ratel_profile(params: dict) -> str:
    name = _get(params, "name", "Generated")
    listener_name = _get(params, "listener_name", name.replace(" ", "_").lower())
    uris = _get_list(params, "get_uris") or ["/api/v1"]
    ua = _get(params, "useragent", _DEFAULT_UA)
    sleep = _get(params, "sleeptime", 60000)
    jitter = _get(params, "jitter", 0)
    client_headers = _get_headers(params, "client_headers")
    server_headers = _get_headers(params, "server_headers")
    transforms = _get_transforms(params)

    encoding = ""
    prepend_val = ""
    append_val = ""
    for t in transforms:
        action = t.get("action", "")
        if action in ("base64", "base64url"):
            encoding = action.title() if action == "base64" else "Base64"
        elif action == "prepend":
            prepend_val = t.get("value", "")
        elif action == "append":
            append_val = t.get("value", "")

    listener = {
        "c2_uri": uris,
        "request_headers": client_headers,
        "response_headers": server_headers,
        "useragent": ua,
        "sleep": sleep // 1000 if sleep >= 1000 else sleep,
        "jitter": jitter,
        "data_encoding": encoding,
        "prepend": prepend_val,
        "append": append_val,
    }

    profile = {
        "listeners": {listener_name: listener},
        "c2_handler": {},
    }

    content = json.dumps(profile, indent=2) + "\n"

    from infraguard.profiles.brute_ratel import parse_brute_ratel_profile
    parse_brute_ratel_profile(content)
    return content


# ── Havoc (TOML) ────────────────────────────────────────────────────────

def _toml_header_list(headers: dict[str, str]) -> str:
    """Format headers as a TOML array of inline tables."""
    if not headers:
        return "[]"
    entries = []
    for k, v in headers.items():
        entries.append(f'{{ "{k}" = "{v}" }}')
    return "[ " + ", ".join(entries) + " ]"


def _toml_transform_list(transforms: list[dict[str, str]]) -> str:
    """Format transforms as a TOML array of inline tables."""
    if not transforms:
        return "[]"
    entries = []
    for t in transforms:
        action = t.get("action", "")
        value = t.get("value", "")
        if action in ("base64", "base64url"):
            url_safe = "true" if action == "base64url" else "false"
            entries.append(f'{{ encode = "base64", url-safe = {url_safe} }}')
        elif action == "mask":
            entries.append('{ encode = "xor" }')
        elif action == "netbios":
            entries.append('{ encode = "netbios" }')
        elif action == "prepend":
            entries.append(f'{{ prepend = "{value}" }}')
        elif action == "append":
            entries.append(f'{{ append = "{value}" }}')
        elif action == "header":
            entries.append(f'{{ header = "{value}" }}')
        elif action == "parameter":
            entries.append(f'{{ parameter = "{value}" }}')
    if not entries:
        return "[]"
    return "[ " + ", ".join(entries) + " ]"


def generate_havoc_profile(params: dict) -> str:
    name = _get(params, "name", "Generated Havoc Profile")
    ua = _get(params, "useragent", _DEFAULT_UA)
    get_uris = _get_list(params, "get_uris") or ["/api/tasks"]
    post_uris = _get_list(params, "post_uris") or ["/api/results"]
    client_headers = _get_headers(params, "client_headers")
    server_headers = _get_headers(params, "server_headers")
    transforms = _get_transforms(params)
    msg_loc = _get(params, "message_location", "body")
    msg_name = _get(params, "message_name", "")

    # Build transform list with message placement at end
    full_transforms = list(transforms)
    if msg_loc == "header" and msg_name:
        full_transforms.append({"action": "header", "value": msg_name})
    elif msg_loc == "parameter" and msg_name:
        full_transforms.append({"action": "parameter", "value": msg_name})

    # Build URI entries as TOML
    get_uri_entries = []
    for uri in get_uris:
        get_uri_entries.append(f'{{ GET = "{uri}" }}')
    post_uri_entries = []
    for uri in post_uris:
        post_uri_entries.append(f'{{ POST = "{uri}" }}')

    content = f"""[[kaine.http.profile]]
name = "{name}"
user-agent = "{ua}"

[kaine.http.profile.agent.task-request]
uri = [ {", ".join(get_uri_entries)} ]
headers = {_toml_header_list(client_headers)}
transform = {_toml_transform_list(full_transforms)}

[kaine.http.profile.server.task-request]
headers = {_toml_header_list(server_headers)}
transform = []

[kaine.http.profile.agent.task-output]
uri = [ {", ".join(post_uri_entries)} ]
headers = {_toml_header_list(client_headers)}
transform = {_toml_transform_list(full_transforms)}

[kaine.http.profile.server.task-output]
headers = {_toml_header_list(server_headers)}
transform = []
"""

    from infraguard.profiles.havoc import parse_havoc_profile
    parse_havoc_profile(content)
    return content


# ── Nighthawk (JSON) ────────────────────────────────────────────────────

def generate_nighthawk_profile(params: dict) -> str:
    get_uris = _get_list(params, "get_uris") or ["/content"]
    post_uris = _get_list(params, "post_uris") or ["/upload"]
    ua = _get(params, "useragent", _DEFAULT_UA)
    client_headers = _get_headers(params, "client_headers")
    msg_loc = _get(params, "message_location", "header")
    msg_name = _get(params, "message_name", "X-Session-ID")

    routes = []
    for uri in get_uris:
        routes.append({"method": "GET", "uri": uri, "headers": dict(client_headers)})
    for uri in post_uris:
        routes.append({"method": "POST", "uri": uri, "headers": dict(client_headers)})

    profile = {
        "listener": {
            "http": {
                "routes": routes,
            },
        },
        "implant": {
            "user_agent": ua,
            "metadata": {
                "location": msg_loc,
                "name": msg_name,
            },
        },
    }

    content = json.dumps(profile, indent=2) + "\n"

    from infraguard.profiles.nighthawk import NighthawkParser
    NighthawkParser().parse(content)
    return content


# ── PoshC2 (YAML) ───────────────────────────────────────────────────────

def generate_poshc2_profile(params: dict) -> str:
    import yaml

    get_uris = _get_list(params, "get_uris") or ["/index.asp"]
    post_uris = _get_list(params, "post_uris") or ["/index.asp"]
    ua = _get(params, "useragent", _DEFAULT_UA)
    sleep = _get(params, "sleeptime", 5000)

    profile: dict[str, Any] = {
        "GET_Requests": get_uris,
        "POST_Requests": post_uris,
        "UserAgent": ua,
        "DefaultSleep": sleep,
    }

    content = yaml.dump(profile, default_flow_style=False, sort_keys=False)

    from infraguard.profiles.poshc2 import PoshC2Parser
    PoshC2Parser().parse(content)
    return content


# ── Mythic HTTP (JSON) ──────────────────────────────────────────────────

def generate_mythic_http_profile(params: dict) -> str:
    name = _get(params, "name", "Generated Mythic HTTP Profile")
    get_uris = _get_list(params, "get_uris") or ["/index"]
    post_uris = _get_list(params, "post_uris") or ["/data"]
    query_param = _get(params, "message_name", "q")
    client_headers = _get_headers(params, "client_headers")
    server_headers = _get_headers(params, "server_headers")
    ua = _get(params, "useragent", _DEFAULT_UA)

    if ua and "User-Agent" not in client_headers:
        client_headers["User-Agent"] = ua

    instance = {
        "get_uri": get_uris[0].lstrip("/") if get_uris else "index",
        "post_uri": post_uris[0].lstrip("/") if post_uris else "data",
        "query_path_name": query_param,
        "headers": client_headers,
        "ServerHeaders": server_headers,
    }

    profile = {
        "name": name,
        "instances": [instance],
    }

    content = json.dumps(profile, indent=2) + "\n"

    from infraguard.profiles.mythic_http import parse_mythic_http_profile
    parse_mythic_http_profile(content)
    return content


# ── Mythic (JSON — normalized C2Profile format) ─────────────────────────

def generate_mythic_profile(params: dict) -> str:
    name = _get(params, "name", "Generated Mythic Profile")
    get_uris = _get_list(params, "get_uris") or ["/"]
    post_uris = _get_list(params, "post_uris") or ["/"]
    ua = _get(params, "useragent", _DEFAULT_UA)
    client_headers = _get_headers(params, "client_headers")
    server_headers = _get_headers(params, "server_headers")
    msg_loc = _get(params, "message_location", "cookie")
    msg_name = _get(params, "message_name", "__session")
    transforms = _get_transforms(params)

    if ua and "User-Agent" not in client_headers:
        client_headers["User-Agent"] = ua

    transform_list = [
        {"action": t.get("action", ""), "value": t.get("value", "")}
        for t in transforms
    ]

    profile = {
        "name": name,
        "get": {
            "verb": "GET",
            "uris": get_uris,
            "client": {
                "headers": client_headers,
                "message": {"location": msg_loc, "name": msg_name},
                "transforms": transform_list or [{"action": "base64url", "value": ""}],
            },
            "server": {
                "headers": server_headers,
                "transforms": [{"action": "base64url", "value": ""}],
            },
        },
        "post": {
            "verb": "POST",
            "uris": post_uris,
            "client": {
                "headers": client_headers,
                "message": {"location": "body", "name": ""},
                "transforms": transform_list or [{"action": "base64url", "value": ""}],
            },
            "server": {
                "headers": server_headers,
                "transforms": [{"action": "base64url", "value": ""}],
            },
        },
    }

    content = json.dumps(profile, indent=2) + "\n"

    from infraguard.profiles.mythic import parse_mythic_profile
    parse_mythic_profile(content)
    return content


# ── Dispatcher ───────────────────────────────────────────────────────────

_GENERATORS: dict[str, Any] = {
    "cobalt_strike": generate_cobalt_strike_profile,
    "sliver": generate_sliver_profile,
    "brute_ratel": generate_brute_ratel_profile,
    "havoc": generate_havoc_profile,
    "nighthawk": generate_nighthawk_profile,
    "poshc2": generate_poshc2_profile,
    "mythic_http": generate_mythic_http_profile,
    "mythic": generate_mythic_profile,
}


def generate_profile(profile_type: str, params: dict) -> str:
    """Generate a profile in native format for the given type.

    Raises ``ValueError`` if the type is not supported or the generated
    profile fails validation.
    """
    gen = _GENERATORS.get(profile_type)
    if gen is None:
        raise ValueError(
            f"Unsupported profile type '{profile_type}'. "
            f"Supported: {', '.join(sorted(_GENERATORS))}"
        )
    return gen(params)
