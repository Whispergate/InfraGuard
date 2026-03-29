"""Cobalt Strike malleable C2 profile parser.

Parses .profile files into the normalized C2Profile model. Uses regex-based
block extraction (adapted from the Tyche project) with additional support
for http-stager blocks, global options, and named variants.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
    Transform,
)


class CobaltStrikeParser:
    """Parse Cobalt Strike malleable C2 profiles."""

    def __init__(self, content: str):
        self.content = content
        self.lines = content.split("\n")

    def parse(self, content: str | None = None) -> C2Profile:
        if content is not None:
            self.content = content
            self.lines = content.split("\n")

        profile_name = self._extract_profile_name()
        global_opts = self._parse_global_options()

        http_get = self._parse_http_block("http-get", "GET")
        http_post = self._parse_http_block("http-post", "POST")
        http_stager = self._parse_stager_block()

        useragent = global_opts.get("useragent")
        sleeptime = None
        jitter = None
        if "sleeptime" in global_opts:
            try:
                sleeptime = int(global_opts["sleeptime"])
            except ValueError:
                pass
        if "jitter" in global_opts:
            try:
                jitter = int(global_opts["jitter"])
            except ValueError:
                pass

        return C2Profile(
            name=profile_name,
            http_get=http_get,
            http_post=http_post,
            http_stager=http_stager,
            useragent=useragent,
            sleeptime=sleeptime,
            jitter=jitter,
            global_options=global_opts,
        )

    def parse_file(self, path: str | Path) -> C2Profile:
        with open(path, encoding="utf-8") as f:
            return self.parse(f.read())

    # ── Global options ────────────────────────────────────────────────

    def _parse_global_options(self) -> dict[str, str]:
        """Extract top-level `set key "value";` directives."""
        opts: dict[str, str] = {}
        # Only match set statements that appear outside of block contexts.
        # We do a simple heuristic: track brace depth.
        depth = 0
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            depth += stripped.count("{") - stripped.count("}")
            if depth == 0:
                match = re.match(r'set\s+(\w+)\s+"((?:[^"\\]|\\.)*)"\s*;', stripped)
                if match:
                    opts[match.group(1)] = self._unescape(match.group(2))
        return opts

    # ── Profile name extraction ───────────────────────────────────────

    def _extract_profile_name(self) -> str:
        # Try the 'sample_name' global option first
        for line in self.lines:
            stripped = line.strip()
            match = re.match(r'set\s+sample_name\s+"((?:[^"\\]|\\.)*)"\s*;', stripped)
            if match:
                return self._unescape(match.group(1))

        # Fallback: look for a descriptive comment
        for line in self.lines:
            if line.strip().startswith("#") and "profile" in line.lower():
                m = re.search(
                    r"#\s*(.+?)\s+(?:profile|browsing)", line, re.IGNORECASE
                )
                if m:
                    return m.group(1).strip()

        return "Converted Malleable Profile"

    # ── HTTP block parsing ────────────────────────────────────────────

    def _parse_http_block(
        self, block_type: str, verb: str
    ) -> HttpTransaction | None:
        block_content = self._extract_block(block_type)
        if not block_content:
            return None

        # Check for explicit verb override
        verb_match = re.search(r'set\s+verb\s+"(\w+)"', block_content)
        if verb_match:
            verb = verb_match.group(1).upper()

        uri_list = self._parse_uri(block_content)
        client_content = self._extract_nested_block(block_content, "client")
        server_content = self._extract_nested_block(block_content, "server")

        client = self._build_client_config(client_content, block_type)
        server = self._build_server_config(server_content)

        return HttpTransaction(
            verb=verb, uris=uri_list, client=client, server=server
        )

    def _parse_stager_block(self) -> HttpTransaction | None:
        block_content = self._extract_block("http-stager")
        if not block_content:
            return None

        # Stager uses uri_x86 / uri_x64 instead of uri
        uris: list[str] = []
        for key in ("uri_x86", "uri_x64"):
            m = re.search(rf'set\s+{key}\s+"((?:[^"\\]|\\.)*)"', block_content)
            if m:
                uris.append(self._unescape(m.group(1)))
        if not uris:
            uris = ["/"]

        client_content = self._extract_nested_block(block_content, "client")
        server_content = self._extract_nested_block(block_content, "server")

        client = self._build_client_config(client_content, "http-stager")
        server = self._build_server_config(server_content)

        return HttpTransaction(
            verb="GET", uris=uris, client=client, server=server
        )

    # ── Client / Server config builders ───────────────────────────────

    def _build_client_config(
        self, content: str | None, block_type: str
    ) -> ClientConfig:
        if not content:
            return ClientConfig()

        headers = self._parse_headers(content)
        parameters = self._parse_parameters(content)
        message = self._parse_message_location(content)

        # Pick the right transform block for the client side
        if block_type == "http-post":
            # POST client: id block holds the beacon ID transforms,
            # output block holds the response output transforms
            id_transforms = self._parse_transforms(content, "id")
            output_transforms = self._parse_transforms(content, "output")
            # For client validation we care about id + output
            transforms = id_transforms or output_transforms
        else:
            # GET client: metadata block
            transforms = self._parse_transforms(content, "metadata")

        return ClientConfig(
            headers=headers,
            parameters=parameters or None,
            message=message,
            transforms=transforms,
        )

    def _build_server_config(self, content: str | None) -> ServerConfig:
        if not content:
            return ServerConfig()

        headers = self._parse_headers(content)
        transforms = self._parse_transforms(content, "output")
        return ServerConfig(headers=headers, transforms=transforms)

    # ── Block extraction (brace-counting) ─────────────────────────────

    def _extract_block(self, block_name: str) -> str | None:
        """Extract top-level named block content (handles comments)."""
        # Remove single-line comments for pattern matching
        cleaned = self._strip_comments(self.content)
        pattern = rf"(?:^|\n)\s*{re.escape(block_name)}\s*\{{"
        start_match = re.search(pattern, cleaned)
        if not start_match:
            return None

        # Find the opening brace position in the original content
        # by mapping back from the cleaned position
        return self._extract_braced_block(cleaned, start_match.end() - 1)

    def _extract_nested_block(self, content: str, block_name: str) -> str | None:
        pattern = rf"{re.escape(block_name)}\s*\{{"
        start_match = re.search(pattern, content)
        if not start_match:
            return None
        return self._extract_braced_block(content, start_match.end() - 1)

    @staticmethod
    def _extract_braced_block(text: str, open_brace_pos: int) -> str | None:
        depth = 0
        for i in range(open_brace_pos, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[open_brace_pos + 1 : i]
        return None

    @staticmethod
    def _strip_comments(text: str) -> str:
        """Remove single-line # comments (but not inside quoted strings)."""
        lines = text.split("\n")
        result = []
        for line in lines:
            in_quote = False
            escape = False
            for i, ch in enumerate(line):
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if ch == '"':
                    in_quote = not in_quote
                if ch == "#" and not in_quote:
                    line = line[:i]
                    break
            result.append(line)
        return "\n".join(result)

    # ── Value parsers ─────────────────────────────────────────────────

    @staticmethod
    def _unescape(s: str) -> str:
        return s.replace('\\"', '"').replace("\\\\", "\\")

    def _parse_uri(self, content: str) -> list[str]:
        match = re.search(r'set\s+uri\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            uris = self._unescape(match.group(1)).split()
            return uris if uris else ["/"]
        return ["/"]

    def _parse_headers(self, content: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        pattern = r'header\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*;'
        for m in re.finditer(pattern, content):
            headers[self._unescape(m.group(1))] = self._unescape(m.group(2))
        return headers

    def _parse_parameters(self, content: str) -> dict[str, str]:
        params: dict[str, str] = {}
        pattern = r'parameter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*;'
        for m in re.finditer(pattern, content):
            params[self._unescape(m.group(1))] = self._unescape(m.group(2))
        return params

    def _parse_message_location(self, content: str) -> MessageConfig:
        """Determine where beacon metadata is placed in the HTTP request."""
        output_block = self._extract_nested_block(content, "output")
        metadata_block = self._extract_nested_block(content, "metadata")
        id_block = self._extract_nested_block(content, "id")

        # Check output block (POST body)
        if output_block:
            if "print" in output_block:
                return MessageConfig(location="body", name="")
            loc = self._location_from_block(output_block)
            if loc:
                return loc

        # Check metadata block (GET cookie/header/parameter)
        if metadata_block:
            loc = self._location_from_block(metadata_block)
            if loc:
                return loc
            return MessageConfig(location="body", name="")

        # Check id block
        if id_block:
            loc = self._location_from_block(id_block)
            if loc:
                return loc

        return MessageConfig(location="cookie", name="__session")

    def _location_from_block(self, block: str) -> MessageConfig | None:
        if 'header "Cookie"' in block:
            cookie_name = self._extract_cookie_name(block)
            return MessageConfig(location="cookie", name=cookie_name)
        header_match = re.search(r'header\s+"([^"]+)"', block)
        if header_match and header_match.group(1) != "Cookie":
            return MessageConfig(
                location="header", name=header_match.group(1)
            )
        param_match = re.search(r'parameter\s+"([^"]+)"', block)
        if param_match:
            return MessageConfig(
                location="parameter", name=param_match.group(1)
            )
        if "uri-append" in block:
            return MessageConfig(location="uri-append", name="")
        return None

    def _extract_cookie_name(self, block: str) -> str:
        for m in re.finditer(r'prepend\s+"((?:[^"\\]|\\.)*)"', block):
            value = self._unescape(m.group(1))
            if "=" in value:
                return value.split("=")[0].strip(";").strip()
        return "__session"

    def _parse_transforms(self, content: str, block_name: str) -> list[Transform]:
        transform_block = self._extract_nested_block(content, block_name)
        if not transform_block:
            return []

        transforms: list[Transform] = []
        for raw_line in transform_block.split("\n"):
            line = raw_line.strip().rstrip(";")
            if not line or line.startswith("#"):
                continue

            if line.startswith("base64url"):
                transforms.append(Transform(action="base64url"))
            elif line.startswith("base64"):
                transforms.append(Transform(action="base64"))
            elif line.startswith("mask"):
                transforms.append(Transform(action="mask"))
            elif line.startswith("netbiosu"):
                transforms.append(Transform(action="netbiosu"))
            elif line.startswith("netbios"):
                transforms.append(Transform(action="netbios"))
            elif line.startswith("prepend"):
                m = re.search(r'prepend\s+"((?:[^"\\]|\\.)*)"', line)
                if m:
                    transforms.append(
                        Transform(action="prepend", value=self._unescape(m.group(1)))
                    )
            elif line.startswith("append"):
                m = re.search(r'append\s+"((?:[^"\\]|\\.)*)"', line)
                if m:
                    transforms.append(
                        Transform(action="append", value=self._unescape(m.group(1)))
                    )
            elif line.startswith("strrep"):
                m = re.search(
                    r'strrep\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"', line
                )
                if m:
                    transforms.append(
                        Transform(
                            action="strrep",
                            value=f"{self._unescape(m.group(1))}|{self._unescape(m.group(2))}",
                        )
                    )
            # 'print' is a terminal directive, not a transform - skip it

        return transforms


# ── Convenience functions ─────────────────────────────────────────────


def parse_cobalt_strike_profile(
    content: str, name: str | None = None
) -> C2Profile:
    """Parse a Cobalt Strike malleable profile string into a C2Profile."""
    parser = CobaltStrikeParser(content)
    profile = parser.parse()
    if name:
        profile.name = name
    return profile


def parse_cobalt_strike_file(
    path: str | Path, name: str | None = None
) -> C2Profile:
    """Parse a Cobalt Strike malleable profile file into a C2Profile."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_cobalt_strike_profile(content, name)
