"""Tests for C2 profile parsers."""

from pathlib import Path

import pytest

from infraguard.profiles.cobalt_strike import CobaltStrikeParser, parse_cobalt_strike_file
from infraguard.profiles.mythic import MythicHTTPParser, parse_mythic_file
from infraguard.profiles.models import C2Profile, Transform
from infraguard.profiles.transforms import TransformChain


# ── Cobalt Strike parser ──────────────────────────────────────────────

CS_PROFILE = Path("examples/jquery-c2.3.14.profile")
CS_JSON = Path("examples/jquery-c2.3.14.profile.json")
MYTHIC_JSON = Path("examples/mythic-httpx.json")


@pytest.mark.skipif(not CS_PROFILE.exists(), reason="CS profile not found")
class TestCobaltStrikeParser:
    def test_parse_name(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.name == "jQuery Profile"

    def test_parse_useragent(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert "Trident" in profile.useragent

    def test_parse_sleeptime(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.sleeptime == 60000

    def test_parse_jitter(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.jitter == 37

    def test_parse_http_get(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_get is not None
        assert profile.http_get.verb == "GET"
        assert "/jquery-3.3.1.min.js" in profile.http_get.uris

    def test_parse_http_post(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_post is not None
        assert profile.http_post.verb == "POST"

    def test_parse_http_stager(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_stager is not None
        assert len(profile.http_stager.uris) == 2

    def test_parse_client_headers(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        headers = profile.http_get.client.headers
        assert "Accept" in headers
        assert "Host" in headers
        assert headers["Host"] == "code.jquery.com"

    def test_parse_metadata_location(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        msg = profile.http_get.client.message
        assert msg is not None
        assert msg.location == "cookie"
        assert msg.name == "__cfduid"

    def test_parse_transforms(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        transforms = profile.http_get.client.transforms
        assert len(transforms) >= 1
        actions = [t.action for t in transforms]
        assert "base64url" in actions

    def test_all_uris(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        uris = profile.all_uris()
        assert len(uris) >= 4

    def test_to_json_roundtrip(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        json_str = profile.to_json()
        restored = C2Profile.from_json(json_str)
        assert restored.name == profile.name
        assert len(restored.all_uris()) == len(profile.all_uris())


# ── Mythic parser ─────────────────────────────────────────────────────

@pytest.mark.skipif(not MYTHIC_JSON.exists(), reason="Mythic profile not found")
class TestMythicParser:
    def test_parse_name(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert "Mythic" in profile.name or "CDN" in profile.name

    def test_parse_http_get(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert profile.http_get is not None
        assert profile.http_get.verb == "GET"

    def test_parse_http_post(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert profile.http_post is not None
        assert profile.http_post.verb == "POST"

    def test_parse_uris(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        uris = profile.all_uris()
        assert len(uris) >= 2


# ── Transform chain ───────────────────────────────────────────────────

class TestTransformChain:
    def test_base64_roundtrip(self):
        chain = TransformChain([Transform(action="base64")])
        data = b"hello world"
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_base64url_roundtrip(self):
        chain = TransformChain([Transform(action="base64url")])
        data = b"test data with special chars: +/="
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_prepend_append(self):
        chain = TransformChain([
            Transform(action="prepend", value="PREFIX_"),
            Transform(action="append", value="_SUFFIX"),
        ])
        data = b"data"
        encoded = chain.encode(data)
        assert encoded == b"PREFIX_data_SUFFIX"
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_validate_prepend_append(self):
        chain = TransformChain([
            Transform(action="prepend", value="__cfduid="),
        ])
        assert chain.validate_prepend_append(b"__cfduid=abc123")
        assert not chain.validate_prepend_append(b"othercookie=abc123")

    def test_netbios_roundtrip(self):
        chain = TransformChain([Transform(action="netbios")])
        data = b"\x41\x42"
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_mask_roundtrip(self):
        chain = TransformChain([Transform(action="mask")])
        data = b"secret beacon data"
        encoded = chain.encode(data)
        assert encoded != data
        decoded = chain.decode(encoded)
        assert decoded == data
