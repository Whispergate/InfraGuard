"""Unit tests for infraguard.core.headers - HeaderSanitizer."""

import pytest

from infraguard.core.headers import DEFAULT_SAFE_HEADERS, sanitize_response_headers


class TestDefaultSafeHeaders:
    def test_contains_expected_headers(self):
        expected = {
            "content-type",
            "content-length",
            "content-encoding",
            "cache-control",
            "etag",
            "last-modified",
            "location",
            "set-cookie",
            "transfer-encoding",
        }
        assert expected == DEFAULT_SAFE_HEADERS

    def test_is_frozenset(self):
        assert isinstance(DEFAULT_SAFE_HEADERS, frozenset)


class TestSanitizeResponseHeaders:
    def test_strips_server_header(self):
        result = sanitize_response_headers({"Server": "Apache/2.4", "content-type": "text/html"})
        assert "Server" not in result
        assert "server" not in result

    def test_strips_x_powered_by(self):
        result = sanitize_response_headers({"X-Powered-By": "PHP/7.4", "content-type": "text/html"})
        assert "X-Powered-By" not in result

    def test_strips_via(self):
        result = sanitize_response_headers({"Via": "1.1 proxy.example.com", "content-type": "text/html"})
        assert "Via" not in result

    def test_strips_x_aspnet_version(self):
        result = sanitize_response_headers({"X-AspNet-Version": "4.0.30319", "content-type": "text/html"})
        assert "X-AspNet-Version" not in result

    def test_passes_content_type(self):
        result = sanitize_response_headers({"content-type": "application/json"})
        assert result["content-type"] == "application/json"

    def test_passes_content_length(self):
        result = sanitize_response_headers({"content-length": "42"})
        assert result["content-length"] == "42"

    def test_passes_content_encoding(self):
        result = sanitize_response_headers({"content-encoding": "gzip"})
        assert result["content-encoding"] == "gzip"

    def test_passes_cache_control(self):
        result = sanitize_response_headers({"cache-control": "no-cache"})
        assert result["cache-control"] == "no-cache"

    def test_passes_etag(self):
        result = sanitize_response_headers({"etag": '"abc123"'})
        assert result["etag"] == '"abc123"'

    def test_passes_last_modified(self):
        result = sanitize_response_headers({"last-modified": "Tue, 01 Jan 2025 00:00:00 GMT"})
        assert result["last-modified"] == "Tue, 01 Jan 2025 00:00:00 GMT"

    def test_passes_location(self):
        result = sanitize_response_headers({"location": "/redirect"})
        assert result["location"] == "/redirect"

    def test_passes_set_cookie(self):
        result = sanitize_response_headers({"set-cookie": "session=abc; Path=/"})
        assert result["set-cookie"] == "session=abc; Path=/"

    def test_passes_transfer_encoding(self):
        result = sanitize_response_headers({"transfer-encoding": "chunked"})
        assert result["transfer-encoding"] == "chunked"

    def test_extra_allowed_passes_through(self):
        result = sanitize_response_headers(
            {"x-custom": "value123", "content-type": "text/html"},
            extra_allowed=frozenset({"x-custom"}),
        )
        assert result["x-custom"] == "value123"

    def test_extra_allowed_does_not_affect_stripped_headers(self):
        result = sanitize_response_headers(
            {"server": "nginx", "x-custom": "value"},
            extra_allowed=frozenset({"x-custom"}),
        )
        assert "server" not in result
        assert result["x-custom"] == "value"

    def test_case_insensitive_content_type(self):
        result = sanitize_response_headers({"Content-Type": "text/html"})
        assert "Content-Type" in result

    def test_case_insensitive_mixed(self):
        result = sanitize_response_headers({"CONTENT-LENGTH": "100"})
        assert "CONTENT-LENGTH" in result

    def test_case_insensitive_strips_server(self):
        result = sanitize_response_headers({"SERVER": "Apache"})
        assert "SERVER" not in result

    def test_empty_input_returns_empty_dict(self):
        result = sanitize_response_headers({})
        assert result == {}

    def test_returns_dict(self):
        result = sanitize_response_headers({"content-type": "text/plain"})
        assert isinstance(result, dict)

    def test_no_extra_allowed_strips_unknown_headers(self):
        result = sanitize_response_headers({"x-frame-options": "DENY", "content-type": "text/html"})
        assert "x-frame-options" not in result
        assert result["content-type"] == "text/html"
