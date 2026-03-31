"""Unit tests for infraguard.core.log_sanitizer - structlog redaction processor."""

import pytest

from infraguard.core.log_sanitizer import redact_sensitive_fields


class TestRedactSensitiveFields:
    def _call(self, event_dict: dict) -> dict:
        """Helper to invoke the structlog processor signature."""
        return redact_sensitive_fields(None, None, event_dict)

    def test_redacts_authorization(self):
        result = self._call({"authorization": "Bearer xyz123"})
        assert result["authorization"] == "[REDACTED]"

    def test_redacts_auth_token(self):
        result = self._call({"auth_token": "super-secret-value"})
        assert result["auth_token"] == "[REDACTED]"

    def test_redacts_password(self):
        result = self._call({"password": "hunter2"})
        assert result["password"] == "[REDACTED]"

    def test_redacts_x_api_key(self):
        result = self._call({"x-api-key": "api-key-value"})
        assert result["x-api-key"] == "[REDACTED]"

    def test_redacts_token(self):
        result = self._call({"token": "mytoken"})
        assert result["token"] == "[REDACTED]"

    def test_redacts_secret(self):
        result = self._call({"secret": "topsecret"})
        assert result["secret"] == "[REDACTED]"

    def test_redacts_suffix_token(self):
        result = self._call({"access-token": "some-token"})
        assert result["access-token"] == "[REDACTED]"

    def test_redacts_suffix_secret(self):
        result = self._call({"app-secret": "mysecret"})
        assert result["app-secret"] == "[REDACTED]"

    def test_redacts_suffix_key(self):
        result = self._call({"api-key": "keyvalue"})
        assert result["api-key"] == "[REDACTED]"

    def test_redacts_suffix_credential(self):
        result = self._call({"db-credential": "dbpass"})
        assert result["db-credential"] == "[REDACTED]"

    def test_does_not_redact_event(self):
        result = self._call({"event": "request_received", "authorization": "Bearer x"})
        assert result["event"] == "request_received"

    def test_does_not_redact_client_ip(self):
        result = self._call({"client_ip": "10.0.0.1"})
        assert result["client_ip"] == "10.0.0.1"

    def test_does_not_redact_domain(self):
        result = self._call({"domain": "example.com"})
        assert result["domain"] == "example.com"

    def test_does_not_redact_path(self):
        result = self._call({"path": "/api/v1/health"})
        assert result["path"] == "/api/v1/health"

    def test_does_not_redact_status(self):
        result = self._call({"status": 200})
        assert result["status"] == 200

    def test_returns_event_dict(self):
        """structlog processor contract: must return event_dict."""
        event_dict = {"event": "test"}
        result = self._call(event_dict)
        assert result is event_dict

    def test_case_insensitive_uppercase_authorization(self):
        result = self._call({"Authorization": "Bearer xyz"})
        assert result["Authorization"] == "[REDACTED]"

    def test_case_insensitive_uppercase_password(self):
        result = self._call({"PASSWORD": "secret"})
        assert result["PASSWORD"] == "[REDACTED]"

    def test_mixed_fields_only_sensitive_redacted(self):
        event_dict = {
            "event": "auth_attempt",
            "client_ip": "192.168.1.1",
            "domain": "test.example.com",
            "authorization": "Bearer token123",
            "password": "pass",
            "status": 401,
        }
        result = self._call(event_dict)
        assert result["event"] == "auth_attempt"
        assert result["client_ip"] == "192.168.1.1"
        assert result["domain"] == "test.example.com"
        assert result["authorization"] == "[REDACTED]"
        assert result["password"] == "[REDACTED]"
        assert result["status"] == 401

    def test_empty_event_dict(self):
        result = self._call({})
        assert result == {}
