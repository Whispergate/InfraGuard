"""Shared test fixtures for InfraGuard."""

import pytest

from infraguard.config.schema import (
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    ListenerConfig,
    PipelineConfig,
)
from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
    Transform,
)


@pytest.fixture
def sample_profile() -> C2Profile:
    """A minimal C2 profile for testing."""
    return C2Profile(
        name="Test Profile",
        http_get=HttpTransaction(
            verb="GET",
            uris=["/callback"],
            client=ClientConfig(
                headers={"Accept": "text/html", "Host": "test.local"},
                message=MessageConfig(location="cookie", name="session"),
                transforms=[Transform(action="base64url")],
            ),
            server=ServerConfig(headers={"Server": "nginx"}),
        ),
        http_post=HttpTransaction(
            verb="POST",
            uris=["/submit"],
            client=ClientConfig(
                headers={"Accept": "text/html", "Host": "test.local"},
                message=MessageConfig(location="body", name=""),
                transforms=[Transform(action="base64url")],
            ),
            server=ServerConfig(headers={"Server": "nginx"}),
        ),
        useragent="TestAgent/1.0",
    )


@pytest.fixture
def sample_config() -> InfraGuardConfig:
    """A minimal InfraGuard config for testing."""
    return InfraGuardConfig(
        listeners=[
            ListenerConfig(protocol="https", bind="127.0.0.1", port=8443),
        ],
        domains={
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path="examples/jquery-c2.3.14.profile",
                profile_type="cobalt_strike",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
            ),
        },
        pipeline=PipelineConfig(block_score_threshold=0.7),
    )
