"""C2 profile conformance filter.

Validates that an incoming request matches the loaded C2 profile:
- URI matches one of the profile's registered URIs
- HTTP verb matches
- Required client headers are present with expected values
- Metadata location (cookie, header, parameter) is populated
- Prepend/append patterns are present where expected
"""

from __future__ import annotations

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.profiles.transforms import TransformChain


class ProfileFilter:
    name = "profile"

    async def check(self, ctx: RequestContext) -> FilterResult:
        profile = ctx.profile
        request = ctx.request
        method = request.method.upper()
        path = request.url.path

        # Determine which transaction to validate against
        txn = None
        if profile.http_get and method == profile.http_get.verb.upper():
            if path in profile.http_get.uris:
                txn = profile.http_get
        if txn is None and profile.http_post and method == profile.http_post.verb.upper():
            if path in profile.http_post.uris:
                txn = profile.http_post
        if txn is None and profile.http_stager:
            if path in profile.http_stager.uris:
                txn = profile.http_stager

        # URI not in any transaction
        if txn is None:
            all_uris = profile.all_uris()
            if path not in all_uris:
                return FilterResult.block(
                    reason=f"URI '{path}' not in profile",
                    filter_name=self.name,
                    score=1.0,
                )
            return FilterResult.block(
                reason=f"Method '{method}' does not match profile for URI '{path}'",
                filter_name=self.name,
                score=1.0,
            )

        # Validate required client headers
        for header_name, expected_value in txn.client.headers.items():
            # Host header is special - the proxy may rewrite it
            if header_name.lower() == "host":
                continue
            actual = request.headers.get(header_name)
            if actual is None:
                return FilterResult.block(
                    reason=f"Missing required header: {header_name}",
                    filter_name=self.name,
                    score=0.9,
                )
            if actual != expected_value:
                return FilterResult.block(
                    reason=f"Header '{header_name}' value mismatch",
                    filter_name=self.name,
                    score=0.8,
                )

        # Validate User-Agent only if the profile explicitly specifies one.
        # If the profile has no useragent set, skip this check — the bot
        # filter already catches known-bad UAs from the blocklist.
        if profile.useragent:
            ua = request.headers.get("user-agent", "")
            if ua != profile.useragent:
                return FilterResult.block(
                    reason="User-Agent mismatch",
                    filter_name=self.name,
                    score=0.9,
                )

        # Validate metadata location is populated
        if txn.client.message:
            msg = txn.client.message
            if msg.location == "cookie" and msg.name:
                cookies = request.cookies
                if msg.name not in cookies:
                    # Check if it's in a prepend pattern (e.g., "__cfduid=...")
                    cookie_header = request.headers.get("cookie", "")
                    if msg.name not in cookie_header:
                        return FilterResult.block(
                            reason=f"Missing metadata cookie: {msg.name}",
                            filter_name=self.name,
                            score=0.7,
                        )
            elif msg.location == "header" and msg.name:
                if msg.name not in request.headers:
                    return FilterResult.block(
                        reason=f"Missing metadata header: {msg.name}",
                        filter_name=self.name,
                        score=0.7,
                    )
            elif msg.location == "parameter" and msg.name:
                if msg.name not in request.query_params:
                    return FilterResult.block(
                        reason=f"Missing metadata parameter: {msg.name}",
                        filter_name=self.name,
                        score=0.7,
                    )

        # Validate prepend/append patterns if transforms define them
        if txn.client.transforms:
            chain = TransformChain(txn.client.transforms)
            # Check body for prepend/append if message is body
            if txn.client.message and txn.client.message.location == "body":
                body = ctx.metadata.get("body", b"")
                if body and not chain.validate_prepend_append(body):
                    return FilterResult.block(
                        reason="Body prepend/append pattern mismatch",
                        filter_name=self.name,
                        score=0.8,
                    )

        return FilterResult.allow(filter_name=self.name)
