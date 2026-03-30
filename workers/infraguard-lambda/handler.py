"""InfraGuard Edge Lambda - AWS Lambda@Edge / Function URL reverse proxy.

Sits in front of your InfraGuard server via AWS CloudFront or Lambda
Function URL. Provides domain fronting through AWS infrastructure,
edge-level country blocking, and real client IP injection.

Deploy as:
  - Lambda@Edge (attached to CloudFront distribution)
  - Lambda Function URL (standalone HTTPS endpoint)

Environment variables:
  INFRAGUARD_BACKEND  - InfraGuard server URL (e.g. https://infraguard.example.com:443)
  ALLOWED_HOSTS       - Comma-separated allowed Host headers
  BLOCKED_COUNTRIES   - Comma-separated ISO country codes to block
  HOST_MAP            - Host rewriting rules (e.g. cf-domain:expected-host)
"""

import json
import os
import urllib.request
import urllib.error
import ssl

# Read config from environment
BACKEND = os.environ.get("INFRAGUARD_BACKEND", "").rstrip("/")
ALLOWED_HOSTS = [
    h.strip().lower()
    for h in os.environ.get("ALLOWED_HOSTS", "").split(",")
    if h.strip()
]
BLOCKED_COUNTRIES = [
    c.strip().upper()
    for c in os.environ.get("BLOCKED_COUNTRIES", "").split(",")
    if c.strip()
]
HOST_MAP = {}
for mapping in os.environ.get("HOST_MAP", "").split(","):
    if ":" in mapping:
        src, dst = mapping.strip().split(":", 1)
        HOST_MAP[src.strip().lower()] = dst.strip()

# Skip TLS verification for self-signed certs on the InfraGuard server
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# Headers to strip from forwarded requests and responses
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "proxy-authorization", "proxy-authenticate",
    "content-length",
})
_STRIP_RESPONSE = _HOP_BY_HOP | {"server"}


def handler(event, context):
    """Lambda handler - supports both Function URL and Lambda@Edge formats."""
    # Detect event format
    if "requestContext" in event and "http" in event.get("requestContext", {}):
        return _handle_function_url(event)
    elif "Records" in event:
        return _handle_lambda_edge(event)
    else:
        return _handle_function_url(event)


def _handle_function_url(event):
    """Handle Lambda Function URL / API Gateway v2 format."""
    http_ctx = event.get("requestContext", {}).get("http", {})
    method = http_ctx.get("method", event.get("httpMethod", "GET"))
    path = http_ctx.get("path", event.get("rawPath", "/"))
    query = event.get("rawQueryString", "")
    headers = event.get("headers", {})
    body = event.get("body", "")
    is_base64 = event.get("isBase64Encoded", False)

    host = headers.get("host", "")
    client_ip = http_ctx.get("sourceIp", headers.get("x-forwarded-for", ""))
    country = headers.get("cloudfront-viewer-country", "")

    # Edge filtering
    if BLOCKED_COUNTRIES and country.upper() in BLOCKED_COUNTRIES:
        return {"statusCode": 403, "body": "Access Denied"}

    if ALLOWED_HOSTS:
        hostname = host.split(":")[0].lower()
        if hostname not in ALLOWED_HOSTS:
            return {"statusCode": 404, "body": "Not Found"}

    if not BACKEND:
        return {"statusCode": 502, "body": "Misconfigured: INFRAGUARD_BACKEND not set"}

    # Build upstream request
    upstream_url = BACKEND + path
    if query:
        upstream_url += "?" + query

    forward_headers = {}
    for k, v in headers.items():
        if k.lower() not in _HOP_BY_HOP and not k.lower().startswith("x-amz"):
            forward_headers[k] = v

    forward_headers["X-Real-IP"] = client_ip
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Forwarded-Proto"] = "https"

    # Host rewriting
    hostname = host.split(":")[0].lower()
    if hostname in HOST_MAP:
        forward_headers["Host"] = HOST_MAP[hostname]

    # Decode body
    if is_base64 and body:
        import base64
        body_bytes = base64.b64decode(body)
    elif body:
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = None

    # Proxy to InfraGuard
    try:
        req = urllib.request.Request(
            upstream_url,
            data=body_bytes,
            headers=forward_headers,
            method=method,
        )
        resp = urllib.request.urlopen(req, context=_SSL_CTX, timeout=30)
        resp_body = resp.read()
        resp_headers = {
            k.lower(): v
            for k, v in resp.getheaders()
            if k.lower() not in _STRIP_RESPONSE
        }

        return {
            "statusCode": resp.status,
            "headers": resp_headers,
            "body": resp_body.decode("utf-8", errors="replace"),
        }
    except urllib.error.HTTPError as e:
        resp_body = e.read()
        return {
            "statusCode": e.code,
            "body": resp_body.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        return {"statusCode": 502, "body": f"Bad Gateway: {e}"}


def _handle_lambda_edge(event):
    """Handle CloudFront Lambda@Edge origin-request format."""
    record = event["Records"][0]["cf"]
    request = record["request"]
    method = request["method"]
    uri = request["uri"]
    query = request.get("querystring", "")
    headers = request.get("headers", {})

    # Extract values from CloudFront headers format (lists of dicts)
    def _get_header(name):
        vals = headers.get(name.lower(), [])
        return vals[0]["value"] if vals else ""

    host = _get_header("host")
    client_ip = _get_header("x-forwarded-for").split(",")[0].strip()
    country = _get_header("cloudfront-viewer-country")

    # Edge filtering
    if BLOCKED_COUNTRIES and country.upper() in BLOCKED_COUNTRIES:
        return {
            "status": "403",
            "statusDescription": "Forbidden",
            "body": "Access Denied",
        }

    if ALLOWED_HOSTS:
        hostname = host.split(":")[0].lower()
        if hostname not in ALLOWED_HOSTS:
            return {
                "status": "404",
                "statusDescription": "Not Found",
                "body": "Not Found",
            }

    if not BACKEND:
        return {"status": "502", "body": "Misconfigured"}

    # Build upstream URL
    upstream_url = BACKEND + uri
    if query:
        upstream_url += "?" + query

    forward_headers = {}
    for name, values in headers.items():
        if name.lower() not in _HOP_BY_HOP and not name.lower().startswith("x-amz"):
            forward_headers[name] = values[0]["value"]

    forward_headers["X-Real-IP"] = client_ip
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Forwarded-Proto"] = "https"

    hostname = host.split(":")[0].lower()
    if hostname in HOST_MAP:
        forward_headers["Host"] = HOST_MAP[hostname]

    # Proxy to InfraGuard
    try:
        body_data = request.get("body", {}).get("data", "")
        body_bytes = body_data.encode("utf-8") if body_data else None

        req = urllib.request.Request(
            upstream_url,
            data=body_bytes,
            headers=forward_headers,
            method=method,
        )
        resp = urllib.request.urlopen(req, context=_SSL_CTX, timeout=30)
        resp_body = resp.read()

        resp_headers = {}
        for k, v in resp.getheaders():
            if k.lower() not in _STRIP_RESPONSE:
                resp_headers[k.lower()] = [{"value": v}]

        return {
            "status": str(resp.status),
            "statusDescription": "OK",
            "headers": resp_headers,
            "body": resp_body.decode("utf-8", errors="replace"),
        }
    except urllib.error.HTTPError as e:
        return {
            "status": str(e.code),
            "body": e.read().decode("utf-8", errors="replace"),
        }
    except Exception as e:
        return {"status": "502", "body": f"Bad Gateway: {e}"}
