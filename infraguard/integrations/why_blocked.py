"""LLM-assisted analysis: 'why did this request get blocked?'

Feeds the pipeline's block reason plus the offending request shape and
the domain's profile into the local Ollama endpoint, and asks the
model to explain in plain English what invariant the request violated
and how to shape a compliant beacon.

Fully optional; skips silently if Ollama is not reachable. Uses the
same client + config as the existing profile-assist path
(``infraguard.integrations.ollama``).
"""

from __future__ import annotations

import structlog

log = structlog.get_logger()


_PROMPT = """You are a red-team infrastructure analyst.
Look at the following blocked HTTP request and the C2 profile it was
evaluated against. Explain in 3-5 short bullet points:

1. Which invariant the profile expects that the request violated.
2. The minimal change to the request (headers, cookie, URI, body) that
   would make it pass.
3. Whether the violation looks like operator error (misconfigured
   beacon) or a defender probe.

Keep the answer under 200 words. No preamble.

## Request
Method: {method}
Path:   {path}
Headers:
{headers}
Cookie: {cookie}
Body preview: {body}

## Profile (name: {profile_name})
{profile_json}

## Block reason from InfraGuard
{reason}
"""


async def explain_block(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    cookie: str,
    body_preview: str,
    profile_json: str,
    profile_name: str,
    reason: str,
    ollama_url: str,
    model: str = "llama3.2:8b",
    timeout: float = 30.0,
) -> str | None:
    """Return the LLM's explanation, or None if Ollama is unavailable."""
    try:
        import httpx
    except ImportError:
        return None

    prompt = _PROMPT.format(
        method=method,
        path=path,
        headers="\n".join(f"  {k}: {v[:120]}" for k, v in headers.items()),
        cookie=cookie[:120] if cookie else "(none)",
        body=body_preview[:300] if body_preview else "(empty)",
        profile_name=profile_name,
        profile_json=profile_json[:4000],
        reason=reason,
    )

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 400},
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(f"{ollama_url}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:
        log.debug("why_blocked_ollama_unreachable", url=ollama_url, error=str(exc))
        return None
    return (data.get("response") or "").strip() or None
