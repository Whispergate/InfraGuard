"""Ollama AI assistant API routes for profile generation help."""

from __future__ import annotations

import json

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

log = structlog.get_logger()

_SYSTEM_PROMPT = """\
You are an expert C2 profile engineer embedded in InfraGuard, a red team \
C2 redirector. You help operators create, modify, and troubleshoot C2 \
communication profiles.

Supported profile types and their native formats:
- Cobalt Strike: custom .profile DSL with http-get/http-post blocks
- Sliver: JSON with implant_config (paths/files/extensions) and server_config
- Brute Ratel (BRC4): JSON with listeners containing c2_uri, headers, encoding
- Havoc (Kaine): TOML with [[kaine.http.profile]] sections
- Nighthawk: JSON with listener.http.routes[] and implant metadata
- PoshC2: YAML with GET_Requests/POST_Requests lists
- Mythic HTTP: JSON with instances[] containing get_uri/post_uri
- Mythic: JSON matching the normalized C2Profile model (get/post blocks)

When generating profiles, always produce the complete native format so it \
can be directly imported. Focus on OPSEC: realistic URIs that blend with \
legitimate traffic, appropriate headers, and sensible transforms.

Keep responses concise and actionable. When asked to generate a profile, \
output the profile content in a code block.\
"""


async def ai_chat(request: Request) -> StreamingResponse | JSONResponse:
    """POST /api/ai/chat — stream an Ollama chat response via SSE."""
    ollama_cfg = getattr(request.app.state.config, "ollama", None)
    if ollama_cfg is None or not ollama_cfg.enabled:
        return JSONResponse(
            {"error": "AI assistant is not configured"},
            status_code=503,
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    messages = body.get("messages", [])
    if not messages:
        return JSONResponse({"error": "messages is required"}, status_code=400)

    full_messages = [{"role": "system", "content": _SYSTEM_PROMPT}] + messages

    import httpx

    url = ollama_cfg.url.rstrip("/") + "/api/chat"
    payload = {
        "model": ollama_cfg.model,
        "messages": full_messages,
        "stream": True,
    }

    async def event_stream():
        try:
            async with httpx.AsyncClient(timeout=ollama_cfg.timeout) as client:
                async with client.stream(
                    "POST", url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status_code != 200:
                        error_body = await resp.aread()
                        yield f"data: {json.dumps({'error': error_body.decode()})}\n\n"
                        return

                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                            msg = chunk.get("message", {})
                            content = msg.get("content", "")
                            done = chunk.get("done", False)
                            yield f"data: {json.dumps({'content': content, 'done': done})}\n\n"
                            if done:
                                break
                        except json.JSONDecodeError:
                            continue
        except httpx.ConnectError:
            yield f"data: {json.dumps({'error': 'Cannot connect to Ollama. Is the service running?'})}\n\n"
        except Exception as exc:
            log.warning("ai_chat_error", error=str(exc))
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


async def ai_status(request: Request) -> JSONResponse:
    """GET /api/ai/status — check if Ollama is configured and reachable."""
    ollama_cfg = getattr(request.app.state.config, "ollama", None)
    if ollama_cfg is None or not ollama_cfg.enabled:
        return JSONResponse({
            "available": False,
            "reason": "AI assistant is not configured",
        })

    import httpx

    try:
        url = ollama_cfg.url.rstrip("/") + "/api/tags"
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                has_model = any(ollama_cfg.model in m for m in models)
                return JSONResponse({
                    "available": True,
                    "model": ollama_cfg.model,
                    "model_loaded": has_model,
                    "models": models,
                    "url": ollama_cfg.url,
                })
            return JSONResponse({
                "available": False,
                "reason": f"Ollama returned status {resp.status_code}",
            })
    except httpx.ConnectError:
        return JSONResponse({
            "available": False,
            "reason": "Cannot connect to Ollama",
            "url": ollama_cfg.url,
        })
    except Exception as exc:
        return JSONResponse({
            "available": False,
            "reason": str(exc),
        })
