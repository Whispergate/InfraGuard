"""Node registry API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.nodes import NodeRegistry


async def list_nodes(request: Request) -> JSONResponse:
    """GET /api/nodes - list all registered nodes."""
    registry: NodeRegistry = request.app.state.node_registry
    nodes = await registry.list_nodes()
    return JSONResponse({"nodes": nodes})


async def register_node(request: Request) -> JSONResponse:
    """POST /api/nodes/register - register a new node."""
    registry: NodeRegistry = request.app.state.node_registry
    body = await request.json()
    node_id = await registry.register(
        name=body.get("name", "unknown"),
        address=body.get("address", ""),
        domains=body.get("domains", []),
    )
    return JSONResponse({"node_id": node_id}, status_code=201)


async def heartbeat_node(request: Request) -> JSONResponse:
    """POST /api/nodes/{node_id}/heartbeat - update node heartbeat."""
    registry: NodeRegistry = request.app.state.node_registry
    node_id = request.path_params["node_id"]
    await registry.heartbeat(node_id)
    return JSONResponse({"status": "ok"})
