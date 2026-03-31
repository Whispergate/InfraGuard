# Cloudflare Workers — dumb HTTP relay front
#
# This module deploys a Cloudflare Worker that relays all matching requests
# to a backend VPS running the full InfraGuard stack.  The Worker itself
# has NO filtering, scoring, or persistence — it is a transparent relay
# that adds a CDN/edge layer for infrastructure obfuscation.
#
# Limitations:
#   - No SQLite (Workers have no persistent filesystem)
#   - No C2 profile matching (CPU time limits)
#   - No event recording (no database)
#   - The backend VPS must run InfraGuard with full capabilities
#
# Use case: hide the real VPS IP behind Cloudflare's edge network.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Look up the zone ID from the domain name
data "cloudflare_zones" "this" {
  filter {
    name = var.domain
  }
}

locals {
  zone_id = data.cloudflare_zones.this.zones[0].id
}

# Worker script — transparent HTTP relay
resource "cloudflare_workers_script" "relay" {
  account_id = data.cloudflare_zones.this.zones[0].account_id
  name       = var.worker_name

  content = <<-JS
    export default {
      async fetch(request, env) {
        const url = new URL(request.url);
        const upstream = "${var.upstream_url}".replace(/\/$/, "");
        const target = upstream + url.pathname + url.search;

        const headers = new Headers(request.headers);
        headers.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");
        headers.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
        headers.delete("Host");

        const resp = await fetch(target, {
          method: request.method,
          headers: headers,
          body: request.method !== "GET" && request.method !== "HEAD"
            ? request.body
            : undefined,
          redirect: "manual",
        });

        const response = new Response(resp.body, {
          status: resp.status,
          headers: resp.headers,
        });

        return response;
      }
    };
  JS
}

# Route: attach the Worker to the domain pattern
resource "cloudflare_workers_route" "relay" {
  zone_id     = local.zone_id
  pattern     = "${var.domain}/${var.route_pattern}"
  script_name = cloudflare_workers_script.relay.name
}
