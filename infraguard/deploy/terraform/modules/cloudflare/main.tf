# Cloudflare Workers - dumb HTTP relay front
#
# This module deploys a Cloudflare Worker that relays all matching requests
# to a backend VPS running the full InfraGuard stack.  The Worker itself
# has NO filtering, scoring, or persistence - it is a transparent relay
# that adds a CDN/edge layer for infrastructure obfuscation.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Look up the zone ID from the domain name
data "cloudflare_zone" "this" {
  filter = {
    name = var.domain
  }
}

# Worker script - transparent HTTP relay
resource "cloudflare_workers_script" "relay" {
  account_id  = var.account_id
  script_name = var.worker_name

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
  zone_id = data.cloudflare_zone.this.zone_id
  pattern = "${var.domain}/${var.route_pattern}"
  script  = cloudflare_workers_script.relay.script_name
}
