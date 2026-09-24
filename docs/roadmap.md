# InfraGuard Roadmap

Living document. Section 1 is what actually landed in the v0.6 update
kicked off from this roadmap sections 2+ are what's still outstanding.

Effort tiers: **S** ≈ half-day, **M** ≈ 1-3 sessions, **L** ≈ multi-week.

Related docs: [plugin-sdk.md](plugin-sdk.md) for the plugin authoring
contract top-level `README.md` for feature inventory.

---

## 1. Landed in v0.6

Cross-referenced against the source tree. "Scaffold" means the module,
config surface, and interface are shipped but a follow-up PR is needed
before it can run in anger.

### CLI additions

| Command | Status | File |
|---|---|---|
| `infraguard simulate-beacon` | Shipped | [infraguard/cli/simulate_beacon_cmd.py](../infraguard/cli/simulate_beacon_cmd.py) |
| `infraguard drop-preview` | Shipped | [infraguard/cli/drop_preview_cmd.py](../infraguard/cli/drop_preview_cmd.py) |
| `infraguard events tail` | Shipped | [infraguard/cli/events_cmd.py](../infraguard/cli/events_cmd.py) |
| `infraguard profile transpile` | Shipped | [infraguard/cli/transpile_cmd.py](../infraguard/cli/transpile_cmd.py) |

### Shared-state features

Cluster-wide extensions to the `infraguard/state/` package added in v0.5:

| Feature | Status | File |
|---|---|---|
| Cross-node dynamic whitelist | Shipped | [infraguard/state/whitelist.py](../infraguard/state/whitelist.py) |
| Beacon session correlation | Shipped | [infraguard/state/beacons.py](../infraguard/state/beacons.py) |
| Distributed drop rate-limit | Shipped | [infraguard/state/drop_rate_limit.py](../infraguard/state/drop_rate_limit.py) |

Wiring these into the hot path (calls in `core/router.py`) is a small
follow-up commit the modules themselves are self-contained.

### Auto-rotation watchdog

| Feature | Status | File |
|---|---|---|
| Burn-score watchdog | Shipped | [infraguard/deploy/watchdog.py](../infraguard/deploy/watchdog.py) |
| Cert-expiry auto-rotate | Shipped | [infraguard/deploy/watchdog.py](../infraguard/deploy/watchdog.py) |
| Cost-cap auto-rotate | Interface only (billing API integration deferred) | [infraguard/deploy/watchdog.py](../infraguard/deploy/watchdog.py) |

Enable via a new `watchdog:` block in `config.yaml`.

### Observability

| Feature | Status | File |
|---|---|---|
| OpenTelemetry traces (opt-in) | Shipped | [infraguard/observability/otel.py](../infraguard/observability/otel.py) |
| Grafana overview dashboard | Shipped | [deploy/grafana/infraguard.json](../deploy/grafana/infraguard.json) |

Wire OTEL into `core/app.py` lifespan import + call `setup_otel()`.
Grafana JSON is one HTTP POST from live.

### Cross-C2 transpiler + LLM helper

| Feature | Status | File |
|---|---|---|
| Profile transpiler using the IR + registry | Shipped | [infraguard/profiles/transpile.py](../infraguard/profiles/transpile.py) |
| LLM "why blocked?" (Ollama) | Shipped | [infraguard/integrations/why_blocked.py](../infraguard/integrations/why_blocked.py) |

### Command Post intel sharing

| Feature | Status | File |
|---|---|---|
| Bi-directional blocklist sync + JA3 anomaly | Shipped (module) | [infraguard/ui/command_post/intel_sharing.py](../infraguard/ui/command_post/intel_sharing.py) |
| STIX 2.1 bundle publisher | Shipped (module) | [infraguard/ui/command_post/stix_publisher.py](../infraguard/ui/command_post/stix_publisher.py) |

Attach a Starlette router that exposes `/api/intel/push`, `/api/intel/pull`,
and `/taxii2/collections/...` in a follow-up.

### Config git integration + TUI widget

| Feature | Status | File |
|---|---|---|
| Auto-commit config history | Shipped | [infraguard/config/git_history.py](../infraguard/config/git_history.py) |
| TUI burn-score widget | Shipped | [infraguard/ui/tui/widgets/burn_widget.py](../infraguard/ui/tui/widgets/burn_widget.py) |

### Transport scaffolds

Marked scaffold: real modules, config surface, and TODO checklists in the
docstrings so a follow-up PR drops in.

| Feature | Status | File |
|---|---|---|
| HTTP/3 (QUIC) listener | Scaffold | [infraguard/listeners/experimental/quic.py](../infraguard/listeners/experimental/quic.py) |
| WebSocket beacon transport | Scaffold | [infraguard/listeners/experimental/websocket.py](../infraguard/listeners/experimental/websocket.py) |
| gRPC beacon transport | Scaffold | [infraguard/listeners/experimental/grpc_transport.py](../infraguard/listeners/experimental/grpc_transport.py) |
| uTLS ClientHello mimicry | Scaffold | [infraguard/core/utls_mimicry.py](../infraguard/core/utls_mimicry.py) |
| Purple-team mirror | Scaffold | [infraguard/core/purple_team_mirror.py](../infraguard/core/purple_team_mirror.py) |
| Adversary-emulation self-test | Scaffold | [infraguard/deploy/adversary_emulation.py](../infraguard/deploy/adversary_emulation.py) |
| Multi-region GeoDNS | Scaffold | [infraguard/deploy/geo_dns.py](../infraguard/deploy/geo_dns.py) |

### New plugins under `infraguard/plugins/builtin/`

22 plugins shipped, all discoverable by the existing loader. Enable
per-domain via the standard `plugins:` block in `config.yaml`.

Alerting:

| Plugin | File | Notes |
|---|---|---|
| `pagerduty` | [pagerduty.py](../infraguard/plugins/builtin/pagerduty.py) | Events API v2 with dedup |
| `telegram_bot` | [telegram_bot.py](../infraguard/plugins/builtin/telegram_bot.py) | Two-way ops over Telegram |

(Slack, Discord, generic webhook, Elasticsearch, Syslog, Wazuh already
shipped pre-v0.6.)

Detection augmentation:

| Plugin | File |
|---|---|
| `yara_scan` | [yara_scan.py](../infraguard/plugins/builtin/yara_scan.py) |
| `ja4_enricher` | [ja4_enricher.py](../infraguard/plugins/builtin/ja4_enricher.py) |
| `p0f_fingerprint` | [p0f_fingerprint.py](../infraguard/plugins/builtin/p0f_fingerprint.py) |
| `greynoise` | [greynoise.py](../infraguard/plugins/builtin/greynoise.py) |
| `http_smuggling` | [http_smuggling.py](../infraguard/plugins/builtin/http_smuggling.py) |

Response manipulation:

| Plugin | File |
|---|---|
| `response_canary` | [response_canary.py](../infraguard/plugins/builtin/response_canary.py) |
| `html_rewriter` | [html_rewriter.py](../infraguard/plugins/builtin/html_rewriter.py) |
| `payload_watermark` | [payload_watermark.py](../infraguard/plugins/builtin/payload_watermark.py) |
| `sig_strip` | [sig_strip.py](../infraguard/plugins/builtin/sig_strip.py) |
| `slow_tarpit` | [slow_tarpit.py](../infraguard/plugins/builtin/slow_tarpit.py) |
| `js_challenge` | [js_challenge.py](../infraguard/plugins/builtin/js_challenge.py) |
| `cache_mimicry` | [cache_mimicry.py](../infraguard/plugins/builtin/cache_mimicry.py) |

Session & behavior tracking:

| Plugin | File |
|---|---|
| `beacon_labeler` | [beacon_labeler.py](../infraguard/plugins/builtin/beacon_labeler.py) |
| `timing_profiler` | [timing_profiler.py](../infraguard/plugins/builtin/timing_profiler.py) |
| `geoip_enricher` | [geoip_enricher.py](../infraguard/plugins/builtin/geoip_enricher.py) |

Payload security & staging:

| Plugin | File |
|---|---|
| `payload_shred` | [payload_shred.py](../infraguard/plugins/builtin/payload_shred.py) |
| `stager_rate_limit` | [stager_rate_limit.py](../infraguard/plugins/builtin/stager_rate_limit.py) |

Testing helpers:

| Plugin | File |
|---|---|
| `request_recorder` | [request_recorder.py](../infraguard/plugins/builtin/request_recorder.py) |
| `shadow_block` | [shadow_block.py](../infraguard/plugins/builtin/shadow_block.py) |
| `prom_custom` | [prom_custom.py](../infraguard/plugins/builtin/prom_custom.py) |

Not shipped (deferred): `ml_bot_classifier` (needs a trained baseline).

---

## 2. Still on the roadmap

### Kubernetes operator + Helm chart

| Effort | Feature | Why now |
|---|---|---|
| **L** | Kubernetes operator + Helm chart at `deploy/helm/` | Complements Terraform/Pulumi the state package (v0.5) + Redis compose profile removed the last blocker. Deliberately parked from v0.6 to keep the release focused. |
| **M** | HPA-driven auto-scaling on `infraguard_active_beacons` | Depends on the K8s operator. |

### Follow-up wiring for v0.6 scaffolds

These are all "the module exists, wire it in":

| Effort | Item |
|---|---|
| **S** | Wire `SharedWhitelist` into `IntelManager.record_valid_request`. |
| **S** | Wire `record_beacon_request` into `DomainRouter._maybe_record_whitelist_and_issue_tokens`. |
| **S** | Wire `DropRateLimiter` into `core.drop.handle_drop`. |
| **S** | Wire `RotationWatchdog` into `core.app.create_app` lifespan. |
| **S** | Call `setup_otel()` in `core.app.create_app` and `ui.api.app.create_api_app`. |
| **M** | Attach Command Post intel-sharing routes to the Starlette app. |
| **M** | Wire config history into every dashboard mutation site. |
| **M** | Adapt aioquic H3 events -> ASGI scope so the QUIC listener speaks HTTP/3. |
| **M** | Adapt WebSocket frame -> Request so beacons can use the WS transport. |
| **M** | Swap outbound `httpx.AsyncClient` for uTLS mimic (opt-in per-domain). |

### Original roadmap items still outstanding

| Effort | Feature | Notes |
|---|---|---|
| **M** | ML bot-classifier plugin | Needs training data + a baseline model. |
| **L** | Full purple-team mirror wiring | Scaffold in `core/purple_team_mirror.py` integration with router hot path. |
| **L** | Full adversary-emulation self-test | Scaffold in `deploy/adversary_emulation.py` needs result correlation to tracking DB and HTML report. |

---

## SDK notes

The plugin SDK already exposes `on_request` / `on_response` /
`on_event` / `on_startup` / `on_shutdown` hooks (see
[plugin-sdk.md](plugin-sdk.md)), so the v0.6 plugin wave did not
need an SDK v2. Two SDK conveniences would help future plugin
authors:

- A `@plugin.every(seconds=...)` scheduled hook for pollers.
- A stable `PluginContext.state` accessor so plugins can call the
  shared `StateBackend` without importing internals.

Neither is blocking. Capture as issues when a plugin needs one.

---

## How to add to this roadmap

1. Open a PR that adds a row to the appropriate table.
2. Effort tier follows the header key. Cite prior code if the idea
   builds on an existing subsystem.
3. If it's a genuine new subsystem (not an incremental improvement),
   also write a one-page ADR under `docs/adrs/` before the PR lands.

## Contributing

Pick anything **S** and open a PR. **M** items are worth a design
comment first. **L** items should start as an issue or ADR to align
on scope.
