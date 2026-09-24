# InfraGuard Roadmap

Living document of features and plugins planned or under consideration for
post-v0.5 releases. Effort tiers are rough: **S** ≈ half-day, **M** ≈ 1–3
sessions, **L** ≈ multi-week.

Nothing here is a commitment — this is the backlog we pick from.

Related docs: [plugin-sdk.md](plugin-sdk.md) for the plugin authoring
contract; the top-level `README.md` for current feature inventory.

---

## Core features

### 1 — Cash in on the new shared-state package

The `infraguard/state/` interface added in v0.5 is only wired to the
replay filter and circuit breaker. Three high-leverage extensions:

| Effort | Feature | Why now |
|---|---|---|
| **M** | **Cross-node dynamic whitelist** — put `record_valid_request` on the Redis backend | Today a beacon whitelisted on `proxy-node-A` gets CIDR-blocked at `proxy-node-B`. Straight port of the `ReplayFilter` pattern. |
| **M** | **Beacon session correlation** — hash `(client_ip, JA3, first_seen_ua)` into a `beacon_id`, store first/last seen and tasking count in state | Powers session views in the dashboard; unblocks HAR export, replay, and burn-per-beacon scoring. |
| **S** | **Distributed rate-limit for the drop response** — per source-IP token bucket on the drop path | A scanner hitting N replicas currently gets N drop redirects — turns us into an amplifier. |

### 2 — Real horizontal-scale story

Redis-optional state + Alembic migrator make these finally practical:

| Effort | Feature | Why now |
|---|---|---|
| **L** | **Kubernetes operator + Helm chart** at `deploy/helm/` | Complements Terraform/Pulumi; the state package removed the last blocker. |
| **M** | **HPA-driven auto-scaling** on a new `infraguard_active_beacons` metric | Requires emitting the metric first — small change in `metrics.py`. |
| **M** | **Multi-region GeoDNS** with rotation-manager integration | Regional blue-greens without a global cutover. |

### 3 — Intel sharing via Command Post

Command Post is currently a read-only aggregator. Make it the intel spine:

| Effort | Feature | Why now |
|---|---|---|
| **M** | **Bi-directional blocklist sync** — a scanner tripped on one node pushes an IoC to Command Post; peers pull | Uses the state-backend pattern; scales fleet learning. |
| **M** | **STIX/TAXII 2.1 publisher** for the operator's own scanner blocklist | Enables red-team consortium sharing. |
| **S** | **Cross-instance JA3 anomaly detection** | A JA3 seen on one domain but not others flagged; runs in Command Post; no extra state. |

### 4 — Transports and evasion

| Effort | Feature | Why now |
|---|---|---|
| **L** | **HTTP/3 (QUIC) listener** via `aioquic` | Modern browsers negotiate H3 first; a redirector without it stands out to defenders. |
| **M** | **WebSocket beacon transport** as a new `content_routes` backend type | Long-lived duplex bypasses HTTP-only proxies; blends with real-time apps. |
| **M** | **uTLS-style ClientHello mimicry for upstream** — proxy→teamserver leg mirrors Chrome/Edge exactly | `curl_cffi` or `tls-client` binding. |
| **M** | **gRPC transport** | Binary + HTTP/2 mux; complements WebSocket. |
| **S** | **Cache-hint mimicry** — auto-emit `ETag`/`Last-Modified`/`Cache-Control: max-age=N` on beacon responses | Makes shaped responses look like static CDN assets. |

### 5 — Operator workflow polish

| Effort | Feature | Why now |
|---|---|---|
| **M** | **`infraguard simulate-beacon`** — send a fully profile-shaped request through the pipeline; see the exact response a real beacon would get | Closes the biggest tooling gap: today you fire real traffic and interpret block reasons manually. |
| **S** | **`infraguard drop-preview --domain X --action decoy`** — render the drop response the pipeline would return, no traffic | Useful when tuning decoys / redirects. |
| **M** | **Config-file git integration** — auto-commit every dashboard mutation to `~/.config/infraguard/history.git`; `infraguard config log` / `revert HEAD~1` | Currently: one bad `set` from the dashboard is unrecoverable. |
| **S** | **TUI burn-score graph widget** | Scorer + tui package already exist; just needs a widget. |

### 6 — Auto-rotation triggers

The `rotate` command is manual. Wire it to observed state:

| Effort | Feature | Why now |
|---|---|---|
| **M** | **Watchdog service** — burn score over threshold auto-fires `rotate --strategy blue-green` | Makes burn scoring actionable, not decorative. |
| **S** | **Cert-expiry auto-rotate** — rotate 14 days before LE expiry | Small, mechanical, high-value. |
| **S** | **Cost-based auto-rotate** — cloud spend cap triggers a cheaper-region green | Optional guardrail. |

### 7 — Observability (from the v0.5 audit)

| Effort | Feature | Why now |
|---|---|---|
| **M** | **OpenTelemetry traces** — one span chain from beacon-hit through router / filter / upstream | Audit's #1 gap; unlocks every other debugging story. |
| **S** | **Grafana dashboard JSON in-tree** at `deploy/grafana/infraguard.json` | Zero code, huge onboarding win. Metrics already emit. |
| **M** | **Alert webhooks** — Slack/Discord/PagerDuty on: first burn hit, circuit open, cert expiring, rotation done | Requires a small `alerts/` package + config schema. |
| **S** | **`infraguard events tail`** — stream audit log as JSONL from CLI, pipe into `jq` / SIEM | 30 lines of code. |

### 8 — Novel / speculative

Higher risk, higher signal:

| Effort | Feature | Why now |
|---|---|---|
| **L** | **Purple-team mirror mode** — duplicate every allowed request to a secondary "defender view" upstream that never touches the C2 path | Blue team sees what got through without breaking the op. |
| **L** | **Adversary-emulation self-test** — `infraguard preflight --scan self` runs Nmap/Nuclei/common scanners against ourselves, reports which reached profile filter | Pre-flight sanity for every rotation. |
| **M** | **LLM-assisted "why blocked?"** — feed request context + profile to Ollama; get a diff proposal to make the beacon pass | Ollama is already integrated for profile assistance. |
| **M** | **Cross-C2 profile transpiler** — take a Cobalt Strike malleable profile, emit Mythic HTTPX config (or reverse) | Uses the shared IR + registry added in v0.5. Turns architecture into product. |

---

## New plugins

Plugins extend the pipeline via `on_request` / `on_response` hooks
(see [plugin-sdk.md](plugin-sdk.md)). The ones marked ⚠️ require the
SDK to gain a new hook (startup/shutdown/schedule/websocket) — capture
those as SDK v2 requirements, not v1 plugins.

### Alerting & notifications

| Effort | Plugin | What it does |
|---|---|---|
| **S** | **`slack-alerter`** | POST to a Slack webhook on: first-time IP allowed, burn threshold crossed, circuit opened, upstream failover fired. Config: webhook URL, event allowlist, per-event message template. |
| **S** | **`discord-alerter`** | Same as above, Discord webhooks. Shared base class with Slack. |
| **M** | **`pagerduty-oncall`** | PagerDuty Events API v2. Fires on circuit-open + all-upstreams-failed. Includes dedup key so a flapping breaker doesn't page 30 times. |
| **M** | **`telegram-bot`** ⚠️ | Two-way ops via Telegram — `/status`, `/block <ip>`, `/whitelist <ip>`, `/rotate <domain>`. Needs a background poll hook. |

### Detection augmentation

| Effort | Plugin | What it does |
|---|---|---|
| **M** | **`yara-scan`** | Run YARA rules against request bodies (catch defenders' payload probes) and optionally against upstream responses (validate C2 payload isn't matching public sigs). Config: rule file, action per-rule (block / suspect / log-only). |
| **M** | **`ja4-enricher`** | Compute JA4 / JA4S / JA4H alongside JA3 (JA4 is TLS 1.3-friendly and harder to fake). Adds `ctx.metadata["ja4"]` for other filters. |
| **M** | **`p0f-fingerprint`** | Passive TCP fingerprint via `p0f`-style rules → OS guess in `ctx.metadata`. Useful for the profile filter (a "Windows-only" campaign can block Linux beacons). |
| **M** | **`greynoise-classifier`** | Query GreyNoise Community API for source IP; classify as `benign` / `malicious` / `unknown`. Cache locally. Blocks on `malicious`, downgrades score on `benign` (avoids blocking researchers). |
| **M** | **`http-smuggling-detector`** | Flag requests with conflicting `Content-Length` + `Transfer-Encoding` — common defender-test smuggle payloads. Cheap detection with high signal. |
| **L** | **`ml-bot-classifier`** | Small trained classifier on request features (header set, header order, timing, JA3 rarity). Ships a baseline model; operators can retrain from their tracking DB. |

### Response manipulation

| Effort | Plugin | What it does |
|---|---|---|
| **S** | **`response-canary`** | Inject a canarytokens.org tracking-pixel / DNS canary into decoy HTML responses. Alerts you when an attacker fetches an internal resource *from* the canary trigger. |
| **M** | **`html-rewriter`** | Rewrite HTML being served by decoys (change og:image, inject SEO title, swap analytics IDs). CSS-selector-based. Handy when operating multiple domains from one decoy tree. |
| **M** | **`payload-watermark`** | Inject a unique marker (comment / whitespace pattern / metadata tag) into every served payload. If a payload is later posted to VirusTotal, you know which fetch it came from. |
| **S** | **`response-sig-strip`** | Remove response headers that leak the redirector (`server:`, `x-powered-by:`, `via:`); go beyond the base sanitizer's list. Paranoid-mode. |
| **M** | **`slow-tarpit`** | Drop-action extension: slow byte drip (~100 bytes/sec) for the first N seconds, then close. Wastes scanner time cheaply. |
| **M** | **`js-challenge`** | Cheap proof-of-work JS challenge on suspect requests — 5-second cost for a bot fleet, imperceptible for a real browser. Not a CAPTCHA; no accessibility issues. |

### Session & behavior tracking

| Effort | Plugin | What it does |
|---|---|---|
| **M** | **`beacon-labeler`** | Tag beacons via a header at first sight (target hostname, engagement id, phishing lure id) and store in state. Enables per-target views. |
| **M** | **`har-export`** ⚠️ | Reconstruct beacon session timeline into HAR format; `infraguard export har --beacon <id>`. Needs a scheduled/on-demand hook. |
| **M** | **`timing-profiler`** | Track request cadence per client; flag beacons with tell-tale intervals (Cobalt Strike default 60s ±jitter looks distinctive). |
| **S** | **`geoip-enricher`** | Add country/ASN/org fields to every logged event. Uses the geoip DB already in the tree. |

### Payload security & staging

| Effort | Plugin | What it does |
|---|---|---|
| **M** | **`payload-token-vending`** | Extend the existing `payload_tokens` table into a proper vending API — upload payload → get single-use tokenized URL back → auto-expire on N fetches or Y minutes. Currently only wired for content_routes. |
| **M** | **`stager-rate-limit`** | Per-target-CIDR rate limit specifically for stager URIs — catches attackers replaying a shellcode fetch. |
| **S** | **`payload-shred`** | Zero out the payload response body after Nth fetch even if the token isn't exhausted; belt-and-braces. |

### Testing helpers

| Effort | Plugin | What it does |
|---|---|---|
| **M** | **`request-recorder`** | Record every allowed request to a rotating pcap-like JSONL log. Enables `infraguard replay` (planned) for dry-run pipeline testing after a profile change. |
| **S** | **`shadow-block`** | Take a config-defined subset of requests and evaluate the pipeline **as if** filter X were enabled, without actually blocking. Reports the delta. Lets operators tune scoring thresholds risk-free. |
| **S** | **`prom-metrics-custom`** | Emit operator-defined metric names for arbitrary request features (e.g. `infraguard_requests_by_country_total{country="RU"}`). |

---

## Top 10 to ship in v0.6

Ranked by impact-per-effort, weighted against what's already been laid
down in v0.5:

1. **`infraguard simulate-beacon`** [M] — closes the biggest operator-experience gap.
2. **OpenTelemetry traces** [M] — audit's #1 observability gap.
3. **Auto-rotation watchdog** [M] — makes burn scoring actionable.
4. **Cross-node dynamic whitelist** [M] — finishes the "scale proxy-node=N safely" story.
5. **Cross-C2 profile transpiler** [M] — turns the IR/registry pattern into a feature.
6. **`slack-alerter` + `discord-alerter` plugins** [S each] — ship together.
7. **`yara-scan` plugin** [M] — defenders' single most-requested capability.
8. **`response-canary` plugin** [S] — free-standing, ship-and-forget.
9. **Grafana dashboard JSON in-tree** [S] — zero code, huge onboarding win.
10. **`infraguard events tail`** [S] — tiny CLI, big operator loop win.

Longer-horizon headliners: HTTP/3 listener, Kubernetes operator, purple-team mirror mode, ML bot classifier.

---

## SDK v2 requirements

Plugins in the list above tagged ⚠️ require the SDK to grow:

- **Lifecycle hooks** — `on_startup(state) -> None`, `on_shutdown() -> None`. Needed for background pollers (telegram-bot) and cache-warming.
- **Scheduled task hook** — `@plugin.every(seconds=…)` decorator. Needed for HAR export, watchdogs.
- **Extra transport hooks** — `on_websocket(ws, ctx)`, `on_grpc(...)`. Once transports 4-3/4-4 land.
- **Shared-state accessor** — a stable API so a plugin can `self.state.get("beacon:{id}")` without importing the internal `StateBackend`.

Capture as issues once someone commits to authoring one of the ⚠️ plugins.

---

## How to add to this roadmap

1. Open a PR that adds a row to the appropriate table.
2. Effort tier follows the header key. Cite prior code if the idea builds on an existing subsystem.
3. If it's a genuine new subsystem (not an incremental improvement), also write a one-page ADR under `docs/adrs/` before the PR lands.

## Contributing

Pick anything **S** and open a PR. **M** items are worth a design comment
first. **L** items should start as an issue or ADR to align on scope.
