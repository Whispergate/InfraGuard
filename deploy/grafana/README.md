# Grafana dashboards for InfraGuard

Ready-to-import dashboards that render the metrics InfraGuard emits
out of the box (`/metrics` on the dashboard container).

## Files

* `infraguard.json`. main overview: request rate, block rate, active
  beacons, upstream latency histogram, per-filter block rate,
  circuit-breaker state changes, top blocked IPs, per-domain burn
  score.

## Import

```bash
curl -X POST -H "Content-Type: application/json" \
     -d @deploy/grafana/infraguard.json \
     -u admin:$GRAFANA_PASSWORD \
     http://your-grafana:3000/api/dashboards/db
```

Or paste the JSON into Grafana's *Dashboards -> Import* dialog.

## Metrics referenced

The panels expect these Prometheus series, all emitted by the
built-in `infraguard/ui/api/metrics.py` module or by the
`prom_custom` / `beacon_correlation` plugins:

- `infraguard_requests_total{filter_result, filter_name, domain}`
- `infraguard_filter_hits_total{filter_name, action}`
- `infraguard_upstream_duration_ms_bucket{le, upstream}`
- `infraguard_breaker_transitions_total{upstream, state}`
- `infraguard_active_beacons`
- `infraguard_burn_score{domain}`

If any panel shows *No data* after import, confirm the series exists
by hitting `/metrics` directly. The `infraguard_active_beacons` and
`infraguard_burn_score` gauges are only populated when the
`beacon_correlation` and burn scorer paths are enabled in the
config (see `docs/roadmap.md`).
