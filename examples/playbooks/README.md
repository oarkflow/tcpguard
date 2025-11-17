# TCPGuard Playbook Catalog

The `playbooks/` directory contains ready-to-use configuration bundles that focus on a specific slice of the DDoS/abuse landscape. Each folder mirrors the `configs/` layout expected by the rule engine (`global`, `rules`, `endpoints`, …) so you can point the example app (or your own deployment) at one of these bundles to enable a targeted detector set.

## Structure

```
examples/playbooks/
├── network-transport/
├── application-layer/
├── protocol-layer/
├── amplification/
├── volumetric-state/
├── advanced-abuse/
└── bot-and-misc/
```

Every playbook currently ships with a specialized `global/ddos.json` file that:

- Enables only the detectors relevant to the category.
- Provides tuned thresholds you can use as a starting point.
- Demonstrates telemetry wiring via the `params.telemetry` map.
- Attaches multiple actions (rate limiters, temporary/permanent bans, jitter warnings) so you can see how mitigation policies differ per layer.

## Using a Playbook

1. Copy one of the folders (for example `network-transport`) to a writable location.
2. Point `NewRuleEngine` to that folder instead of `examples/configs`.
3. Optionally merge additional `rules/` and `endpoints/` subdirectories if you need business logic layered on top of the detector pack.

Because the playbooks isolate groups of detectors, it is easy to run focused tests or stage rollouts. You can also combine multiple playbooks by overlaying the JSON files (the `name` fields are unique so they will not collide).
