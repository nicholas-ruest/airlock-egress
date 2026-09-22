# Airlock Egress

Airlock Egress is a small, zero-runtime-dependency CLI for making outbound HTTP
access explicit before an agent or evaluation runner is launched. It validates
an expiring JSON contract, checks individual requests, simulates request traces
against count and byte budgets, and compiles the network-enforceable subset to
a deny-by-default Cilium policy.

It is intentionally not a sandbox, proxy, or confidential-computing system.
Use the generated Cilium policy for host/port enforcement and enforce HTTP
methods, paths, expiry, and cumulative budgets in a trusted proxy or admission
layer. The simulator makes that application policy testable before deployment.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install -e .
airlock-egress --version
```

## Quick start

Validate the example contract:

```bash
airlock-egress validate examples/contract.json
```

Check one request. Allowed checks exit `0`; denied checks exit `3`.

```bash
airlock-egress check examples/contract.json \
  https://artifacts.example.com/public/model.json --method GET
```

Simulate a JSONL trace and write a content-addressed receipt. A trace containing
any denied event exits `4`, which makes the command suitable for CI.

```bash
airlock-egress simulate examples/contract.json examples/trace.jsonl \
  --output receipt.json
```

Compile the DNS/host/port subset to Kubernetes API JSON accepted by `kubectl`:

```bash
airlock-egress compile examples/contract.json --output cilium-policy.json
kubectl apply -f cilium-policy.json
```

The generated Cilium policy allows DNS through the common `kube-dns` label and
only the declared FQDN/port pairs for the selected service account. Check your
cluster's DNS labels before applying it.

## Contract shape

```json
{
  "version": 1,
  "workload": {
    "name": "evaluation-runner",
    "namespace": "airlock",
    "service_account": "evaluation-runner"
  },
  "expires_at": "2030-01-01T00:00:00Z",
  "limits": {"max_requests": 3, "max_bytes": 4096},
  "destinations": [{
    "host": "artifacts.example.com",
    "protocol": "https",
    "ports": [443],
    "methods": ["GET"],
    "path_prefixes": ["/public/"]
  }]
}
```

Hosts may be exact FQDNs or use one leading wildcard such as
`*.telemetry.example.com`. A wildcard never matches the apex domain. Global or
mid-label wildcards are rejected. Contracts fail closed after `expires_at`.
Percent-encoded, backslash-containing, repeated-slash, and dot-segment paths are
also rejected so upstream normalization cannot widen an allowed prefix.

Trace events contain `url`, optional `method` (default `GET`), optional `bytes`
(default `0`), and optional timezone-aware `at` (default: now). Only allowed
events consume request and byte budgets.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Valid, allowed, or fully allowed simulation |
| 2 | Malformed input or I/O failure |
| 3 | Single request denied |
| 4 | Simulation completed with one or more denials |

## Verify

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
python -m compileall -q airlock_egress tests
python -m unittest discover -s tests -v
```

## Security boundary and limitations

- The CLI does not send network traffic; it evaluates declared URLs and traces.
- Cilium enforces DNS/FQDN and TCP ports, not encrypted HTTP methods or paths.
- DNS policy labels vary by cluster and must be reviewed before deployment.
- Request/byte limits are sequential simulator semantics, not distributed
  counters. Enforce them in a trusted runtime for production use.
- A policy is only one layer of an evaluation airlock; it does not provide
  attestation, secret handling, monitoring, or teardown guarantees.

## License

MIT
