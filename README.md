# Tuck

> **Helix Ecosystem Immune System / The Uncompromising Gate**
>
> CI-144 PFP-xCF14 first consumer · sub-microsecond hard real-time decisions · fail-closed · zero-trust credential physical injection · holographic audit

> **中文版 (Chinese Version)**: [README.zh-CN.md](./README.zh-CN.md)

---

## One-Line Positioning

**Tuck is Helix's immune system — using the 4-byte PFP physical features, it makes pass/intercept/human-confirm decisions in sub-microseconds. It does not think, does not orchestrate, does not execute. It only filters.**

## Core Commitments

| # | Commitment | Meaning | Acceptance criteria |
|---|---|---|---|
| 1 | Reads only 4 bytes, sub-microsecond decision | PFP fixed-offset read, bit operations, no branches | p99 < 1μs |
| 2 | fail-closed, never passes the unknown | any anomaly defaults to intercept | fault injection 100% intercept |
| 3 | Credentials never in component memory | identity_label flow, physical edge injection, zeroization | memory grep finds no plaintext credential |
| 4 | Every decision recorded tamper-proof | SHA-256 chained log, WORM storage | tampering detectable |

## Six Engineering Principles

- **Extreme decoupling**: core has no network dependency; hard real-time path separated from transport layer
- **On-demand loading**: PFP fields lazily extracted by bit operations; non-real-time features deferred
- **On-demand driving**: event-driven, no polling, `decide()` called per frame
- **Extreme reuse**: reuses CI-144 BIND-19 PFP types, does not implement its own frame parsing
- **Physical facts first**: decisions based on PFP sensor features, not AI semantic reasoning
- **Determinism first**: fixed offset, bit operations, match jump table, no branches, no heap allocation

## Architecture

```
crates/
├── tuck-core/      # hard real-time core: PFP read, decide(), fail-closed, Decision type
├── tuck-policy/    # policy engine: Risk-Level policy config, HITL execution gate (P2)
├── tuck-credential/# credential physical injection: identity_label → plaintext credential, zeroization, HSM/TPM (P3)
├── tuck-audit/     # holographic audit: SHA-256 chained log, WORM storage, query API (P4)
├── tuck-proxy/     # transport integration: CI-144 frame proxy, HTTP middleware (P5)
└── tuck/           # binary entry: CLI, config, assembly
```

## Performance Benchmarks (criterion, 1000 samples)

| Benchmark | p50 | p99 | Throughput | Target |
|---|---|---|---|---|
| `decide_from_bytes` CRITICAL | 314.73 ps | **322.89 ps** | 3.10 Gelem/s | < 1μs ✅ (3097x faster) |
| `decide_from_bytes` invalid_magic | 298.72 ps | 299.75 ps | 3.34 Gelem/s | < 1μs ✅ |
| PFP `risk_level()` extraction | 298.78 ps | 299.57 ps | 3.35 Gelem/s | - |
| PFP `effective_risk_level()` | 305.68 ps | 317.91 ps | 3.27 Gelem/s | - |

**Hard real-time decision latency: p99 = 0.32 ns, far beyond the <1μs target (3097x faster).**

Run benchmarks: `cargo bench -p tuck-core`

- **P6-T5 status flow (ADR-0003)**: `StatusProvider` pull-mode query interface (`summary()` real-time cumulative snapshot + `recent_decisions()` recent-event projection), aggregating Metrics atomic counters + reusing the P4 audit chain, zero new storage/write paths — the window for the Cellrix display layer

- **Content governance gateway (ADR-0004)**: Tuck is now the **single door for all LLM traffic** (local + external). Every call passes: identity gate (bearer, fail-closed) → detection (dict/regex/entropy rules) → policy matrix (`{pass/block/hold} × {transform} × {alert}`, destination-tiered) → optional redaction (session-scoped entity→placeholder mapping, in-memory only) → forward → demap on the way back (JSON + SSE with rolling carry). Every call lands in the tamper-evident ledger: `request` record (destination/action/transform/categories/redactions) + `response` record (status/demap_miss), linked by caller `trace_id`. **The chain stores redacted form only — original entities never touch the ledger.** Anchored by batched Ed25519 signatures so a full rewrite of the chain is detectable. Tuck judges strings, never meaning.

## Gateway Service (the only door)

The `tuck` binary assembles the governance gateway (feature `gateway`, 按需加载).
Everything is injected from `TuckConfig.gateway` — no hardcoded values:

```toml
[server]
host = "127.0.0.1"
port = 60052

[gateway]
enabled = true
upstream = "http://127.0.0.1:8000/v1"   # default upstream (单上游兼容)
upstream_key = "sk-..."                  # L2: injected at the physical edge
api_key = "tk-local-gate"                # identity gate (fail-closed)
jwt_secret = ""                          # optional JWT HS256 channel
audit_path = "/var/tuck/audit.jsonl"     # tamper-evident ledger
rules_path = ""                          # detection rules JSON (optional)

# Multi-upstream routing (optional): caller selects with `X-Route-Tier: <tier>`.
# Missing/unknown tier falls back to the default upstream above.
[[gateway.upstreams]]
tier = "free"                            # e.g. a permanent free API pool
base_url = "https://apihub.agnes-ai.com/v1"
upstream_key = "sk-free-..."
```

```bash
cargo run --bin tuck --features gateway -- --config tuck.toml
```

Point any OpenAI-compatible client at `http://127.0.0.1:60052/v1` with
`Authorization: Bearer tk-local-gate`. The gateway governs the traffic,
replaces the credential with the route's `upstream_key` (L2) before leaving
the machine, and writes every call (request + response, trace_id-linked)
to the audit chain. Read it back: `GET /v1/audit?trace_id=...` (same credential).

Route example — daily inference on the free pool, paid as fallback:

```bash
curl http://127.0.0.1:60052/v1/chat/completions \
  -H "Authorization: Bearer tk-local-gate" \
  -H "X-Route-Tier: free" \
  -d '{"model":"agnes-2.5-flash","messages":[{"role":"user","content":"hi"}]}'
```

Anaphase wiring (zero code change): set `reasoning_endpoint` to the gateway
and `reasoning_api_key` to a Tuck credential — the traffic physically
cannot bypass Tuck (ADR-0004 D7/D12).

Library wiring (embedded consumers):

```rust
use tuck_gateway::{governance_router, GatewayState, AuthConfig, policy::RuleSet, matrix::PolicyMatrix};

let chain = tuck_audit::AuditChain::open("audit.jsonl")?;
let state = GatewayState::new("http://127.0.0.1:8080/v1").with_chain(chain);
let router = governance_router(state, rules, PolicyMatrix::default(), AuthConfig { api_key: Some("...".into()) });
// axum::serve(listener, router).await?;
```

## Test Coverage

```
369 tests passed, 0 failed
├── 28 PFP/decision tests (incl. ≥12 fault-injection categories, 100% Reject)
├── 27 SAP optional enhancement tests (replay detection/signature verification/LRU cache/decide_with_sap)
├── 6 status-flow tests (StatusProvider: summary aggregation/recent reverse projection/empty log/truncation/disabled)
├── 9 policy config tests (TOML load/save/version validation/custom policies)
├── 9 HITL execution gate tests (confirm/reject/timeout fail-closed/history records)
├── 9 CATASTROPHIC hard-override tests (emergency signal/broadcast notification/priority/audit)
├── 9 policy hot-reload tests (file monitoring/atomic swap/version management/reload history)
├── 22 credential management tests (identity_label/Credential/Zeroizing/CredentialStore)
├── 17 physical edge injection tests (HttpHeader/Bearer/QueryParam/BodyField/BasicAuth)
├── 13 encrypted file storage tests (AES-256-GCM/master key/atomic write/wrong-key rejection)
├── 10 HSM/TPM trait tests (trait object safety/KeyAlgorithm/PcrPolicy/AttestationQuote)
├── 14 audit log tests (SHA-256 chained structure/verify_chain/tamper detection/capacity limits)
├── 9 WORM storage tests (append write/crash recovery/tampered-file detection/statistics)
├── 14 audit query tests (multi-dimension filtering/pagination/sorting/composite filters/serialization)
├── 16 tamper detection tests (5 tamper types/TamperReport/history integration/end-to-end chain verification)
├── 16 frame parsing tests (FrameHeader/Frame/FrameBuilder/zero-copy/backward compatibility)
├── 14 HTTP intercept tests (PFP header extraction/decide/Allow/Reject/HITL/HardOverride/error handling)
├── 9 outbound handling tests (Allow+inject/Reject no-inject/HardOverride/missing header/credential not found)
├── 15 Mind integration tests (SecurityEvent/AuditQuery/PFP construction guide/bridge traits)
├── 11 Anaphase integration tests (SecurityGate/TuckSecurityGate/credential injection/bridge traits)
├── 12 Tentacle integration tests (PluginAudit/ToolGate/SandboxConstraints/bridge traits)
├── 15 config management tests (TOML parsing/env vars/validation/round-trip serialization)
├── 9 structured log tests (level validation/initialization/format/macros)
├── 13 monitoring metrics tests (decision/risk/latency/credential/audit/SAP/plugin/errors/Prometheus format)
└── 10 health check tests (status/serialization/components/metrics/audit-chain failure)
```

### Content Governance Gateway (ADR-0004, new)

```
tuck-audit (11 tests)
├── 7 chain tests (append/round-trip/deterministic hashing/tail recovery/tamper: modify/delete/reorder)
└── 4 anchor tests (batched Ed25519/signature verify/full-rewrite rejection/wrong-key rejection)
tuck-gateway (40 tests)
├── 4 proxy tests (JSON round-trip/SSE passthrough/auth forward/502)
├── 6 policy engine tests (dict/regex/entropy rules/category/hit spans)
├── 5 policy matrix tests (pass-block-hold precedence/transform/destination tiers/fail-closed)
├── 7 redaction table tests (deterministic placeholder/session scope/redact/demap/demap_miss)
├── 4 governance pipeline tests (mapping redacted/guard blocked/local hygiene/demap restore)
├── 3 identity gate tests (no key denied/wrong key denied/fail-closed unconfigured)
├── 6 session token tests (round-trip/expiry/wrong secret/tamper/alg pin/deterministic)
├── 3 audit query integration tests (JWT scope in audit/trace_id pair/credential required)
└── 1 edge-injection test (L2: upstream_key replaces caller credential)
```
```

Run tests: `cargo test --workspace`
Run benchmarks: `cargo bench -p tuck-core`

## Core Modules

| Module | Duty | Status |
|---|---|---|
| `pfp` (lib.rs) | PFP 4-byte zero-copy read + decide() hard real-time decision | ✅ |
| `sap` | SAP 28-byte optional enhancement + Seq-Counter replay protection | ✅ |
| `policy` | policy config (TOML) + version management + file load/save | ✅ |
| `hitl` | HITL execution gate (NeedHumanConfirm → confirm/timeout Reject) | ✅ |
| `catastrophic` | CATASTROPHIC hard override (emergency signal + parallel human notification) | ✅ |
| `hot_reload` | policy hot reload (file monitoring + atomic swap + reload history) | ✅ |
| `credential` | credential management (identity_label + Credential + Zeroizing + CredentialStore trait) | ✅ |
| `injection` | physical edge injection (inject before outbound + zeroize after injection) | ✅ |
| `file_store` | encrypted file storage (AES-256-GCM + MasterKey + atomic write) | ✅ |
| `hsm` | HSM/TPM trait reservation (HsmCredentialStore + TpmCredentialStore) | ✅ |
| `audit` | audit log (SHA-256 chained structure + AuditLog + verify_chain) | ✅ |
| `audit_store` | WORM storage (append-only file + crash recovery + tamper detection) | ✅ |
| `audit_query` | audit query API (multi-dimension filtering + pagination + sorting + Queryable trait) | ✅ |
| `tamper` | tamper detection (TamperReport + 5 tamper types + history integration) | ✅ |
| `frame` | CI-144 frame parser (zero-copy Frame/FrameHeader/FrameBuilder) | ✅ |
| `proxy` | HTTP interceptor (PFP header extraction + decide + InterceptResult) | ✅ |
| `outbound` | outbound handler (intercept + credential injection integration + OutboundHandler) | ✅ |
| `mind_bridge` | Helix-Mind integration (SecurityEvent/AuditQuery/PFP construction guide) | ✅ |
| `anaphase_bridge` | Anaphase integration (SecurityGate/TuckSecurityGate/credential injection) | ✅ |
| `tentacle_bridge` | Tentacle integration (PluginAudit/ToolGate/SandboxConstraints) | ✅ |
| `config` | config management (TOML parsing/env-var override/config validation) | ✅ |
| `metrics` | monitoring metrics (Prometheus format/atomic counters/decision/latency/errors) | ✅ |
| `health` | health checks (component status/metrics summary/Kubernetes probes) | ✅ |

## Quick Start

```bash
# build
cargo build --workspace

# test
cargo test --workspace

# run (PFP hex bytes)
cargo run --bin tuck -- --pfp CF140800
```

## PFP 4-Byte Structure

```
Byte 0-1: Family-Magic (0xCF14)
Byte 2:
  bit 0-1: Modality       (COGNITIVE/RENDER/EXECUTIVE/SENSOR_FEED)
  bit 2-3: Risk-Level     (LOW/MEDIUM/CRITICAL/CATASTROPHIC)
  bit 4-5: Body-Stance    (SEATED/STANDING/MOVING/UNKNOWN)
  bit 6-7: Proximity-Edge (SAFE/WARNING/DANGER/CRITICAL_EDGE)
Byte 3:
  bit 0:   Output-Dest    (INTERNAL/EXTERNAL)
  bit 1:   Override-Flag  (NORMAL/HARD_OVERRIDE)
  bit 2:   Replay-Enable  (DISABLED/ENABLED)
  bit 3-7: Reserved       (must be 0)
```

## Decision Rules

| Risk-Level | Default decision |
|---|---|
| LOW | Pass |
| MEDIUM | Pass |
| CRITICAL | NeedHumanConfirm |
| CATASTROPHIC | Reject |
| CATASTROPHIC + HardOverride | HardOverridePass (non-negotiable) |

**Rule 6**: when Replay-Enable=0, the effective Risk-Level is forcibly downgraded to MEDIUM (replay-attack protection).

## Development Plan

| Stage | Content | Status |
|---|---|---|
| P0 | methodology initialization + Rust project skeleton | ✅ done |
| P1 | core skeleton (PFP read + decide() + fail-closed) | ✅ done |
| P2 | policy engine (Risk-Level policies + HITL + CATASTROPHIC) | ✅ done |
| P3 | credential physical injection (identity_label + zeroization + HSM) | ✅ done |
| P4 | holographic audit (SHA-256 chained + WORM + query API) | ✅ done |
| P5 | transport integration (CI-144 proxy + HTTP middleware) | ✅ done |
| P6 | ecosystem integration (CI-144/Mind/Anaphase/Tentacle/Cellrix status flow) | ✅ done |
| P7 | production readiness (config/logging/monitoring/health/deployment) | ✅ done |

## Deployment

### Docker

```bash
# build image
docker build -t tuck:latest .

# run
docker run -d \
  --name tuck \
  -p 8443:8443 \
  -v /etc/tuck:/etc/tuck:ro \
  -v /var/log/tuck:/var/log/tuck \
  tuck:latest
```

### systemd

```bash
# copy service file
sudo cp deploy/tuck.service /etc/systemd/system/

# create user and directories
sudo useradd --system tuck
sudo mkdir -p /etc/tuck /var/log/tuck /var/lib/tuck
sudo chown -R tuck:tuck /etc/tuck /var/log/tuck /var/lib/tuck

# copy config
sudo cp config.example.toml /etc/tuck/config.toml

# start
sudo systemctl enable --now tuck

# check status
sudo systemctl status tuck
sudo journalctl -u tuck -f
```

### Configuration

Copy `config.example.toml` to `config.toml` and modify. Environment variable overrides supported:

```bash
export TUCK_SERVER__PORT=9090
export TUCK_LOG__LEVEL=debug
export TUCK_LOG__FORMAT=json
export TUCK_CREDENTIAL__MASTER_KEY=your-hex-key
```

## Monitoring

### Prometheus Metrics

Prometheus-format metrics exposed at the `/metrics` endpoint by default:

- `tuck_decisions_total{decision="pass|reject|hitl|hard_override"}` — decision counts
- `tuck_risk_levels_total{risk="low|medium|critical|catastrophic"}` — risk-level counts
- `tuck_decision_latency_seconds` — average decision latency
- `tuck_credential_injections_total{result="success|failed"}` — credential injection results
- `tuck_credential_lookups_total{result="hit|miss"}` — credential lookup results
- `tuck_audit_entries_total` — audit entry count
- `tuck_audit_chain_verifications_total{result="success|failure"}` — audit chain verification
- `tuck_sap_verifications_total{result="success|failed"}` — SAP signature verification
- `tuck_replay_cache_total{result="hit|miss"}` — replay cache
- `tuck_plugin_audits_total{decision="pass|reject|hitl"}` — plugin audits
- `tuck_errors_total{type="invalid_pfp|invalid_sap|config_error"}` — error counts
- `tuck_uptime_seconds` — uptime

### Health Checks

The `/health` endpoint returns JSON health status:

```json
{
  "status": "healthy",
  "service": "tuck",
  "version": "0.1.0",
  "uptime_seconds": 1234,
  "components": [...],
  "metrics": {...}
}
```

Suitable for Kubernetes liveness/readiness probes and load-balancer health checks.

## Ecosystem Alignment

- **CI-144 protocol family**: https://github.com/CommonIntents/BIND-19
- **PFP-xCF14 spec**: https://github.com/CommonIntents/PFP-xCF14
- **phyt-DNA methodology**: https://github.com/Jasonmilk/phyt-DNA
- **Helix-Mind** (soul/thinking): https://github.com/Jasonmilk/Helix-Mind
- **Anaphase-Helix** (body/orchestration): https://github.com/Jasonmilk/Anaphase-Helix
- **Helix-Tentacle** (hands/tool execution): https://github.com/Jasonmilk/Helix-Tentacle

## Methodology

Tuck follows the **phyt-DNA v1.0** self-growing methodology. Core documents:

- `docs/VISION.md` — vision index (thought alignment)
- `docs/DNA.md` — immutable principles + Tuck-specific ironclad rules
- `docs/RNA.md` — loading protocol + AI collaboration rules
- `docs/SPEC.md` — complete narrative (knowledge ontology)
- `docs/PLAN.md` — development navigation board
- `docs/GROWTH.md` — growth records
- `docs/DEPRECATE.md` — retirement records
- `docs/spec/` — philosophy/architecture/contract/safety/position volumes
- `docs/decisions/` — ADR architecture decision records

## License

Apache 2.0 (unified ecosystem license per phyt-DNA PROTECTION v1.1)
