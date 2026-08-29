//! Tuck P5 integration benchmarks.
//!
//! Measures end-to-end performance of the full P5 pipeline:
//! - Frame parsing + PFP extraction
//! - HTTP interception + decide()
//! - Credential injection
//! - Audit log write throughput

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tuck_core::audit::AuditLog;
use tuck_core::credential::{Credential, CredentialError, CredentialStore, IdentityLabel};
use tuck_core::frame::{Frame, FrameBuilder};
use tuck_core::injection::{InjectionTarget, OutboundRequest};
use tuck_core::outbound::OutboundHandler;
use tuck_core::proxy::{HttpInterceptor, pfp_header_value};
use tuck_core::{Decision, OverrideFlag, RiskLevel, SecurityPolicy};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// Simple in-memory credential store for benchmarks.
#[derive(Default)]
struct BenchCredentialStore {
    credentials: Mutex<HashMap<String, Vec<u8>>>,
}

impl BenchCredentialStore {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&self, label: &str, value: &[u8]) {
        self.credentials
            .lock()
            .unwrap()
            .insert(label.to_string(), value.to_vec());
    }
}

#[async_trait]
impl CredentialStore for BenchCredentialStore {
    async fn get(&self, label: &IdentityLabel) -> Result<Credential, CredentialError> {
        let key = label.to_string();
        let creds = self.credentials.lock().unwrap();
        match creds.get(&key) {
            Some(bytes) if !bytes.is_empty() => Ok(Credential::new(bytes.clone(), label.clone())),
            Some(_) => Err(CredentialError::Empty),
            None => Err(CredentialError::NotFound(key)),
        }
    }

    async fn put(&self, _label: &IdentityLabel, _credential: &[u8]) -> Result<(), CredentialError> {
        unimplemented!()
    }

    async fn delete(&self, _label: &IdentityLabel) -> Result<(), CredentialError> {
        unimplemented!()
    }

    async fn list(&self) -> Result<Vec<IdentityLabel>, CredentialError> {
        unimplemented!()
    }
}

/// Build a PFP 4-byte array from risk level and override flag.
fn make_pfp_bytes(risk: RiskLevel, override_flag: OverrideFlag) -> [u8; 4] {
    let modality = 2; // Executive
    let body_stance = 1; // Standing
    let proximity_edge = 0; // Safe
    let output_dest = 1; // External
    let replay_enable = 1; // Enabled

    let byte2 = modality | (risk as u8) << 2 | body_stance << 4 | proximity_edge << 6;
    let byte3 = output_dest | (override_flag as u8) << 1 | replay_enable << 2;

    [0xCF, 0x14, byte2, byte3]
}

// ============================================================================
// Benchmark 1: Frame parsing + PFP extraction
// ============================================================================

fn bench_frame_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_parsing");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Build a frame with PFP + payload
    let pfp = make_pfp_bytes(RiskLevel::Critical, OverrideFlag::Normal);
    let frame_bytes = FrameBuilder::new()
        .with_seq(42)
        .with_pfp(pfp)
        .with_payload(vec![0u8; 1024])
        .build();

    group.bench_function("parse_full_frame", |b| {
        b.iter(|| {
            let frame = Frame::parse(&frame_bytes).unwrap();
            let _ = frame.extract_pfp().unwrap();
        })
    });

    group.bench_function("parse_header_only", |b| {
        b.iter(|| {
            let header = tuck_core::frame::FrameHeader::parse(&frame_bytes).unwrap();
            let _ = header.seq;
        })
    });

    group.finish();
}

// ============================================================================
// Benchmark 2: HTTP interception + decide
// ============================================================================

fn bench_http_interception(c: &mut Criterion) {
    let policy = SecurityPolicy::default();
    let interceptor = HttpInterceptor::new(policy);

    let mut group = c.benchmark_group("http_interception");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    let scenarios = [
        ("LOW", RiskLevel::Low, OverrideFlag::Normal),
        ("CRITICAL", RiskLevel::Critical, OverrideFlag::Normal),
        ("CATASTROPHIC", RiskLevel::Catastrophic, OverrideFlag::Normal),
        ("HARD_OVERRIDE", RiskLevel::Catastrophic, OverrideFlag::HardOverride),
    ];

    for (name, risk, override_flag) in scenarios {
        let pfp = make_pfp_bytes(risk, override_flag);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![("x-pfp", pfp_value.as_str())];

        group.bench_with_input(BenchmarkId::new("intercept", name), &headers, |b, h| {
            b.iter(|| interceptor.intercept(h.clone()).unwrap())
        });
    }

    group.finish();
}

// ============================================================================
// Benchmark 3: Credential injection
// ============================================================================

fn bench_credential_injection(c: &mut Criterion) {
    let store = BenchCredentialStore::new();
    store.insert("env:test/api-key", b"secret-token-12345-very-long-value-for-benchmark");

    let policy = SecurityPolicy::default();
    let handler = OutboundHandler::new(policy, store);

    let mut group = c.benchmark_group("credential_injection");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
    let pfp_value = pfp_header_value(&pfp);

    let targets = [
        ("HttpHeader", InjectionTarget::header("X-API-Key")),
        ("BearerToken", InjectionTarget::BearerToken),
        ("QueryParam", InjectionTarget::query_param("api_key")),
    ];

    for (name, target) in targets {
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:test/api-key"),
        ];

        group.bench_with_input(BenchmarkId::new("inject", name), &target, |b, t| {
            b.iter(|| {
                let mut request = OutboundRequest::new();
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(handler.handle_outbound(headers.clone(), &mut request, t)).unwrap()
            })
        });
    }

    group.finish();
}

// ============================================================================
// Benchmark 4: Audit log write throughput
// ============================================================================

fn bench_audit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_throughput");
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Single entry append
    group.bench_function("append_single", |b| {
        let mut log = AuditLog::new();
        b.iter(|| {
            log.append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                "test",
                None,
            );
        })
    });

    // Batch append (100 entries)
    group.bench_function("append_batch_100", |b| {
        b.iter(|| {
            let mut log = AuditLog::new();
            for i in 0..100 {
                log.append(
                    Decision::Pass,
                    "Low",
                    "Cognitive",
                    "Normal",
                    &format!("test-{i}"),
                    None,
                );
            }
        })
    });

    // Chain verification (1000 entries)
    group.bench_function("verify_chain_1000", |b| {
        let mut log = AuditLog::new();
        for i in 0..1000 {
            log.append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                &format!("test-{i}"),
                None,
            );
        }
        b.iter(|| log.verify_chain())
    });

    group.finish();
}

// ============================================================================
// Benchmark 5: Full pipeline (frame → intercept → inject → audit)
// ============================================================================

fn bench_full_pipeline(c: &mut Criterion) {
    let store = BenchCredentialStore::new();
    store.insert("env:test/api-key", b"secret-token");

    let policy = SecurityPolicy::default();
    let handler = OutboundHandler::new(policy, store);

    let mut group = c.benchmark_group("full_pipeline");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
    let pfp_value = pfp_header_value(&pfp);
    let target = InjectionTarget::header("X-API-Key");

    group.bench_function("full_pipeline_allow", |b| {
        b.iter(|| {
            let headers = vec![
                ("x-pfp", pfp_value.as_str()),
                ("x-identity-label", "env:test/api-key"),
            ];
            let mut request = OutboundRequest::new();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(handler.handle_outbound(headers, &mut request, &target)).unwrap();

            // Also write audit entry
            let mut log = AuditLog::new();
            log.append(
                Decision::Pass,
                "Low",
                "Executive",
                "Normal",
                "benchmark",
                Some("env:test/api-key"),
            );
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_parsing,
    bench_http_interception,
    bench_credential_injection,
    bench_audit_throughput,
    bench_full_pipeline
);
criterion_main!(benches);
