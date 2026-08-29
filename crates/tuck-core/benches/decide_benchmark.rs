//! Tuck hard real-time decision benchmarks.
//!
//! Measures p50/p90/p99/p999 latency of the `decide()` function.
//! Target: p99 < 1μs (sub-microsecond hard real-time decision).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tuck_core::{decide, decide_from_bytes, OverrideFlag, PfpHeader, ReplayEnable, RiskLevel, SecurityPolicy};

/// Build a PFP header with given risk level, override flag, and replay enable.
fn make_pfp(risk: RiskLevel, override_flag: OverrideFlag, replay_enable: ReplayEnable) -> PfpHeader {
    let mut bytes = [0xCF, 0x14, 0, 0];
    bytes[2] = (risk as u8) << 2;
    bytes[3] = (override_flag as u8) << 1 | (replay_enable as u8) << 2;
    PfpHeader::from_bytes(bytes).unwrap()
}

/// Benchmark `decide()` for each risk level.
fn bench_decide(c: &mut Criterion) {
    let policy = SecurityPolicy::default();
    let mut group = c.benchmark_group("decide");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    let scenarios = [
        ("LOW", RiskLevel::Low, OverrideFlag::Normal, ReplayEnable::Enabled),
        ("MEDIUM", RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Enabled),
        ("CRITICAL", RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled),
        ("CATASTROPHIC", RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Enabled),
        ("CATASTROPHIC_OVERRIDE", RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Enabled),
        ("RULE6_DOWNGRADE", RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Disabled),
    ];

    for (name, risk, override_flag, replay_enable) in scenarios {
        let pfp = make_pfp(risk, override_flag, replay_enable);
        group.bench_with_input(BenchmarkId::new("decide", name), &pfp, |b, pfp| {
            b.iter(|| decide(pfp, &policy))
        });
    }

    group.finish();
}

/// Benchmark `decide_from_bytes()` — full path from raw bytes to decision.
fn bench_decide_from_bytes(c: &mut Criterion) {
    let policy = SecurityPolicy::default();
    let mut group = c.benchmark_group("decide_from_bytes");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));

    // CRITICAL risk (typical high-value decision path)
    let bytes = [0xCF, 0x14, 0b1000, 0b000]; // CRITICAL, Normal, Replay enabled

    group.bench_function("CRITICAL_from_bytes", |b| {
        b.iter(|| decide_from_bytes(&bytes, &policy))
    });

    // Invalid magic (fail-closed path)
    let invalid_bytes = [0x00, 0x00, 0, 0];
    group.bench_function("invalid_magic_reject", |b| {
        b.iter(|| decide_from_bytes(&invalid_bytes, &policy))
    });

    group.finish();
}

/// Benchmark PFP field extraction — verify zero-copy lazy extraction is fast.
fn bench_pfp_extraction(c: &mut Criterion) {
    let pfp = make_pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled);
    let mut group = c.benchmark_group("pfp_extraction");
    group.throughput(Throughput::Elements(1));
    group.sample_size(1000);

    group.bench_function("risk_level", |b| b.iter(|| pfp.risk_level()));
    group.bench_function("override_flag", |b| b.iter(|| pfp.override_flag()));
    group.bench_function("effective_risk_level", |b| b.iter(|| pfp.effective_risk_level()));
    group.bench_function("all_fields", |b| {
        b.iter(|| {
            let _ = pfp.modality();
            let _ = pfp.risk_level();
            let _ = pfp.body_stance();
            let _ = pfp.proximity_edge();
            let _ = pfp.output_dest();
            let _ = pfp.override_flag();
            let _ = pfp.replay_enable();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decide,
    bench_decide_from_bytes,
    bench_pfp_extraction
);
criterion_main!(benches);
