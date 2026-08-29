//! Tuck — Helix ecosystem immune system.
//!
//! Binary entry point. Thin assembly layer only — all business logic lives in `tuck-core`.
//!
//! # Principles
//! - **极致解耦**: Binary only assembles crates, no business logic here.
//! - **按需加载**: Components loaded only when needed (proxy/audit/credential are optional features).
//! - **按需驱动**: Event-driven, no polling. `decide()` is called per-frame, not in a loop.
//! - **极致复用**: Reuses `tuck-core` decision engine, BIND-19 PFP types, CI-144 protocol family.
//! - **物理事实优先**: Decisions based on PFP physical features (sensor-driven), not AI semantics.
//! - **确定性优先**: Fixed offset, bit operations, match jump table, no branch, no heap allocation in hot path.

use clap::Parser;
use tuck_core::{decide_from_bytes, SecurityPolicy};

/// Tuck — Helix ecosystem immune system (CI-144 PFP consumer, hard real-time security gate).
#[derive(Parser, Debug)]
#[command(name = "tuck", version, about)]
struct Cli {
    /// PFP header bytes as hex (e.g. "CF140000"). If omitted, runs in library mode.
    #[arg(short, long)]
    pfp: Option<String>,

    /// Show version and exit.
    #[arg(short, long)]
    version: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing (按需加载: only when binary runs, not when used as library)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.version {
        println!("Tuck v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Default policy (按需驱动: policy loaded once, decide() called per-frame)
    let policy = SecurityPolicy::default();

    if let Some(hex) = cli.pfp {
        // Decode hex PFP bytes
        let bytes = hex::decode(&hex)?;
        let decision = decide_from_bytes(&bytes, &policy);
        println!("PFP: 0x{}", hex.to_uppercase());
        println!("Decision: {:?}", decision);
    } else {
        // Library mode — print info
        println!("Tuck v{} — Helix ecosystem immune system", env!("CARGO_PKG_VERSION"));
        println!();
        println!("Usage: tuck --pfp <hex-bytes>");
        println!("Example: tuck --pfp CF140800  (CRITICAL risk, normal override)");
        println!();
        println!("Principles: 极致解耦 / 按需加载 / 按需驱动 / 极致复用 / 物理事实优先 / 确定性优先");
    }

    Ok(())
}
