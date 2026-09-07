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

mod logging;

use clap::Parser;
use tuck_core::{config::TuckConfig, decide_from_bytes, SecurityPolicy};

/// Tuck — Helix ecosystem immune system (CI-144 PFP consumer, hard real-time security gate).
#[derive(Parser, Debug)]
#[command(name = "tuck", version, about)]
struct Cli {
    /// PFP header bytes as hex (e.g. "CF140000"). If omitted, runs in library mode.
    #[arg(short, long)]
    pfp: Option<String>,

    /// Configuration file path (TOML).
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load configuration (TOML file + environment variable overrides)
    let config = TuckConfig::load(cli.config.as_deref())?;

    // Initialize structured logging (按需加载: only when binary runs)
    let _logging_guard = logging::init_logging(&config.log)?;

    tracing::info!(
        target: "tuck::startup",
        version = env!("CARGO_PKG_VERSION"),
        host = %config.server.host,
        port = config.server.port,
        fail_closed = config.security.fail_closed,
        "Tuck starting up"
    );

    // Default policy (按需驱动: policy loaded once, decide() called per-frame)
    let policy = SecurityPolicy::default();

    if let Some(hex) = cli.pfp {
        // Decode hex PFP bytes
        let bytes = hex::decode(&hex)?;
        let decision = decide_from_bytes(&bytes, &policy);

        // Structured logging
        tracing::info!(
            target: "tuck::decision",
            pfp = %hex.to_uppercase(),
            decision = ?decision,
            "PFP decision"
        );

        println!("PFP: 0x{}", hex.to_uppercase());
        println!("Decision: {:?}", decision);
    } else {
        // Library mode — print info
        println!("Tuck v{} — Helix ecosystem immune system", env!("CARGO_PKG_VERSION"));
        println!();
        println!("Usage: tuck --pfp <hex-bytes>");
        println!("Example: tuck --pfp CF140800  (CRITICAL risk, normal override)");
        println!();
        println!("Configuration:");
        println!("  --config <path>  TOML configuration file");
        println!("  Environment: TUCK_SERVER__PORT, TUCK_LOG__LEVEL, etc.");
        println!();
        println!("Principles: 极致解耦 / 按需加载 / 按需驱动 / 极致复用 / 物理事实优先 / 确定性优先");
    }

    tracing::info!(target: "tuck::shutdown", "Tuck shutting down");
    Ok(())
}
