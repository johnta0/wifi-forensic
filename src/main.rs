//! wfx — Wi-Fi forensic CLI.
//!
//! - `wfx inspect` : show the current Wi-Fi / IP settings (does not test connectivity)
//! - `wfx test`    : diagnose the current connection layer by layer (exit 1 on failure)
//!
//! - `wfx capture`: join the target SSID, record, and always restore the original Wi-Fi (saves a bundle)
//! - `wfx analyze`: rule-based analysis of a bundle
//! - `wfx bundles`: list saved bundles
//!
//! `--json` switches to machine-readable output for agents.

mod analyze;
mod bundle;
mod capture;
mod collect;
mod diagnose;
mod exec;
mod model;
mod render;
mod restore;
mod worker;

use clap::{Parser, Subcommand};
use model::*;

#[derive(Parser)]
#[command(name = "wfx", version, about = "Wi-Fi forensic CLI")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the current Wi-Fi and IP settings
    Inspect {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Diagnose the current connection layer by layer
    Test {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Join the target SSID, record, and restore the original Wi-Fi (tcpdump needs sudo)
    Capture {
        /// SSID to join (password from Keychain, or the WFX_WIFI_PASSWORD env var if unknown)
        ssid: String,
        /// SSID to restore to (default: the SSID connected before running)
        #[arg(long)]
        restore: Option<String>,
        /// Maximum seconds to wait for an IP address
        #[arg(long, default_value_t = 45)]
        dhcp_wait: u64,
        /// Skip packet capture (no sudo needed)
        #[arg(long)]
        no_pcap: bool,
        /// Return the bundle path as soon as the worker starts
        #[arg(long)]
        no_wait: bool,
        /// Print summary.json as is
        #[arg(long)]
        json: bool,
    },
    /// Analyze a bundle with rule-based checks
    Analyze {
        bundle: std::path::PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List saved bundles, newest first
    Bundles,
    /// Detached capture body (internal)
    #[command(name = "__capture-worker", hide = true)]
    CaptureWorker { bundle: std::path::PathBuf },
}

fn main() -> anyhow::Result<()> {
    // Usage errors exit 64 (clap's default 2 collides with "restore failed")
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            std::process::exit(if e.use_stderr() { 64 } else { 0 });
        }
    };
    match cli.command {
        Cmd::Inspect { json } => {
            let c = collect::collect();
            for w in &c.warnings {
                eprintln!("warn: {w}");
            }
            let report = Inspection {
                schema_version: SCHEMA_VERSION,
                timestamp: collect::now_iso8601(),
                wifi: c.wifi,
                network: c.network,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render::inspection(&report));
            }
        }
        Cmd::Test { json } => {
            let c = collect::collect();
            for w in &c.warnings {
                eprintln!("warn: {w}");
            }
            let report = diagnose::build_test_report(c);
            let failed = report.first_failure.is_some();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render::test_report(&report));
            }
            if failed {
                std::process::exit(1);
            }
        }
        Cmd::Capture { ssid, restore, dhcp_wait, no_pcap, no_wait, json } => {
            let code = capture::run(capture::CaptureArgs { ssid, restore, dhcp_wait, no_pcap, no_wait, json });
            std::process::exit(code);
        }
        Cmd::Analyze { bundle, json } => analyze::run(&bundle, json)?,
        Cmd::Bundles => capture::list_bundles()?,
        Cmd::CaptureWorker { bundle } => std::process::exit(worker::run(&bundle)),
    }
    Ok(())
}
