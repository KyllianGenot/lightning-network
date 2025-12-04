//! CLI for LNURL channel and withdraw protocols.
//!
//! Implements LNURL-channel and LNURL-withdraw protocols,
//! communicating with a Core Lightning node via `lightning-cli`.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tracing::{debug, error, info};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_CLI_PATH: &str = "lightning-cli";
const DEFAULT_WITHDRAW_DESCRIPTION: &str = "LNURL withdrawal";
const INVOICE_LABEL_PREFIX: &str = "lnurl-withdraw";
const STATUS_OK: &str = "OK";

// ============================================================================
// CLI Configuration
// ============================================================================

#[derive(Parser)]
#[command(name = "lnurl-client")]
#[command(version, about = "CLI for LNURL channel and withdraw protocols")]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Request a channel from an LNURL server
    ChannelRequest {
        /// Server URL (e.g., http://localhost:3000)
        server: String,

        /// Path to lightning-cli binary
        #[arg(long, default_value = DEFAULT_CLI_PATH)]
        cli_path: String,

        /// Bitcoin network (e.g., testnet, signet)
        #[arg(long)]
        network: Option<String>,
    },

    /// Request a withdrawal from an LNURL server
    WithdrawRequest {
        /// Server URL (e.g., http://localhost:3000)
        server: String,

        /// Amount to withdraw in millisatoshis
        amount_msat: u64,

        /// Invoice description
        #[arg(long, default_value = DEFAULT_WITHDRAW_DESCRIPTION)]
        description: String,

        /// Path to lightning-cli binary
        #[arg(long, default_value = DEFAULT_CLI_PATH)]
        cli_path: String,

        /// Bitcoin network (e.g., testnet, signet)
        #[arg(long)]
        network: Option<String>,
    },
}

// ============================================================================
// API Response Types
// ============================================================================

/// Response from LNURL-channel initial request.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ChannelRequestResponse {
    uri: String,
    callback: String,
    k1: String,
    tag: String,
}

/// Response from LNURL-withdraw initial request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct WithdrawRequestResponse {
    callback: String,
    k1: String,
    tag: String,
    default_description: String,
    min_withdrawable: u64,
    max_withdrawable: u64,
}

/// Response from channel open callback.
#[derive(Debug, Deserialize)]
struct ChannelOpenResponse {
    status: String,
    reason: Option<String>,
    txid: Option<String>,
    channel_id: Option<String>,
}

/// Response from withdraw callback.
#[derive(Debug, Deserialize)]
struct WithdrawResponse {
    status: String,
    reason: Option<String>,
}

/// Response from lightning-cli getinfo.
#[derive(Debug, Deserialize)]
struct GetInfoResponse {
    id: String,
}

/// Response from lightning-cli invoice.
#[derive(Debug, Deserialize)]
struct InvoiceResponse {
    bolt11: String,
}

// ============================================================================
// Lightning CLI Helpers
// ============================================================================

/// Builds a lightning-cli command with optional network flag.
fn build_cli_command(cli_path: &str, network: Option<&str>) -> Command {
    let mut cmd = Command::new(cli_path);
    if let Some(net) = network {
        cmd.arg(format!("--network={net}"));
    }
    cmd
}

/// Executes a lightning-cli command and returns the output.
fn execute_cli_command(mut cmd: Command) -> Result<Vec<u8>> {
    let output = cmd.output().context("Failed to execute lightning-cli")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed: {stderr}");
    }

    Ok(output.stdout)
}

/// Retrieves the local node ID from the Lightning node.
fn get_local_node_id(cli_path: &str, network: Option<&str>) -> Result<String> {
    let mut cmd = build_cli_command(cli_path, network);
    cmd.arg("getinfo");

    let output = execute_cli_command(cmd).context("getinfo failed")?;
    let info: GetInfoResponse = serde_json::from_slice(&output)?;

    Ok(info.id)
}

/// Connects to a remote Lightning node.
fn connect_to_peer(cli_path: &str, network: Option<&str>, uri: &str) -> Result<()> {
    info!(uri, "Connecting to peer");

    let mut cmd = build_cli_command(cli_path, network);
    cmd.args(["connect", uri]);

    match execute_cli_command(cmd) {
        Ok(_) => {
            info!("Successfully connected to peer");
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already connected") {
                debug!("Already connected to peer");
                Ok(())
            } else {
                Err(e).context("Failed to connect to peer")
            }
        }
    }
}

/// Creates a Lightning invoice for receiving payment.
fn create_invoice(
    cli_path: &str,
    network: Option<&str>,
    amount_msat: u64,
    description: &str,
) -> Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time error")?
        .as_millis();
    let label = format!("{INVOICE_LABEL_PREFIX}-{timestamp}");

    let mut cmd = build_cli_command(cli_path, network);
    cmd.args(["invoice", &format!("{amount_msat}msat"), &label, description]);

    let output = execute_cli_command(cmd).context("Invoice creation failed")?;
    let response: InvoiceResponse = serde_json::from_slice(&output)?;

    Ok(response.bolt11)
}

// ============================================================================
// LNURL Protocol Handlers
// ============================================================================

/// Handles LNURL-channel flow: requests channel info and initiates channel opening.
async fn handle_channel_request(server: &str, cli_path: &str, network: Option<&str>) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = server.trim_end_matches('/');

    // Step 1: Get channel request info
    info!(server, "Requesting channel info");
    let url = format!("{base_url}/channel-request");
    let response: ChannelRequestResponse = client
        .get(&url)
        .send()
        .await
        .context("Failed to reach server")?
        .json()
        .await
        .context("Invalid response format")?;

    debug!(uri = %response.uri, callback = %response.callback, "Received channel request");

    // Step 2: Connect to the remote node
    connect_to_peer(cli_path, network, &response.uri)?;

    // Step 3: Get local node ID
    let local_node_id = get_local_node_id(cli_path, network)?;
    debug!(node_id = %local_node_id, "Retrieved local node ID");

    // Step 4: Request channel opening
    info!("Requesting channel open");
    let open_url = format!("{base_url}/open-channel?remoteid={local_node_id}&k1={}", response.k1);

    let open_response: ChannelOpenResponse = client
        .get(&open_url)
        .send()
        .await
        .context("Channel open request failed")?
        .json()
        .await
        .context("Invalid channel open response")?;

    if open_response.status == STATUS_OK {
        info!("Channel opened successfully");
        if let Some(txid) = &open_response.txid {
            info!(txid, "Funding transaction");
        }
        if let Some(channel_id) = &open_response.channel_id {
            info!(channel_id, "Channel ID");
        }
    } else {
        let reason = open_response.reason.unwrap_or_default();
        error!(reason, "Channel open failed");
        bail!("Channel open failed: {reason}");
    }

    Ok(())
}

/// Handles LNURL-withdraw flow: requests withdrawal info and submits invoice for payment.
async fn handle_withdraw_request(
    server: &str,
    amount_msat: u64,
    description: &str,
    cli_path: &str,
    network: Option<&str>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = server.trim_end_matches('/');

    // Step 1: Get withdrawal request info
    info!(server, "Requesting withdrawal info");
    let url = format!("{base_url}/withdraw-request");
    let response: WithdrawRequestResponse = client
        .get(&url)
        .send()
        .await
        .context("Failed to reach server")?
        .json()
        .await
        .context("Invalid response format")?;

    debug!(
        min = response.min_withdrawable,
        max = response.max_withdrawable,
        "Withdrawal limits"
    );

    // Step 2: Validate amount
    if amount_msat < response.min_withdrawable || amount_msat > response.max_withdrawable {
        bail!(
            "Amount {amount_msat} msat outside allowed range [{}, {}]",
            response.min_withdrawable,
            response.max_withdrawable
        );
    }

    // Step 3: Create invoice
    info!(amount_msat, "Creating invoice");
    let bolt11 = create_invoice(cli_path, network, amount_msat, description)?;
    debug!(invoice_preview = &bolt11[..bolt11.len().min(50)], "Invoice created");

    // Step 4: Submit withdrawal request
    info!("Submitting withdrawal request");
    let withdraw_url = format!("{base_url}/withdraw?k1={}&pr={bolt11}", response.k1);

    let withdraw_response: WithdrawResponse = client
        .get(&withdraw_url)
        .send()
        .await
        .context("Withdrawal request failed")?
        .json()
        .await
        .context("Invalid withdrawal response")?;

    if withdraw_response.status == STATUS_OK {
        info!("Withdrawal successful");
    } else {
        let reason = withdraw_response.reason.unwrap_or_default();
        error!(reason, "Withdrawal failed");
        bail!("Withdrawal failed: {reason}");
    }

    Ok(())
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    let result = match cli.command {
        Commands::ChannelRequest {
            server,
            cli_path,
            network,
        } => handle_channel_request(&server, &cli_path, network.as_deref()).await,

        Commands::WithdrawRequest {
            server,
            amount_msat,
            description,
            cli_path,
            network,
        } => {
            handle_withdraw_request(&server, amount_msat, &description, &cli_path, network.as_deref())
                .await
        }
    };

    if let Err(e) = result {
        error!("{e:#}");
        std::process::exit(1);
    }
}
