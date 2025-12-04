//! LNURL server for Lightning Network channel requests and withdrawals.
//!
//! This server implements LNURL-channel and LNURL-withdraw protocols,
//! communicating with a Core Lightning node via cln-rpc.

use std::env;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use cln_rpc::model::requests::{FundchannelRequest, PayRequest};
use cln_rpc::primitives::{Amount, AmountOrAll, Sha256};
use cln_rpc::{ClnRpc, Request, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_RPC_PATH: &str = "/tmp/lightning-rpc";
const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 3000;

const TAG_CHANNEL_REQUEST: &str = "channelRequest";
const TAG_WITHDRAW_REQUEST: &str = "withdrawRequest";

const STATUS_OK: &str = "OK";
const STATUS_ERROR: &str = "ERROR";

/// Default channel funding amount in satoshis.
const DEFAULT_CHANNEL_AMOUNT_SAT: u64 = 100_000;

/// Minimum withdrawal amount in millisatoshis (1 sat).
const MIN_WITHDRAWABLE_MSAT: u64 = 1_000;

/// Maximum withdrawal amount in millisatoshis (1000 sats).
const MAX_WITHDRAWABLE_MSAT: u64 = 1_000_000;

// ============================================================================
// Application State
// ============================================================================

/// Shared state containing the CLN RPC client.
type AppState = Arc<Mutex<ClnRpc>>;

/// Server configuration loaded from environment variables.
struct Config {
    rpc_path: String,
    host: String,
    port: u16,
    node_pubkey: String,
    node_address: String,
}

impl Config {
    /// Loads configuration from environment variables with defaults.
    fn from_env() -> Self {
        Self {
            rpc_path: env::var("CLN_RPC_PATH").unwrap_or_else(|_| DEFAULT_RPC_PATH.to_string()),
            host: env::var("HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT),
            node_pubkey: env::var("NODE_PUBKEY").expect("NODE_PUBKEY environment variable required"),
            node_address: env::var("NODE_ADDRESS")
                .expect("NODE_ADDRESS environment variable required"),
        }
    }

    /// Returns the node URI in format pubkey@host:port.
    fn node_uri(&self) -> String {
        format!("{}@{}", self.node_pubkey, self.node_address)
    }

    /// Returns the server bind address.
    fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Parameters for the open-channel endpoint.
#[derive(Debug, Deserialize)]
struct OpenChannelParams {
    /// Remote node's public key.
    remoteid: String,
    /// Authentication token.
    k1: String,
    /// Whether to open a private channel.
    #[serde(default)]
    private: Option<bool>,
}

/// Parameters for the withdraw endpoint.
#[derive(Debug, Deserialize)]
struct WithdrawParams {
    /// Authentication token.
    k1: String,
    /// BOLT11 invoice to pay.
    pr: String,
}

// ============================================================================
// API Response Types
// ============================================================================

/// Response for LNURL-channel initial request.
#[derive(Debug, Serialize)]
struct ChannelRequestResponse {
    uri: String,
    callback: String,
    k1: String,
    tag: &'static str,
}

/// Response for LNURL-withdraw initial request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawRequestResponse {
    callback: String,
    k1: String,
    tag: &'static str,
    default_description: String,
    min_withdrawable: u64,
    max_withdrawable: u64,
}

/// Response for channel open callback.
#[derive(Debug, Serialize)]
struct ChannelOpenResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_id: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mindepth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outnum: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx: Option<String>,
}

impl ChannelOpenResponse {
    fn success(txid: String, channel_id: Sha256, mindepth: Option<u32>, outnum: u32, tx: String) -> Self {
        Self {
            status: STATUS_OK.to_string(),
            reason: None,
            txid: Some(txid),
            channel_id: Some(channel_id),
            mindepth,
            outnum: Some(outnum),
            tx: Some(tx),
        }
    }

    fn error(reason: impl Into<String>) -> Self {
        Self {
            status: STATUS_ERROR.to_string(),
            reason: Some(reason.into()),
            txid: None,
            channel_id: None,
            mindepth: None,
            outnum: None,
            tx: None,
        }
    }
}

/// Response for withdraw callback.
#[derive(Debug, Serialize)]
struct WithdrawResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl WithdrawResponse {
    fn success() -> Self {
        Self {
            status: STATUS_OK.to_string(),
            reason: None,
        }
    }

    fn error(reason: impl Into<String>) -> Self {
        Self {
            status: STATUS_ERROR.to_string(),
            reason: Some(reason.into()),
        }
    }
}

// ============================================================================
// Route Handlers
// ============================================================================

/// Returns channel request metadata for LNURL-channel protocol.
async fn handle_channel_request() -> Json<ChannelRequestResponse> {
    // TODO: Generate secure random k1 token and store for validation
    let k1 = generate_k1_token();

    let response = ChannelRequestResponse {
        uri: Config::from_env().node_uri(),
        callback: "https://example.com/open-channel".to_string(),
        k1,
        tag: TAG_CHANNEL_REQUEST,
    };

    Json(response)
}

/// Returns withdrawal request metadata for LNURL-withdraw protocol.
async fn handle_withdraw_request() -> Json<WithdrawRequestResponse> {
    // TODO: Generate secure random k1 token and store for validation
    let k1 = generate_k1_token();

    let response = WithdrawRequestResponse {
        callback: "https://example.com/withdraw".to_string(),
        k1,
        tag: TAG_WITHDRAW_REQUEST,
        default_description: "Withdrawal from service".to_string(),
        min_withdrawable: MIN_WITHDRAWABLE_MSAT,
        max_withdrawable: MAX_WITHDRAWABLE_MSAT,
    };

    Json(response)
}

/// Opens a channel to the requesting node.
async fn handle_open_channel(
    State(client): State<AppState>,
    Query(params): Query<OpenChannelParams>,
) -> (StatusCode, Json<ChannelOpenResponse>) {
    // Validate k1 token
    // TODO: Implement proper k1 validation against stored tokens
    if !validate_k1_token(&params.k1) {
        warn!(k1 = %params.k1, "Invalid k1 token");
        return (StatusCode::BAD_REQUEST, Json(ChannelOpenResponse::error("Invalid k1")));
    }

    // Parse node ID
    let node_id = match params.remoteid.parse() {
        Ok(id) => id,
        Err(e) => {
            warn!(remoteid = %params.remoteid, error = %e, "Invalid node ID");
            return (
                StatusCode::BAD_REQUEST,
                Json(ChannelOpenResponse::error(format!("Invalid node ID: {e}"))),
            );
        }
    };

    // Build channel funding request
    let request = FundchannelRequest {
        id: node_id,
        amount: AmountOrAll::Amount(Amount::from_sat(DEFAULT_CHANNEL_AMOUNT_SAT)),
        announce: params.private,
        feerate: None,
        minconf: None,
        mindepth: None,
        utxos: None,
        push_msat: None,
        close_to: None,
        request_amt: None,
        compact_lease: None,
        reserve: None,
        channel_type: None,
    };

    // Execute channel funding
    let mut rpc = client.lock().await;
    match rpc.call(Request::FundChannel(request)).await {
        Ok(Response::FundChannel(response)) => {
            info!(
                channel_id = ?response.channel_id,
                txid = %response.txid,
                "Channel funded successfully"
            );
            (
                StatusCode::OK,
                Json(ChannelOpenResponse::success(
                    response.txid,
                    response.channel_id,
                    response.mindepth,
                    response.outnum,
                    response.tx,
                )),
            )
        }
        Ok(_) => {
            error!("Unexpected response type from fundchannel");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ChannelOpenResponse::error("Unexpected response type")),
            )
        }
        Err(e) => {
            error!(error = %e, "Channel funding failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ChannelOpenResponse::error(format!("Channel funding failed: {e}"))),
            )
        }
    }
}

/// Processes a withdrawal by paying the provided invoice.
async fn handle_withdraw(
    State(client): State<AppState>,
    Query(params): Query<WithdrawParams>,
) -> (StatusCode, Json<WithdrawResponse>) {
    // Validate k1 token
    // TODO: Implement proper k1 validation against stored tokens
    if !validate_k1_token(&params.k1) {
        warn!(k1 = %params.k1, "Invalid k1 token");
        return (StatusCode::BAD_REQUEST, Json(WithdrawResponse::error("Invalid k1")));
    }

    // Build payment request
    let request = PayRequest {
        bolt11: params.pr.clone(),
        amount_msat: None,
        label: None,
        riskfactor: None,
        maxfeepercent: None,
        retry_for: None,
        maxdelay: None,
        exemptfee: None,
        localinvreqid: None,
        exclude: None,
        maxfee: None,
        description: Some("LNURL withdraw".to_string()),
        partial_msat: None,
    };

    // Execute payment
    let mut rpc = client.lock().await;
    match rpc.call(Request::Pay(request)).await {
        Ok(Response::Pay(response)) => {
            info!(
                payment_hash = ?response.payment_hash,
                amount_msat = ?response.amount_msat,
                "Payment sent successfully"
            );
            (StatusCode::OK, Json(WithdrawResponse::success()))
        }
        Ok(_) => {
            error!("Unexpected response type from pay");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse::error("Unexpected response type")),
            )
        }
        Err(e) => {
            error!(error = %e, "Payment failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse::error(format!("Payment failed: {e}"))),
            )
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generates a k1 authentication token.
///
/// TODO: Replace with cryptographically secure random generation and store for validation.
fn generate_k1_token() -> String {
    // Placeholder - should use proper random generation
    "placeholder_k1_token".to_string()
}

/// Validates a k1 authentication token.
///
/// TODO: Implement proper validation against stored tokens.
fn validate_k1_token(k1: &str) -> bool {
    // Placeholder - should validate against stored tokens
    k1 == "placeholder_k1_token"
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::from_env();

    // Connect to CLN RPC
    let client = match ClnRpc::new(&config.rpc_path).await {
        Ok(c) => {
            info!(rpc_path = %config.rpc_path, "Connected to CLN RPC");
            c
        }
        Err(e) => {
            error!(error = %e, rpc_path = %config.rpc_path, "Failed to connect to CLN RPC");
            std::process::exit(1);
        }
    };

    let state: AppState = Arc::new(Mutex::new(client));

    // Build router
    let app = Router::new()
        .route("/channel-request", get(handle_channel_request))
        .route("/open-channel", get(handle_open_channel))
        .route("/withdraw-request", get(handle_withdraw_request))
        .route("/withdraw", get(handle_withdraw))
        .with_state(state);

    // Start server
    let bind_address = config.bind_address();
    info!(address = %bind_address, "Starting LNURL server");

    let listener = match tokio::net::TcpListener::bind(&bind_address).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, address = %bind_address, "Failed to bind to address");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "Server error");
        std::process::exit(1);
    }
}
