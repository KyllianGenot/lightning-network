use axum::{
    routing::{get},
    http::StatusCode,
    Json, Router,
    extract::{Query, State},
};
use cln_rpc::{self, primitives::Sha256};
use cln_rpc::model::requests::{FundchannelRequest, PayRequest};
use cln_rpc::primitives::{Amount, AmountOrAll};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::sync::{Arc, OnceLock};
use std::collections::HashSet;
use tokio::sync::Mutex;

type SharedClient = Arc<Mutex<cln_rpc::ClnRpc>>;
type SharedK1Store = Arc<Mutex<HashSet<String>>>;

#[derive(Clone)]
struct AppState {
    client: SharedClient,
    k1_store: SharedK1Store,
}

const REQUESTCHANNELTAG: &str = "channelRequest";
const WITHDRAWCHANNELTAG: &str = "withdrawRequest";
const DEFAULT_DESCRIPTION: &str = "Withdrawal from service";
const IP_ADDRESS: &str = "192.168.27.70:49735";
const CALLBACK_URL: &str = "http://192.168.27.70:3000/";

static NODE_URI: OnceLock<String> = OnceLock::new();

#[derive(Debug, Serialize)]
struct RequestChannelResponse {
    uri: &'static str,       
    callback: String,  
    k1: String,        
    tag: &'static str,
}

async fn request_channel(
    State(state): State<AppState>,
) -> (StatusCode, Json<RequestChannelResponse>) {
    println!("Request channel received");
    let k1 = Uuid::new_v4().to_string();
    
    // Store k1 in HashSet
    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }
    
    let response = RequestChannelResponse {
        uri: NODE_URI.get().expect("NODE_URI should be set at this point"),
        callback: format!("{}{}", CALLBACK_URL, "open-channel"), 
        k1,
        tag: REQUESTCHANNELTAG,
    };

    println!("Request channel response: {:?}", response);

    (StatusCode::OK, Json(response))
}

#[derive(Debug, Deserialize)]
struct OpenChannelParams {
    remoteid: String,
    k1: String,
    #[serde(default)]
    private: Option<bool>,
}

#[derive(Serialize, Default)]
struct OpenChannelResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mindepth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_id: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outnum: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
}

async fn open_channel(
    State(state): State<AppState>,
    Query(params): Query<OpenChannelParams>,
) -> (StatusCode, Json<OpenChannelResponse>) {
    println!("Open channel request received");
    println!("Params: {:?}", params);
    // Check if k1 exists in HashSet
    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    
    if !k1_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenChannelResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
                ..Default::default()
            }),
        );
    }

    let node_id = match params.remoteid.parse() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid node id: {}", e)),
                    ..Default::default()
                }),
            );
        }
    };

    let amount = AmountOrAll::Amount(Amount::from_sat(100_000));
    let announce = params.private;
    
    let request = FundchannelRequest {
        id: node_id,
        amount,
        announce: announce,
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

    
    let mut client_guard = state.client.lock().await;
    match client_guard.call(cln_rpc::Request::FundChannel(request)).await {
        Ok(cln_rpc::Response::FundChannel(response)) => {
            (
                StatusCode::OK,
                Json(OpenChannelResponse {
                    status: "OK".to_string(),
                    reason: None,
                    mindepth: Some(response.mindepth.unwrap()),
                    channel_id: Some(response.channel_id),
                    outnum: Some(response.outnum),
                    tx: Some(response.tx),
                    txid: Some(response.txid),
                }),
            )
        }
        Ok(_) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some("Unexpected response type".to_string()),
                    ..Default::default()
                }),
            )
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Failed to open channel: {}", e)),
                    ..Default::default()
                }),
            )
        }
    }
}

#[derive(Debug, Serialize)]
struct RequestWithdrawResponse {
    callback: String,
    k1: String,
    tag: &'static str,
    defaultDescription: &'static str,
    minWithdrawable: u64,
    maxWithdrawable: u64,
}

async fn request_withdraw(
    State(state): State<AppState>,
) -> (StatusCode, Json<RequestWithdrawResponse>) {
    let k1 = Uuid::new_v4().to_string();
    
    // Store k1 in HashSet
    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }
    
    let crr = RequestWithdrawResponse {
        callback: format!("{}{}", CALLBACK_URL, "withdraw"),
        k1,
        tag: WITHDRAWCHANNELTAG,
        defaultDescription: DEFAULT_DESCRIPTION,
        minWithdrawable: 1000,  // 1 sat in millisats
        maxWithdrawable: 1000000,  // 1000 sats in millisats
    };

    (StatusCode::OK, Json(crr))
}


#[derive(Debug, Deserialize)]
struct WithdrawParams {
    k1: String,
    pr: String,  // BOLT11 invoice
}

#[derive(Serialize, Default)]
struct WithdrawResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

async fn withdraw(
    State(state): State<AppState>,
    Query(params): Query<WithdrawParams>,
) -> (StatusCode, Json<WithdrawResponse>) {
    println!("Withdraw request received");
    println!("Params: {:?}", params);
    // Check if k1 exists in HashSet
    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    
    if !k1_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
            }),
        );
    }

    let request = PayRequest {
        bolt11: params.pr,
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
        description: None,
        partial_msat: None,
    };

    let mut client_guard = state.client.lock().await;
    match client_guard.call(cln_rpc::Request::Pay(request)).await {
        Ok(cln_rpc::Response::Pay(response)) => {
            println!("Payment successful: {:?}", response.payment_hash);
            (
                StatusCode::OK,
                Json(WithdrawResponse {
                    status: "OK".to_string(),
                    reason: None,
                }),
            )
        }
        Ok(_) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse {
                    status: "ERROR".to_string(),
                    reason: Some("Unexpected response type".to_string()),
                }),
            )
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Failed to pay invoice: {}", e)),
                }),
            )
        }
    }
}

#[tokio::main]
async fn main() {
    let client = match cln_rpc::ClnRpc::new("/Users/kyllian/.lightning/testnet4/testnet4/lightning-rpc").await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to cln rpc: {}", e);
            return;
        }
    };


    let shared_client = Arc::new(Mutex::new(client));
    let k1_store = Arc::new(Mutex::new(HashSet::new()));
    
    let app_state = AppState {
        client: shared_client.clone(),
        k1_store: k1_store.clone(),
    };

    // Get the pubkey from the node, which also allows us to validate the client
    let node_info = shared_client.lock().await.call(cln_rpc::Request::Getinfo(cln_rpc::model::requests::GetinfoRequest{})).await;
    match node_info {
        Ok(cln_rpc::model::Response::Getinfo(response)) => {
            let pubkey = response.id.to_string();
            NODE_URI.set(format!("{}@{}", pubkey, IP_ADDRESS)).expect("Failed to set NODE_URI");
            println!("Node pubkey initialized: {}", pubkey);
        }
        Err(e) => {
            eprintln!("Failed to get node info: {}", e);
            eprintln!("PUB_KEY will not be initialized - server may fail");
            return;
        }
        _ => {
            eprintln!("Unexpected response type");
            eprintln!("PUB_KEY will not be initialized - server may fail");
            return;
        }
    }

    let app = Router::new()
        .route("/request-channel", get(request_channel))
        .route("/open-channel", get(open_channel))
        .route("/request-withdraw", get(request_withdraw))
        .route("/withdraw", get(withdraw))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
