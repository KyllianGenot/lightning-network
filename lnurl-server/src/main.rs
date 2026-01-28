use axum::{
    routing::{get},
    http::StatusCode,
    Json, Router,
    extract::{Query, State},
};
use cln_rpc::{self, primitives::Sha256};
use cln_rpc::model::requests::{FundchannelRequest, PayRequest};
use cln_rpc::primitives::{Amount, AmountOrAll, Feerate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::sync::{Arc, OnceLock};
use std::collections::HashSet;
use tokio::sync::Mutex;
use secp256k1::{Secp256k1, Message, PublicKey};
use rand::RngCore;

type SharedClient = Arc<Mutex<cln_rpc::ClnRpc>>;
type SharedK1Store = Arc<Mutex<HashSet<String>>>;

#[derive(Clone)]
struct AppState {
    client: SharedClient,
    k1_store: SharedK1Store,
}

const REQUESTCHANNELTAG: &str = "channelRequest";
const WITHDRAWCHANNELTAG: &str = "withdrawRequest";
const LOGINTAG: &str = "login";
const DEFAULT_DESCRIPTION: &str = "Withdrawal from service";
const IP_ADDRESS: &str = "137.74.119.232:49735";
const CALLBACK_URL: &str = "http://137.74.119.232:3000/";

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
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<u16>,
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

    // Single lock acquisition for the entire CLN interaction
    let mut client_guard = state.client.lock().await;
    
    let request = FundchannelRequest {
        id: node_id,
        amount,
        announce: announce,
        feerate: Some(Feerate::Urgent),
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

    // Use the same client_guard - no duplicate lock acquisition
    match client_guard.call(cln_rpc::Request::FundChannel(request)).await {
        Ok(cln_rpc::Response::FundChannel(response)) => {
            (
                StatusCode::OK,
                Json(OpenChannelResponse {
                    status: "OK".to_string(),
                    reason: None,
                    mindepth: response.mindepth,
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

#[derive(Debug, Serialize)]
struct LoginResponse {
    tag: &'static str,
    k1: String,
}

async fn login(
    State(state): State<AppState>,
) -> (StatusCode, Json<LoginResponse>) {
    println!("Login request received");
    
    // Generate 32 random bytes for k1
    let mut k1_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k1_bytes);
    let k1 = hex::encode(k1_bytes);
    
    // Store k1 in HashSet
    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }
    
    let response = LoginResponse {
        tag: LOGINTAG,
        k1,
    };

    println!("Login response: {:?}", response);

    (StatusCode::OK, Json(response))
}

#[derive(Debug, Deserialize)]
struct VerifyAuthParams {
    k1: String,
    sig: String,
    key: String,
}

#[derive(Serialize, Default)]
struct VerifyAuthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

async fn verify_auth(
    State(state): State<AppState>,
    Query(params): Query<VerifyAuthParams>,
) -> (StatusCode, Json<VerifyAuthResponse>) {
    println!("Verify auth request received");
    println!("Params: {:?}", params);
    
    // Check if k1 exists in HashSet
    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    
    if !k1_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(VerifyAuthResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
            }),
        );
    }

    // Decode k1 from hex
    let k1_bytes = match hex::decode(&params.k1) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyAuthResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid k1 hex: {}", e)),
                }),
            );
        }
    };

    // Decode public key from hex
    let pubkey = match hex::decode(&params.key) {
        Ok(bytes) => {
            match PublicKey::from_slice(&bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(VerifyAuthResponse {
                            status: "ERROR".to_string(),
                            reason: Some(format!("Invalid public key: {}", e)),
                        }),
                    );
                }
            }
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyAuthResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid key hex: {}", e)),
                }),
            );
        }
    };

    // Decode signature from hex (DER encoded)
    let signature = match hex::decode(&params.sig) {
        Ok(bytes) => {
            match secp256k1::ecdsa::Signature::from_der(&bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(VerifyAuthResponse {
                            status: "ERROR".to_string(),
                            reason: Some(format!("Invalid signature: {}", e)),
                        }),
                    );
                }
            }
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyAuthResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid sig hex: {}", e)),
                }),
            );
        }
    };

    // Create message from k1 bytes
    if k1_bytes.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(VerifyAuthResponse {
                status: "ERROR".to_string(),
                reason: Some("k1 must be exactly 32 bytes".to_string()),
            }),
        );
    }
    let message = match Message::from_slice(&k1_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyAuthResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid message: {}", e)),
                }),
            );
        }
    };

    // Verify signature
    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&message, &signature, &pubkey) {
        Ok(_) => {
            // Remove k1 from store after successful auth
            {
                let mut k1_store = state.k1_store.lock().await;
                k1_store.remove(&params.k1);
            }
            println!("Auth successful for key: {}", params.key);
            (
                StatusCode::OK,
                Json(VerifyAuthResponse {
                    status: "OK".to_string(),
                    reason: None,
                }),
            )
        }
        Err(e) => {
            (
                StatusCode::BAD_REQUEST,
                Json(VerifyAuthResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Signature verification failed: {}", e)),
                }),
            )
        }
    }
}

#[tokio::main]
async fn main() {
    let client = match cln_rpc::ClnRpc::new("/home/ubuntu/.lightning/testnet4/lightning-rpc").await {
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
        .route("/login", get(login))
        .route("/verify-auth", get(verify_auth))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
