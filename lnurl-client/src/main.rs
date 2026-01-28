use serde::Deserialize;
use cln_rpc::ClnRpc;
use url::Url;
use anyhow::{Context, Result, anyhow};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Message};

const CLN_RPC_PATH: &str = "/Users/kyllian/.lightning/testnet4/lightning-rpc";

#[derive(Debug)]
enum Commands {
    RequestChannel {
        url: Url,
    },
    RequestWithdraw {
        url: Url,
        amount: u32,
    },
    RequestAuth {
        url: Url,
    },
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  lnurl-client request-channel <url|ip>");
    eprintln!("  lnurl-client request-withdraw <url|ip> <amount_msat>");
    eprintln!("  lnurl-client request-auth <url|ip>");
}

fn parse_url_or_ip(input: &str) -> Result<Url> {
    // First try parsing as a URL
    if let Ok(url) = Url::parse(input) {
        return Ok(url);
    }
    
    // Handle IPv6 with port in brackets format: [::1]:8080
    if let Some(bracket_end) = input.find("]:") {
        if input.starts_with('[') {
            let ip_part = &input[1..bracket_end];
            let port_part = &input[bracket_end + 2..];
            if port_part.parse::<u16>().is_ok() {
                if let Ok(ip) = IpAddr::from_str(ip_part) {
                    let url_str = format!("http://[{}]:{}", ip, port_part);
                    return Url::parse(&url_str)
                        .context("Failed to convert IP address with port to URL");
                }
            }
        }
    }
    
    // Try parsing as IP address with port: 192.168.1.1:8080 or ::1:8080
    if let Some(colon_pos) = input.rfind(':') {
        let ip_part = &input[..colon_pos];
        let port_part = &input[colon_pos + 1..];
        
        if port_part.parse::<u16>().is_ok() {
            if let Ok(ip) = IpAddr::from_str(ip_part) {
                let url_str = format!("http://{}:{}", ip, port_part);
                return Url::parse(&url_str)
                    .context("Failed to convert IP address with port to URL");
            }
        }
    }
    
    // Try parsing as plain IP address (no port) - IpAddr::from_str handles both IPv4 and IPv6
    if let Ok(ip) = IpAddr::from_str(input) {
        let url_str = format!("http://{}", ip);
        return Url::parse(&url_str)
            .context("Failed to convert IP address to URL");
    }
    
    Err(anyhow!("Invalid URL or IP address: {}", input))
}

fn parse_args() -> Result<Commands> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Err(anyhow!("No command provided"));
    }

    let command_name = args[1].as_str();
    
    match command_name {
        "request-channel" => {
            if args.len() < 3 {
                return Err(anyhow!("request-channel requires a <url> argument"));
            } else if args.len() > 3 {
                return Err(anyhow!("request-channel does not accept additional arguments"));
            }
            
            let url = parse_url_or_ip(&args[2])?;

            Ok(Commands::RequestChannel {
                url,
            })
        } 
        "request-withdraw" => {
            if args.len() < 4 {
                return Err(anyhow!("request-withdraw requires a <url> and <amount> arguments"));
            } else if args.len() > 4 {
                return Err(anyhow!("request-withdraw does not accept additional arguments"));
            }
            
            let url = parse_url_or_ip(&args[2])?;
            let amount: u32 = args[3].trim().parse()?;

            Ok(Commands::RequestWithdraw {
                url,
                amount,
            })
        },
        "request-auth" => {
            if args.len() < 3 {
                return Err(anyhow!("request-auth requires a <url> argument"));
            } else if args.len() > 3 {
                return Err(anyhow!("request-auth does not accept additional arguments"));
            }
            
            let url = parse_url_or_ip(&args[2])?;

            Ok(Commands::RequestAuth {
                url,
            })
        },
        _ => {
            print_usage();
            Err(anyhow!("Unknown command: {}", command_name))
        }
    }
}

fn get_node_uri(ln_client: &mut ClnRpc, rt: &tokio::runtime::Runtime) -> Result<String> {
    let node_info = rt.block_on(ln_client.call(cln_rpc::Request::Getinfo(cln_rpc::model::requests::GetinfoRequest{})));
    let node_uri = match node_info {
        Ok(cln_rpc::model::Response::Getinfo(response)) => {
            let pubkey = response.id.to_string();
            println!("Node pubkey initialized: {}", pubkey);
            format!("{}@{}", pubkey, "137.74.119.232:49735")
        }
        Err(e) => {
            return Err(anyhow!("Failed to get node info: {}", e));
        }
        _ => {
            return Err(anyhow!("Unexpected response type"));
        }
    };

    Ok(node_uri)
}

fn connect_to_node(ln_client: &mut ClnRpc, rt: &tokio::runtime::Runtime, node_uri: &str) -> Result<()> {
    let parsed = node_uri.split('@').collect::<Vec<&str>>();
    if parsed.len() != 2 {
        return Err(anyhow!("Invalid node URI: {}", node_uri));
    }
    let pubkey = PublicKey::from_str(parsed[0])?;
    let host = parsed[1];
    let port_str = host.split(':').collect::<Vec<&str>>()[1];
    let ip_str = host.split(':').collect::<Vec<&str>>()[0];
    
    let ip_addr: Ipv4Addr = ip_str.parse()?;
    let port = port_str.parse::<u16>().ok();

    println!("Connecting to node {}@{}:{}...", pubkey, ip_addr, port.unwrap_or(9735));
    let request = cln_rpc::model::requests::ConnectRequest{
        id: pubkey.to_string(),
        host: Some(ip_addr.to_string()),
        port: port,
    };

    match rt.block_on(ln_client.call(cln_rpc::Request::Connect(request))) {
        Ok(_) => println!("Connected to peer successfully."),
        Err(e) => println!("Note: Connection step skipped (likely connecting to self): {}", e),
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ChannelRequestResponse {
    uri: String,
    callback: String,
    k1: String,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct ChannelOpenResponse {
    status: String,
    reason: Option<String>,
    txid: Option<String>,
    channel_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawRequestResponse {
    callback: String,
    k1: String,
    tag: String,
    default_description: String,
    min_withdrawable: u64,
    max_withdrawable: u64,
}

#[derive(Debug, Deserialize)]
struct WithdrawResponse {
    status: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    tag: String,
    k1: String,
}

#[derive(Debug, Deserialize)]
struct VerifyAuthResponse {
    status: String,
    reason: Option<String>,
}

fn channel_request(url: &Url) -> Result<()> {
    println!("Requesting channel info from {}...", url);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("Failed to create Tokio runtime")?;
    let mut ln_client = rt.block_on(cln_rpc::ClnRpc::new(CLN_RPC_PATH))?;

    let mut node_uri = get_node_uri(&mut ln_client, &rt)?;

    println!("Node URI: {}", node_uri);

    let request_url = format!("{}/request-channel", url.as_str().trim_end_matches('/'));
    let resp: ChannelRequestResponse = ureq::get(&request_url).call()?.into_json()?;
    
    println!("Received channel request:");
    println!("  URI: {}", resp.uri);
    println!("  Callback: {}", resp.callback);
    println!("  k1: {}", resp.k1);

    connect_to_node(&mut ln_client, &rt, &resp.uri)?;

    println!("Requesting channel open...");
    
    let _ = node_uri.split_off(secp256k1::constants::PUBLIC_KEY_SIZE * 2); // it will panic if the string is less than 33 bytes long
    
    let (our_ip, our_port) = ("169.155.254.176", 49735);
    
    let open_url = format!(
        "{}?remoteid={}&k1={}&ip={}&port={}",
        resp.callback,
        node_uri,
        resp.k1,
        our_ip,
        our_port
    );
    println!("Open URL: {}", open_url);
    
    let open_resp = match ureq::get(&open_url).call() {
        Ok(resp) => resp.into_json::<ChannelOpenResponse>()?,
        Err(e) => {
            return Err(anyhow!("Failed to open channel: {}", e));
        }
    };
    println!("Open response: {:?}", open_resp);
     
    println!("Channel opened successfully!");
    if let Some(txid) = open_resp.txid {
        println!("  Transaction ID: {}", txid);
    }
    if let Some(channel_id) = open_resp.channel_id {
        println!("  Channel ID: {}", channel_id);
    }

    Ok(())
}

fn withdraw_request(url: &Url, amount: u32) -> Result<()> {
    println!("Requesting withdraw info from {}...", url);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("Failed to create Tokio runtime")?;
    let mut ln_client = rt.block_on(cln_rpc::ClnRpc::new(CLN_RPC_PATH))?;

    let request_url = format!("{}/request-withdraw", url.as_str().trim_end_matches('/'));
    let resp: WithdrawRequestResponse = ureq::get(&request_url).call()?.into_json()?;

    println!("Received withdraw request:");
    println!("  Callback: {}", resp.callback);
    println!("  k1: {}", resp.k1);
    println!("  Min withdrawable: {} msat", resp.min_withdrawable);
    println!("  Max withdrawable: {} msat", resp.max_withdrawable);

    let amount_msat = amount as u64;
    if amount_msat < resp.min_withdrawable {
        return Err(anyhow!("Amount {} msat is below minimum {} msat", amount_msat, resp.min_withdrawable));
    }
    if amount_msat > resp.max_withdrawable {
        return Err(anyhow!("Amount {} msat exceeds maximum {} msat", amount_msat, resp.max_withdrawable));
    }

    println!("Creating invoice for {} msat...", amount_msat);

    let invoice_request = cln_rpc::model::requests::InvoiceRequest {
        amount_msat: cln_rpc::primitives::AmountOrAny::Amount(cln_rpc::primitives::Amount::from_msat(amount_msat)),
        label: format!("lnurl-withdraw-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
        description: resp.default_description.clone(),
        expiry: None,
        fallbacks: None,
        preimage: None,
        cltv: None,
        deschashonly: None,
        exposeprivatechannels: None,
    };

    let invoice_response = rt.block_on(ln_client.call(cln_rpc::Request::Invoice(invoice_request)));
    let bolt11 = match invoice_response {
        Ok(cln_rpc::model::Response::Invoice(response)) => {
            println!("Invoice created: {}", response.bolt11);
            response.bolt11
        }
        Err(e) => {
            return Err(anyhow!("Failed to create invoice: {}", e));
        }
        _ => {
            return Err(anyhow!("Unexpected response type"));
        }
    };

    println!("Requesting withdrawal...");

    let withdraw_url = format!(
        "{}?k1={}&pr={}",
        resp.callback,
        resp.k1,
        bolt11
    );
    println!("Withdraw URL: {}", withdraw_url);

    let withdraw_resp = match ureq::get(&withdraw_url).call() {
        Ok(resp) => resp.into_json::<WithdrawResponse>()?,
        Err(e) => {
            return Err(anyhow!("Failed to withdraw: {}", e));
        }
    };
    println!("Withdraw response: {:?}", withdraw_resp);

    if withdraw_resp.status == "OK" {
        println!("Withdrawal successful!");
    } else {
        if let Some(reason) = withdraw_resp.reason {
            return Err(anyhow!("Withdrawal failed: {}", reason));
        }
        return Err(anyhow!("Withdrawal failed"));
    }

    Ok(())
}

fn auth_request(url: &Url) -> Result<()> {
    println!("Requesting auth info from {}...", url);

    let request_url = format!("{}/login", url.as_str().trim_end_matches('/'));
    let resp: LoginResponse = ureq::get(&request_url).call()?.into_json()?;

    println!("Received login challenge:");
    println!("  Tag: {}", resp.tag);
    println!("  k1: {}", resp.k1);

    // Decode k1 from hex
    let k1_bytes = hex::decode(&resp.k1)
        .context("Failed to decode k1 hex")?;
    
    if k1_bytes.len() != 32 {
        return Err(anyhow!("Invalid k1 length: expected 32 bytes, got {}", k1_bytes.len()));
    }

    // Generate a linking key (in production, this would be derived from seed)
    // For simplicity, we use a deterministic key based on the domain
    let secp = Secp256k1::new();
    
    // Create a simple deterministic secret key for demo purposes
    // In real implementation, this would be derived from wallet seed + domain
    let mut seed = [0u8; 32];
    let domain_bytes = url.host_str().unwrap_or("localhost").as_bytes();
    for (i, byte) in domain_bytes.iter().enumerate() {
        seed[i % 32] ^= byte;
    }
    // Make sure the seed is valid for secp256k1
    seed[0] = seed[0].saturating_add(1);
    
    let secret_key = SecretKey::from_slice(&seed)
        .context("Failed to create secret key")?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    println!("Using linking key: {}", hex::encode(public_key.serialize()));

    // Create message from k1 bytes and sign it
    let k1_array: [u8; 32] = k1_bytes.try_into()
        .map_err(|_| anyhow!("k1 must be exactly 32 bytes"))?;
    let message = Message::from_slice(&k1_array)
        .context("Failed to create message from k1")?;
    
    let signature = secp.sign_ecdsa(&message, &secret_key);
    let sig_der = signature.serialize_der();

    println!("Signature created: {}", hex::encode(&sig_der));

    // Send verification request
    let verify_url = format!(
        "{}/verify-auth?k1={}&sig={}&key={}",
        url.as_str().trim_end_matches('/'),
        resp.k1,
        hex::encode(&sig_der),
        hex::encode(public_key.serialize())
    );
    println!("Verify URL: {}", verify_url);

    let verify_resp = match ureq::get(&verify_url).call() {
        Ok(resp) => resp.into_json::<VerifyAuthResponse>()?,
        Err(e) => {
            return Err(anyhow!("Failed to verify auth: {}", e));
        }
    };
    println!("Verify response: {:?}", verify_resp);

    if verify_resp.status == "OK" {
        println!("Authentication successful!");
    } else {
        if let Some(reason) = verify_resp.reason {
            return Err(anyhow!("Authentication failed: {}", reason));
        }
        return Err(anyhow!("Authentication failed"));
    }

    Ok(())
}

fn main() {
    let command = match parse_args() {
        Ok(command) => command,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
 

    let result = match command {
        Commands::RequestChannel { url } => {
            channel_request(&url)
        }
        Commands::RequestWithdraw { url, amount } => {
            withdraw_request(&url, amount)
        }
        Commands::RequestAuth { url } => {
            auth_request(&url)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
