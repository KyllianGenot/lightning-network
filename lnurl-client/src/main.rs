use serde::Deserialize;
use cln_rpc::ClnRpc;
use url::Url;
use anyhow::{Context, Result, anyhow};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use secp256k1::PublicKey;

const CLN_RPC_PATH: &str = "/Users/kyllian/.lightning/testnet4/testnet4/lightning-rpc";

#[derive(Debug)]
enum Commands {
    RequestChannel {
        url: Url,
    },
    RequestWithdraw {
        url: Url,
        amount: u32,
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  lnurl-client request-channel <url|ip> ");
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
            format!("{}@{}", pubkey, "127.0.0.1:49735")
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
    let port = host.split(':').collect::<Vec<&str>>()[1];
    let ip_addr: Ipv4Addr = host.split(':').collect::<Vec<&str>>()[0].parse()?;

    println!("Connecting to node {}@{}:{}...", pubkey, ip_addr, port);
    let request = cln_rpc::model::requests::ConnectRequest{
        id: pubkey.to_string(),
        host: Some(ip_addr.to_string()),
        port: port.parse::<u16>().ok(),
    };

    let _response = rt.block_on(ln_client.call(cln_rpc::Request::Connect(request)))?;

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
    let open_url = format!(
        "{}?remoteid={}&k1={}",
        resp.callback,
        node_uri,
        resp.k1
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
    unimplemented!()
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
        _ => unreachable!()
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
