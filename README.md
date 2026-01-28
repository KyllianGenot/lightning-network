# LNURL Server & Client

A Rust implementation for LNURL (Channel, Withdraw, Auth) on Bitcoin Testnet4.

* **Server URL:** `http://137.74.119.232:3000`
* **Node URI:** `0291130cecc90ab7c3d0943490136c548e73578fc311a3431cc9534ab8394ed275@137.74.119.232:49735`

## 1. Configuration

The configuration is hardcoded in the source files. Update with your own informations.

* **Server Config (`lnurl-server/src/main.rs`):**
* IP Address: `137.74.119.232:49735`
* Callback URL: `http://137.74.119.232:3000/`
* CLN RPC Path: `/home/ubuntu/.lightning/testnet4/lightning-rpc`

* **Client Config (`lnurl-client/src/main.rs`):**
* Public IP: `137.74.119.232`
* CLN RPC Path: `/home/ubuntu/.lightning/testnet4/lightning-rpc`

---

## 2. Starting the Server

The server is already configured to run as a system service.

```bash
# Check status and view logs
sudo systemctl status lnurl-server
sudo journalctl -u lnurl-server -f

# Manual start (alternative)
cd lnurl-server
cargo run --release

```

---

## 3. Running Tests (Client)

To verify the functionalities, run these commands from the `lnurl-client` directory.

```bash
cd lnurl-client

```

### A. Interoperability Test

Request a channel from my server.

```bash
cargo run -- request-channel http://137.74.119.232:3000

```

### B. Withdraw Test

Request a 1 sat (1000 msat) payment from my server.

```bash
cargo run -- request-withdraw http://137.74.119.232:3000 1000

```

### C. Auth Test

Perform an LNURL-Auth (LUD-04) cryptographic login.

```bash
cargo run -- request-auth http://137.74.119.232:3000

```