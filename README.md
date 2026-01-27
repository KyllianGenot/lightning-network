# LNURL Server & Client

A Rust implementation for LNURL (Channel, Withdraw, Auth) on Bitcoin Testnet4.

* **Server URL:** `http://137.74.119.232:3000`
* **Node URI:** `0291130cecc90ab7c3d0943490136c548e73578fc311a3431cc9534ab8394ed275@137.74.119.232:49735`

## 1. Configuration

The configuration is hardcoded in the source files for simplicity.

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

Request a channel from an external server (e.g., Professor's Node) to prove the client works.

```bash
cargo run -- request-channel http://82.67.177.113:3001

```

### B. Self-Test (My Server)

Request a channel from my own server.
*Note: The final connection step will skip because the node cannot connect to itself, proving the handshake works.*

```bash
cargo run -- request-channel http://137.74.119.232:3000

```

### C. Withdraw Test

Request a 1 sat (1000 msat) payment from my server.

```bash
cargo run -- request-withdraw http://137.74.119.232:3000 1000

```

### D. Auth Test

Perform an LNURL-Auth (LUD-04) cryptographic login.

```bash
cargo run -- request-auth http://137.74.119.232:3000

```