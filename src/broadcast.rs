//! Optional on-chain anchoring of the attestation digest via a Bitcoin
//! `OP_RETURN` output. Shells out to `bitcoin-cli` — same philosophy as the TPM
//! wrapper: use the reference client, produce genuine artifacts.
//!
//! Network-agnostic via `ASC_BTC_NETWORK`:
//!   - `regtest` (default): self-contained, mines its own block to confirm.
//!   - `testnet` / `signet`: public and third-party verifiable; needs a wallet
//!     funded from a faucet.
//!   - `mainnet`: real money.
//!
//! Other env knobs: `ASC_BTC_DATADIR`, `ASC_BTC_WALLET`, `ASC_BTC_CLI`.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::process::Command;

pub struct Btc {
    network: String,
    datadir: Option<String>,
    wallet: Option<String>,
    cli: String,
}

impl Btc {
    pub fn from_env() -> Self {
        Btc {
            network: std::env::var("ASC_BTC_NETWORK").unwrap_or_else(|_| "regtest".into()),
            datadir: std::env::var("ASC_BTC_DATADIR").ok(),
            wallet: std::env::var("ASC_BTC_WALLET").ok(),
            cli: std::env::var("ASC_BTC_CLI").unwrap_or_else(|_| "bitcoin-cli".into()),
        }
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    fn base_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        match self.network.as_str() {
            "mainnet" | "main" => {}
            other => a.push(format!("-{other}")), // -regtest / -testnet / -signet
        }
        if let Some(dd) = &self.datadir {
            a.push(format!("-datadir={dd}"));
        }
        if let Some(w) = &self.wallet {
            a.push(format!("-rpcwallet={w}"));
        }
        a
    }

    fn call(&self, extra: &[&str]) -> Result<String> {
        let mut args = self.base_args();
        args.extend(extra.iter().map(|s| s.to_string()));
        let out = Command::new(&self.cli)
            .args(&args)
            .output()
            .with_context(|| format!("failed to spawn `{}` (is Bitcoin Core installed?)", self.cli))?;
        if !out.status.success() {
            bail!(
                "bitcoin-cli {:?} failed:\n{}",
                extra,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Run a call whose JSON result carries a `hex` field (fund/sign).
    fn call_hex(&self, extra: &[&str]) -> Result<String> {
        let out = self.call(extra)?;
        let v: Value = serde_json::from_str(&out).context("parse bitcoin-cli JSON")?;
        Ok(v["hex"].as_str().context("bitcoin-cli JSON missing `hex`")?.to_string())
    }

    /// Build → fund → sign → broadcast an `OP_RETURN` carrying `digest_hex`.
    /// Returns the real txid. On regtest, mines one block so the anchor confirms.
    pub fn anchor_op_return(&self, digest_hex: &str) -> Result<String> {
        let outs = format!("[{{\"data\":\"{digest_hex}\"}}]");
        let raw = self.call(&["createrawtransaction", "[]", &outs])?;
        let funded = self.call_hex(&["-named", "fundrawtransaction", &format!("hexstring={raw}")])?;
        let signed =
            self.call_hex(&["-named", "signrawtransactionwithwallet", &format!("hexstring={funded}")])?;
        let txid = self.call(&["sendrawtransaction", &signed])?;
        if self.network == "regtest" {
            if let Ok(addr) = self.call(&["getnewaddress"]) {
                let _ = self.call(&["generatetoaddress", "1", &addr]);
            }
        }
        Ok(txid)
    }
}
