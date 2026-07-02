//! The Attested Signing Ceremony (§6.8.1).
//!
//!   Step 1  measured signing   — extend PCR23 with the REAL payload, then
//!                                 quote the environment (boot PCRs 0..7) plus
//!                                 that payload PCR under the hardware AK.
//!   Step 2  atomic binding      — commit the attestation digest to the SCITT
//!                                 log and embed it in a Bitcoin OP_RETURN.
//!   Step 3  independent verify   — anyone re-runs tpm2_checkquote + recomputes
//!                                 the expected PCR23 and the attestation digest.
//!
//! The security claim it demonstrates: whatever a compromised UI *displayed*,
//! the attestation records the payload that was *actually* signed — so the
//! malicious instruction becomes forensically irrefutable. That is exactly the
//! evidence that was missing in Bybit, Radiant Capital and WazirX.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::opreturn;
use crate::scitt::ScittLog;
use crate::tpm::{parse_pcr_value, Tpm};

/// PCRs quoted every ceremony: 0..7 capture the boot/firmware/kernel
/// environment; 23 carries the measured payload.
const PCR_LIST: &str = "sha256:0,1,2,3,4,5,6,7,23";
const PAYLOAD_PCR: u32 = 23;
const ZERO_PCR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub version: u32,
    pub timestamp: String,
    /// What the operator interface claimed the user was authorising.
    pub displayed_payload_sha256: String,
    /// What was actually bound into the attestation and signed. In an honest
    /// ceremony these two are equal; under a presentation-layer attack they
    /// diverge — and this field wins.
    pub signed_payload_sha256: String,
    pub pcr_selection: String,
    pub attested_pcr23: String,
    pub nonce_hex: String,
    pub attestation_digest: String,
    pub opreturn_scriptpubkey_hex: String,
    pub scitt_seq: u64,
    pub scitt_entry_hash: String,
    pub ak_pem: String,
    pub quote_msg: String,
    pub quote_sig: String,
    pub quote_pcrs: String,
}

pub struct Ceremony {
    tpm: Tpm,
    workdir: PathBuf,
}

impl Ceremony {
    pub fn new(workdir: impl Into<PathBuf>) -> Result<Self> {
        let workdir = workdir.into();
        fs::create_dir_all(&workdir)
            .with_context(|| format!("create workdir {}", workdir.display()))?;
        Ok(Ceremony { tpm: Tpm::new(workdir.clone()), workdir })
    }

    pub fn setup(&self) -> Result<()> {
        self.tpm.ensure_ak()?;
        Ok(())
    }

    fn scitt(&self) -> ScittLog {
        ScittLog::open(self.workdir.join("scitt-log.jsonl"))
    }

    /// Run one ceremony binding `signed` (the real instruction). `displayed` is
    /// recorded only to model the UI-vs-payload gap; the attestation is over
    /// `signed`.
    pub fn run(&self, displayed: &[u8], signed: &[u8]) -> Result<Receipt> {
        let ak = self.tpm.ensure_ak()?;

        let displayed_hash = sha256_hex(displayed);
        let signed_hash = sha256_hex(signed);

        // Step 1: measured signing. Clean the application PCR, then bind the
        // real payload into it.
        self.tpm.pcr_reset(PAYLOAD_PCR)?;
        self.tpm.pcr_extend_sha256(PAYLOAD_PCR, &signed_hash)?;
        let attested_pcr23 = self.tpm.pcr_read_sha256(PAYLOAD_PCR)?;

        // Fresh nonce guarantees quote freshness (anti-replay).
        let nonce_hex = random_hex(20)?;
        let quote = self.tpm.quote(&ak.ctx, PCR_LIST, &nonce_hex)?;

        // Attestation digest = SHA256(quote message || signature || AK pubkey).
        // This single 32-byte value is what we anchor and log.
        let msg_bytes = fs::read(&quote.msg)?;
        let sig_bytes = fs::read(&quote.sig)?;
        let ak_pem_bytes = fs::read(&ak.pem)?;
        let attestation_digest = {
            let mut h = Sha256::new();
            h.update(&msg_bytes);
            h.update(&sig_bytes);
            h.update(&ak_pem_bytes);
            hex::encode(h.finalize())
        };

        let timestamp = chrono::Utc::now().to_rfc3339();

        // Step 2a: commit to the transparency log.
        let entry = self.scitt().append(
            &timestamp,
            &signed_hash,
            &attestation_digest,
            &attested_pcr23,
        )?;

        // Step 2b: build the on-chain anchor.
        let digest_bytes = hex::decode(&attestation_digest)?;
        let opreturn_hex = opreturn::script_hex(&digest_bytes)?;

        let receipt = Receipt {
            version: 1,
            timestamp,
            displayed_payload_sha256: displayed_hash,
            signed_payload_sha256: signed_hash,
            pcr_selection: PCR_LIST.to_string(),
            attested_pcr23,
            nonce_hex,
            attestation_digest,
            opreturn_scriptpubkey_hex: opreturn_hex,
            scitt_seq: entry.seq,
            scitt_entry_hash: entry.entry_hash,
            ak_pem: ak.pem.to_string_lossy().into_owned(),
            quote_msg: quote.msg.to_string_lossy().into_owned(),
            quote_sig: quote.sig.to_string_lossy().into_owned(),
            quote_pcrs: quote.pcrs.to_string_lossy().into_owned(),
        };

        let receipt_path = self.workdir.join(format!("receipt-{}.json", entry.seq));
        fs::write(&receipt_path, serde_json::to_string_pretty(&receipt)?)?;

        // Leave the PCR clean for the next ceremony.
        self.tpm.pcr_reset(PAYLOAD_PCR).ok();
        self.tpm.cleanup();

        Ok(receipt)
    }

    /// Independent verification, as a CMF auditor / court expert would perform.
    pub fn verify(&self, receipt: &Receipt, expected_payload: &[u8]) -> Result<VerifyReport> {
        let ak_pem = PathBuf::from(&receipt.ak_pem);
        let quote = crate::tpm::QuoteArtifacts {
            msg: PathBuf::from(&receipt.quote_msg),
            sig: PathBuf::from(&receipt.quote_sig),
            pcrs: PathBuf::from(&receipt.quote_pcrs),
        };

        // (1) Cryptographic: the hardware AK really signed this quote, over
        //     this PCR set, bound to this nonce.
        let checkquote_out = self.tpm.checkquote(&ak_pem, &quote, &receipt.nonce_hex);
        let signature_ok = checkquote_out.is_ok();
        let quoted_pcr23 = checkquote_out
            .ok()
            .and_then(|out| parse_pcr_value(&out, PAYLOAD_PCR))
            .unwrap_or_else(|| receipt.attested_pcr23.clone());

        // (2) Binding: does the attested PCR23 equal SHA256(zeros || H(expected))?
        //     If the auditor's expected payload differs from what was signed,
        //     this fails — which is precisely how a presentation-layer fraud
        //     surfaces.
        let expected_pcr23 = expected_pcr23_for(expected_payload);
        let binding_ok = quoted_pcr23 == expected_pcr23;

        // (3) Anchor: recompute the attestation digest and confirm it matches
        //     the OP_RETURN and the transparency log.
        let recomputed_digest = recompute_attestation_digest(
            &quote.msg,
            &quote.sig,
            &ak_pem,
        )?;
        let digest_ok = recomputed_digest == receipt.attestation_digest;
        let opreturn_ok = opreturn::script_hex(&hex::decode(&recomputed_digest)?)?
            == receipt.opreturn_scriptpubkey_hex;

        // (4) Transparency: the log chain is intact and commits this digest.
        let scitt = self.scitt();
        let chain_ok = scitt.verify_chain().is_ok();
        let committed_ok = crate::scitt::contains_attestation(
            &self.workdir.join("scitt-log.jsonl"),
            &receipt.attestation_digest,
        )?;

        Ok(VerifyReport {
            signature_ok,
            binding_ok,
            digest_ok,
            opreturn_ok,
            chain_ok,
            committed_ok,
            expected_pcr23,
            quoted_pcr23,
        })
    }
}

pub struct VerifyReport {
    pub signature_ok: bool,
    pub binding_ok: bool,
    pub digest_ok: bool,
    pub opreturn_ok: bool,
    pub chain_ok: bool,
    pub committed_ok: bool,
    pub expected_pcr23: String,
    pub quoted_pcr23: String,
}

impl VerifyReport {
    pub fn passed(&self) -> bool {
        self.signature_ok
            && self.binding_ok
            && self.digest_ok
            && self.opreturn_ok
            && self.chain_ok
            && self.committed_ok
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// PCR23 value after reset(0) + extend(SHA256(payload)):
/// SHA256( 32 zero bytes || SHA256(payload) ).
pub fn expected_pcr23_for(payload: &[u8]) -> String {
    let payload_digest = hex::decode(sha256_hex(payload)).unwrap();
    let zeros = hex::decode(ZERO_PCR).unwrap();
    let mut h = Sha256::new();
    h.update(&zeros);
    h.update(&payload_digest);
    hex::encode(h.finalize())
}

fn recompute_attestation_digest(msg: &Path, sig: &Path, ak_pem: &Path) -> Result<String> {
    let mut h = Sha256::new();
    h.update(&fs::read(msg)?);
    h.update(&fs::read(sig)?);
    h.update(&fs::read(ak_pem)?);
    Ok(hex::encode(h.finalize()))
}

/// Cryptographically strong nonce from the OS CSPRNG.
fn random_hex(n: usize) -> Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buf)
        .context("read nonce")?;
    Ok(hex::encode(buf))
}
