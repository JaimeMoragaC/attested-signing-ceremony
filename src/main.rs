//! `asc` — Attested Signing Ceremony reference PoC.
//!
//! Reference implementation for §6.8.1 of «Ficción Jurídica de la Auditoría
//! Delegada». Runs against the real hardware TPM via the in-kernel resource
//! manager. See README.md for the threat model and the mapping to the Bybit /
//! Radiant Capital / WazirX cases.

mod ceremony;
mod opreturn;
mod scitt;
mod tpm;

use anyhow::{Context, Result};
use ceremony::{Ceremony, Receipt, VerifyReport};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "asc", version, about = "Attested Signing Ceremony (§6.8.1) reference PoC")]
struct Cli {
    /// Working directory for keys, quotes, receipts and the SCITT log.
    #[arg(long, global = true, default_value = "asc-work")]
    workdir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Provision the hardware Attestation Key (idempotent).
    Setup,
    /// Run one honest ceremony over a payload (displayed == signed).
    Ceremony {
        /// Payload as a UTF-8 string.
        #[arg(long, conflicts_with = "payload_file")]
        payload: Option<String>,
        /// Payload from a file (any bytes).
        #[arg(long)]
        payload_file: Option<PathBuf>,
    },
    /// Independently verify a receipt against an expected payload.
    Verify {
        /// Receipt JSON emitted by a ceremony.
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long, conflicts_with = "expect_file")]
        expect: Option<String>,
        #[arg(long)]
        expect_file: Option<PathBuf>,
    },
    /// End-to-end story: benign UI vs. malicious signed payload, then show that
    /// verification against the benign display FAILS and against the real
    /// payload PASSES — the forensic proof the three real heists lacked.
    DemoTamper,
}

fn load_payload(text: &Option<String>, file: &Option<PathBuf>) -> Result<Vec<u8>> {
    match (text, file) {
        (Some(s), _) => Ok(s.clone().into_bytes()),
        (None, Some(p)) => fs::read(p).with_context(|| format!("read {}", p.display())),
        (None, None) => anyhow::bail!("provide --payload or --payload-file"),
    }
}

fn print_receipt(r: &Receipt) {
    println!("  timestamp           {}", r.timestamp);
    println!("  displayed payload   sha256:{}", r.displayed_payload_sha256);
    println!("  SIGNED payload      sha256:{}", r.signed_payload_sha256);
    println!("  attested PCR23      {}", r.attested_pcr23);
    println!("  nonce               {}", r.nonce_hex);
    println!("  attestation digest  {}", r.attestation_digest);
    println!("  OP_RETURN script    {}", r.opreturn_scriptpubkey_hex);
    println!("  SCITT seq / head    {} / {}", r.scitt_seq, r.scitt_entry_hash);
}

fn print_report(label: &str, rep: &VerifyReport) {
    let mark = |b: bool| if b { "PASS" } else { "FAIL" };
    println!("── verification: {label}");
    println!("  [{}] AK signature + nonce (hardware attested)", mark(rep.signature_ok));
    println!("  [{}] payload binding (PCR23 matches expected)", mark(rep.binding_ok));
    println!("  [{}] attestation digest matches receipt", mark(rep.digest_ok));
    println!("  [{}] OP_RETURN anchor matches digest", mark(rep.opreturn_ok));
    println!("  [{}] SCITT chain intact", mark(rep.chain_ok));
    println!("  [{}] digest committed in SCITT log", mark(rep.committed_ok));
    if !rep.binding_ok {
        println!("      expected PCR23 {}", rep.expected_pcr23);
        println!("      attested PCR23 {}", rep.quoted_pcr23);
    }
    println!("  => {}", if rep.passed() { "CEREMONY VALID" } else { "REJECTED" });
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cer = Ceremony::new(&cli.workdir)?;

    match cli.cmd {
        Cmd::Setup => {
            cer.setup()?;
            println!("AK provisioned under {}", cli.workdir.display());
        }
        Cmd::Ceremony { payload, payload_file } => {
            let p = load_payload(&payload, &payload_file)?;
            let r = cer.run(&p, &p)?;
            println!("── ceremony complete (honest: displayed == signed)");
            print_receipt(&r);
        }
        Cmd::Verify { receipt, expect, expect_file } => {
            let r: Receipt = serde_json::from_str(&fs::read_to_string(&receipt)?)
                .context("parse receipt")?;
            let expected = load_payload(&expect, &expect_file)?;
            let rep = cer.verify(&r, &expected)?;
            print_report("receipt vs expected payload", &rep);
            if !rep.passed() {
                std::process::exit(1);
            }
        }
        Cmd::DemoTamper => run_demo_tamper(&cer)?,
    }
    Ok(())
}

fn run_demo_tamper(cer: &Ceremony) -> Result<()> {
    let displayed = b"TRANSFER 0.10 BTC -> bc1q-alice-legitimate-client".to_vec();
    let signed = b"TRANSFER 10.00 BTC -> bc1q-attacker-lazarus-group".to_vec();

    println!("========================================================================");
    println!(" PRESENTATION-LAYER ATTACK (Bybit / Radiant Capital / WazirX pattern)");
    println!("========================================================================");
    println!(" UI SHOWED  : {}", String::from_utf8_lossy(&displayed));
    println!(" DEVICE SIGNED: {}", String::from_utf8_lossy(&signed));
    println!();
    println!(" The signing key faithfully authorised the malicious payload. In the");
    println!(" real heists the signing environment produced no verifiable record of");
    println!(" WHAT was signed. Here, measured signing binds the real payload:");
    println!();

    let r = cer.run(&displayed, &signed)?;
    print_receipt(&r);
    println!();

    // An auditor who trusts the compromised UI verifies against the benign
    // payload — and the ceremony rejects it, exposing the fraud.
    let rep_benign = cer.verify(&r, &displayed)?;
    print_report("auditor checks against what the UI DISPLAYED", &rep_benign);
    println!();

    // Verifying against the real signed payload passes: the attestation proves
    // exactly what left the signer.
    let rep_real = cer.verify(&r, &signed)?;
    print_report("auditor checks against what was ACTUALLY signed", &rep_real);
    println!();

    println!("========================================================================");
    println!(" RESULT: the attestation records the REAL instruction regardless of what");
    println!(" the compromised interface displayed. The malicious transfer is now");
    println!(" forensically irrefutable — the evidence Bybit, Radiant and WazirX");
    println!(" could not produce. (§6.8.1 / §5.3 ceguera forense bidireccional.)");
    println!("========================================================================");
    Ok(())
}
