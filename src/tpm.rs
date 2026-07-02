//! Thin wrapper over the `tpm2-tools` reference stack.
//!
//! We shell out to the standard `tpm2_*` binaries rather than binding
//! `tss-esapi` directly: the tools ARE the reference implementation, they are
//! stable across distros, and — crucially for the provenance argument of the
//! paper — every command here runs against the real hardware TPM exposed at
//! `/dev/tpmrm0`, so the attestation output is genuine silicon output, not a
//! simulator's.
//!
//! The in-kernel Resource Manager (`/dev/tpmrm0`, group `tss`) lets us run
//! unprivileged; override with `ASC_TCTI` if your device differs.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default TPM Command Transmission Interface. The in-kernel resource manager
/// multiplexes transient objects for us and needs no root.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

pub struct Tpm {
    pub workdir: PathBuf,
    tcti: String,
}

impl Tpm {
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        let tcti = std::env::var("ASC_TCTI").unwrap_or_else(|_| DEFAULT_TCTI.to_string());
        Tpm { workdir: workdir.into(), tcti }
    }

    /// Run a `tpm2_*` tool inside the work directory with the configured TCTI,
    /// returning captured stdout. Non-zero exit is an error carrying stderr.
    fn run(&self, tool: &str, args: &[&str]) -> Result<String> {
        // Paths handed to the tools are already workdir-prefixed (see `p`), so
        // we run in the process CWD — setting current_dir too would double the
        // prefix.
        let out = Command::new(tool)
            .args(args)
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .output()
            .with_context(|| format!("failed to spawn `{tool}` (is tpm2-tools installed?)"))?;
        if !out.status.success() {
            bail!(
                "{tool} {} exited with {}\nstdout:\n{}\nstderr:\n{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn p(&self, name: &str) -> String {
        self.workdir.join(name).to_string_lossy().into_owned()
    }

    /// Provision an Attestation Key (AK) under the Endorsement hierarchy.
    /// Idempotent: if `ak.ctx` + `ak.pem` already exist we reuse them, so the
    /// same key signs across ceremonies (a real deployment would persist the AK
    /// to an NV handle and enrol its certificate; that is a deployment step, not
    /// a change to this ceremony).
    pub fn ensure_ak(&self) -> Result<AkPaths> {
        let ak = AkPaths {
            ctx: self.workdir.join("ak.ctx"),
            pem: self.workdir.join("ak.pem"),
            name: self.workdir.join("ak.name"),
        };
        if ak.ctx.exists() && ak.pem.exists() {
            return Ok(ak);
        }
        // Endorsement Key: the hardware-rooted seed of the attestation identity.
        self.run("tpm2_createek", &["-G", "rsa", "-c", &self.p("ek.ctx"), "-u", &self.p("ek.pub")])
            .context("tpm2_createek")?;
        // Restricted signing AK derived from the EK; this is what signs quotes.
        self.run(
            "tpm2_createak",
            &[
                "-C", &self.p("ek.ctx"),
                "-c", &self.p("ak.ctx"),
                "-G", "rsa",
                "-g", "sha256",
                "-s", "rsassa",
                "-u", &self.p("ak.pem"),
                "-f", "pem",
                "-n", &self.p("ak.name"),
            ],
        )
        .context("tpm2_createak")?;
        Ok(ak)
    }

    /// Reset a resettable PCR (23 is the application PCR, resettable from
    /// locality 0) back to all-zero.
    pub fn pcr_reset(&self, index: u32) -> Result<()> {
        self.run("tpm2_pcrreset", &[&index.to_string()]).map(|_| ())
    }

    /// Extend `sha256(payload)` into a PCR: PCR_new = SHA256(PCR_old || digest).
    /// This is the heart of "measured signing" — it binds the concrete
    /// instruction being signed to the attestation.
    pub fn pcr_extend_sha256(&self, index: u32, digest_hex: &str) -> Result<()> {
        let spec = format!("{index}:sha256={digest_hex}");
        self.run("tpm2_pcrextend", &[&spec]).map(|_| ())
    }

    /// Read a single sha256 PCR and return its 64-hex value.
    pub fn pcr_read_sha256(&self, index: u32) -> Result<String> {
        let out = self.run("tpm2_pcrread", &[&format!("sha256:{index}")])?;
        parse_pcr_value(&out, index)
            .with_context(|| format!("could not parse PCR{index} from tpm2_pcrread output:\n{out}"))
    }

    /// Produce a fresh, AK-signed quote over the selected PCRs, bound to `nonce`.
    /// Writes the attestation message, signature and PCR blob into the workdir.
    pub fn quote(&self, ak_ctx: &Path, pcr_list: &str, nonce_hex: &str) -> Result<QuoteArtifacts> {
        let msg = self.workdir.join("quote.msg");
        let sig = self.workdir.join("quote.sig");
        let pcrs = self.workdir.join("quote.pcrs");
        self.run(
            "tpm2_quote",
            &[
                "-c", &ak_ctx.to_string_lossy(),
                "-l", pcr_list,
                "-q", nonce_hex,
                "-m", &msg.to_string_lossy(),
                "-s", &sig.to_string_lossy(),
                "-o", &pcrs.to_string_lossy(),
                "-g", "sha256",
            ],
        )
        .context("tpm2_quote")?;
        Ok(QuoteArtifacts { msg, sig, pcrs })
    }

    /// Verify a quote the way an independent auditor would: signature valid
    /// under the AK public key, PCR blob consistent with the signed digest, and
    /// nonce matching. Returns the tool's stdout (which echoes the attested
    /// PCRs) for the caller to inspect the bound PCR23 value.
    pub fn checkquote(
        &self,
        ak_pem: &Path,
        q: &QuoteArtifacts,
        nonce_hex: &str,
    ) -> Result<String> {
        self.run(
            "tpm2_checkquote",
            &[
                "-u", &ak_pem.to_string_lossy(),
                "-m", &q.msg.to_string_lossy(),
                "-s", &q.sig.to_string_lossy(),
                "-f", &q.pcrs.to_string_lossy(),
                "-q", nonce_hex,
                "-g", "sha256",
            ],
        )
        .context("tpm2_checkquote")
    }

    /// Flush transient objects/sessions so we stay a good TPM citizen.
    pub fn cleanup(&self) {
        let _ = self.run("tpm2_flushcontext", &["-t"]);
        let _ = self.run("tpm2_flushcontext", &["-l"]);
        let _ = self.run("tpm2_flushcontext", &["-s"]);
    }
}

pub struct AkPaths {
    pub ctx: PathBuf,
    pub pem: PathBuf,
    pub name: PathBuf,
}

pub struct QuoteArtifacts {
    pub msg: PathBuf,
    pub sig: PathBuf,
    pub pcrs: PathBuf,
}

/// Parse `NN: 0x<hex>` for `index` out of a tpm2-tools YAML-ish dump, scoped to
/// the sha256 bank. Shared by pcr_read and checkquote-output parsing.
pub fn parse_pcr_value(dump: &str, index: u32) -> Option<String> {
    let mut in_sha256 = false;
    for line in dump.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("sha256") {
            in_sha256 = true;
            continue;
        }
        if lower.starts_with("sha1") || lower.starts_with("sha384") || lower.starts_with("sha512")
        {
            in_sha256 = false;
            continue;
        }
        if !in_sha256 {
            continue;
        }
        if let Some((idx, val)) = t.split_once(':') {
            if idx.trim() == index.to_string() {
                let v = val.trim().trim_start_matches("0x").to_ascii_lowercase();
                if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(v);
                }
            }
        }
    }
    None
}
