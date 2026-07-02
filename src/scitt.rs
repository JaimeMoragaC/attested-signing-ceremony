//! SCITT-style transparency log: append-only, hash-chained, one JSON object per
//! line. This is a minimal stand-in for a full SCITT Transparency Service (IETF
//! draft-ietf-scitt-architecture); it demonstrates the property that matters
//! for the paper — every attestation is committed to an immutable, verifiable
//! sequence, so a later actor cannot silently rewrite the record of what was
//! attested at signing time.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub timestamp: String,
    pub signed_payload_sha256: String,
    pub attestation_digest: String,
    pub pcr23: String,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}

impl LogEntry {
    fn compute_hash(
        seq: u64,
        timestamp: &str,
        payload: &str,
        attestation: &str,
        pcr23: &str,
        prev: &str,
    ) -> String {
        // Canonical, order-fixed preimage. Any mutation of any field or of the
        // chain order changes this hash and breaks verification downstream.
        let material =
            format!("{seq}|{timestamp}|{payload}|{attestation}|{pcr23}|{prev}");
        let mut h = Sha256::new();
        h.update(material.as_bytes());
        hex::encode(h.finalize())
    }
}

pub struct ScittLog {
    path: PathBuf,
}

impl ScittLog {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        ScittLog { path: path.into() }
    }

    fn entries(&self) -> Result<Vec<LogEntry>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let f = File::open(&self.path)
            .with_context(|| format!("open scitt log {}", self.path.display()))?;
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(&line).context("parse scitt entry")?);
        }
        Ok(out)
    }

    /// Append a new attestation record, chaining it to the current head.
    pub fn append(
        &self,
        timestamp: &str,
        signed_payload_sha256: &str,
        attestation_digest: &str,
        pcr23: &str,
    ) -> Result<LogEntry> {
        let existing = self.entries()?;
        let (seq, prev) = match existing.last() {
            Some(last) => (last.seq + 1, last.entry_hash.clone()),
            None => (0, GENESIS_PREV.to_string()),
        };
        let entry_hash = LogEntry::compute_hash(
            seq,
            timestamp,
            signed_payload_sha256,
            attestation_digest,
            pcr23,
            &prev,
        );
        let entry = LogEntry {
            seq,
            timestamp: timestamp.to_string(),
            signed_payload_sha256: signed_payload_sha256.to_string(),
            attestation_digest: attestation_digest.to_string(),
            pcr23: pcr23.to_string(),
            prev_entry_hash: prev,
            entry_hash,
        };
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("append to scitt log {}", self.path.display()))?;
        writeln!(f, "{}", serde_json::to_string(&entry)?)?;
        Ok(entry)
    }

    /// Recompute the whole chain and confirm no entry was altered or reordered.
    pub fn verify_chain(&self) -> Result<usize> {
        let entries = self.entries()?;
        let mut prev = GENESIS_PREV.to_string();
        for (i, e) in entries.iter().enumerate() {
            if e.seq as usize != i {
                bail!("scitt: entry at position {i} has seq {}", e.seq);
            }
            if e.prev_entry_hash != prev {
                bail!("scitt: broken link at seq {} (prev mismatch)", e.seq);
            }
            let expect = LogEntry::compute_hash(
                e.seq,
                &e.timestamp,
                &e.signed_payload_sha256,
                &e.attestation_digest,
                &e.pcr23,
                &e.prev_entry_hash,
            );
            if expect != e.entry_hash {
                bail!("scitt: tampered entry at seq {} (hash mismatch)", e.seq);
            }
            prev = e.entry_hash.clone();
        }
        Ok(entries.len())
    }
}

/// Confirm a given attestation digest is actually committed in the log.
pub fn contains_attestation(path: &Path, attestation_digest: &str) -> Result<bool> {
    let log = ScittLog::open(path.to_path_buf());
    Ok(log
        .entries()?
        .iter()
        .any(|e| e.attestation_digest == attestation_digest))
}
