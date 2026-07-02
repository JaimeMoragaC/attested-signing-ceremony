//! Bitcoin `OP_RETURN` anchoring of the attestation digest.
//!
//! Step 2 of the ceremony embeds the 32-byte attestation digest in a provably
//! unspendable output, so the public chain records not just that the key
//! authorised the transaction, but that it did so from an environment whose
//! state was attested at that instant. 32 bytes fits comfortably inside the
//! 80-byte standardness limit for a single `OP_RETURN` data push.

use anyhow::{bail, Result};

const OP_RETURN: u8 = 0x6a;
/// Bitcoin Core relays `OP_RETURN` outputs whose pushed data is <= 80 bytes.
const MAX_OP_RETURN_DATA: usize = 80;

/// Build the `scriptPubKey` for an `OP_RETURN` output carrying `data`:
/// `OP_RETURN <push> <data>`. Returns the raw script bytes.
pub fn build_script(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > MAX_OP_RETURN_DATA {
        bail!(
            "attestation payload is {} bytes, exceeds the {}-byte OP_RETURN standardness limit",
            data.len(),
            MAX_OP_RETURN_DATA
        );
    }
    let mut script = Vec::with_capacity(2 + data.len());
    script.push(OP_RETURN);
    // Direct push opcode for lengths 1..=75 is the length byte itself.
    if data.len() <= 75 {
        script.push(data.len() as u8);
    } else {
        // OP_PUSHDATA1 for 76..=80.
        script.push(0x4c);
        script.push(data.len() as u8);
    }
    script.extend_from_slice(data);
    Ok(script)
}

pub fn script_hex(data: &[u8]) -> Result<String> {
    Ok(hex::encode(build_script(data)?))
}

/// The exact `bitcoin-cli` invocation an operator would use to broadcast the
/// anchor on testnet (kept as a hint so the PoC is verifiable end-to-end
/// without bundling a wallet).
pub fn broadcast_hint(attestation_digest_hex: &str) -> String {
    format!(
        "# Broadcast the attestation anchor on Bitcoin testnet:\n\
         bitcoin-cli -testnet createrawtransaction \\\n  \
         '[{{\"txid\":\"<funding-utxo>\",\"vout\":0}}]' \\\n  \
         '[{{\"data\":\"{attestation_digest_hex}\"}}]'\n\
         # then fundrawtransaction / signrawtransactionwithwallet / sendrawtransaction"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirty_two_byte_digest_fits() {
        let digest = [0xabu8; 32];
        let script = build_script(&digest).unwrap();
        assert_eq!(script[0], OP_RETURN);
        assert_eq!(script[1], 0x20); // push 32
        assert_eq!(script.len(), 34);
    }

    #[test]
    fn oversized_rejected() {
        assert!(build_script(&[0u8; 81]).is_err());
    }
}
