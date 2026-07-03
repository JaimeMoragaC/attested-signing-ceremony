# Attested Signing Ceremony — reference PoC

Reference implementation of the **Attested Signing Ceremony** described in
§6.8.1 of *Ficción Jurídica de la Auditoría Delegada*. It runs against a **real
hardware TPM 2.0** (via the in-kernel resource manager `/dev/tpmrm0`, no root
required) and demonstrates a single, falsifiable claim:

> Whatever a compromised interface *displays*, the attestation records the
> payload that was *actually signed*. The malicious instruction becomes
> forensically irrefutable — exactly the evidence that Bybit, Radiant Capital
> and WazirX could not produce.

This is not a product and not a simulator run. It is the minimum artifact that
turns a written argument into something you can execute, verify against your own
silicon, and defend live.

## Threat model

The three heists analysed in the paper were **presentation-layer attacks**: the
UI showed transaction *X*, the device signed transaction *Y*. The key behaved
correctly; the *context* of signing was compromised. Boot-time attestation
(PCR0–7) alone does not catch this, because the binary is unchanged. So we add
**measured signing**: immediately before the ceremony we extend the payload into
a resettable application PCR (23) and quote it together with the boot PCRs. The
attestation now binds the *specific instruction*, not just the environment.

This stays entirely inside the sovereign TPM 2.0 trust root the paper defends —
no Intel SGX/TDX or AMD SEV-SNP enclaves, which would reintroduce the foreign
proprietary-silicon dependency §6.7 (Objeción A) rejects.

## The three steps (mapped to the code)

| Paper step | What it does | Module |
|---|---|---|
| **1. Measured signing** | `tpm2_pcrreset 23` → `tpm2_pcrextend 23 = SHA256(payload)` → `tpm2_quote` over `sha256:0..7,23` under the hardware AK | [`src/tpm.rs`](src/tpm.rs), [`src/ceremony.rs`](src/ceremony.rs) |
| **2. Atomic binding** | commit `attestation_digest = SHA256(quote‖sig‖AKpub)` to a hash-chained SCITT log **and** embed it in a Bitcoin `OP_RETURN` | [`src/scitt.rs`](src/scitt.rs), [`src/opreturn.rs`](src/opreturn.rs) |
| **3. Independent verify** | `tpm2_checkquote` (signature + nonce) → recompute expected `PCR23 = SHA256(0³² ‖ SHA256(payload))` → confirm digest, anchor and log chain | [`src/ceremony.rs`](src/ceremony.rs) |

## Requirements

- Linux with a TPM 2.0 at `/dev/tpmrm0` and your user in group `tss`
- `tpm2-tools` ≥ 5.x (`tpm2_createek`, `tpm2_createak`, `tpm2_pcrextend`,
  `tpm2_quote`, `tpm2_checkquote`, `tpm2_pcrreset`, `tpm2_pcrread`)
- Rust ≥ 1.75

Override the device with `ASC_TCTI` (e.g. `ASC_TCTI=device:/dev/tpm0`, or a
swtpm simulator socket) if needed.

## Run

```bash
cargo build --release
./target/release/asc setup          # provision the hardware AK (once)
./target/release/asc demo-tamper    # the money demo
# or drive it manually:
./target/release/asc ceremony --payload "TRANSFER 0.10 BTC -> alice"
./target/release/asc verify --receipt asc-work/receipt-0.json --expect "TRANSFER 0.10 BTC -> alice"
```

Or the whole thing: `bash scripts/run_demo.sh`.

### On-chain anchoring (optional, `--broadcast`)

Add `--broadcast` to build, fund, sign and **send** the `OP_RETURN` anchor to a
Bitcoin node, recording the real txid in the receipt. Configure the node via
`ASC_BTC_NETWORK` (`regtest` default / `testnet` / `signet` / `mainnet`),
`ASC_BTC_DATADIR`, `ASC_BTC_WALLET`:

```bash
# self-contained: local regtest node, no faucet needed
export ASC_BTC_NETWORK=regtest ASC_BTC_DATADIR=~/.bitcoin-poc-regtest ASC_BTC_WALLET=poc
./target/release/asc demo-tamper --broadcast
# -> receipt shows: OP_RETURN txid <txid> (regtest) [ON-CHAIN]
```

For a publicly verifiable anchor use `ASC_BTC_NETWORK=testnet` with a
faucet-funded wallet.

### Public Bitcoin anchor, free (OpenTimestamps)

For a publicly verifiable anchor **with no wallet, faucet or fee**, the
attestation digest can be timestamped on Bitcoin **mainnet** via OpenTimestamps
(calendar servers aggregate thousands of hashes and pay the fee). A worked
example ships in [`examples/`](examples/): a real TPM-produced attestation digest
and its proof.

```bash
ots verify examples/attestation-anchor.txt.ots
# run `ots upgrade examples/attestation-anchor.txt.ots` once the Bitcoin block confirms
```

It proves that a genuine attestation digest existed before a specific Bitcoin block.

The `demo-tamper` run signs a malicious payload while "displaying" a benign one,
then verifies twice: against the displayed payload it **REJECTS** (PCR23 does not
match), against the real payload it **PASSES**. That divergence is the forensic
proof.

## What is real vs. scaffolded

- **Real:** all TPM operations run against your hardware TPM and produce genuine
  AK-signed quotes; `tpm2_checkquote` cryptographically verifies them; the SCITT
  chain and the `OP_RETURN` script are fully built and checked; and with
  `--broadcast` the anchor is **actually transmitted to a Bitcoin node** (via
  `bitcoin-cli`), returning a real txid recorded in the receipt and verifiable
  on-chain.
- **Scaffolded (deliberately):** the AK is created fresh per work directory
  rather than persisted to an NV handle and enrolled with a CA; the SCITT log
  is a local hash-chained file, not a networked Transparency Service. These are
  deployment/integration steps, not gaps in the ceremony logic.

## Hardening TODO

- Persist + CA-enrol the AK; pin the EK certificate.
- Parse the signed `quote.pcrs` blob directly instead of trusting
  `tpm2_checkquote`'s echoed PCR values.
- The `--broadcast` path runs end-to-end on **regtest** (self-contained, mines
  its own block). For a publicly verifiable txid, set `ASC_BTC_NETWORK=testnet`
  and fund the wallet from a faucet.
- Replace the file-based log with a real SCITT Transparency Service + inclusion
  proofs.

## Licence

MIT — see [LICENSE](LICENSE).
