# Artifact — reproduction guide

This document lets an independent reviewer reproduce every result claimed by the
PoC from scratch, on their own hardware TPM. It follows the structure expected
by artifact-evaluation committees (requirements → build → run → expected output).

## 1. Requirements

**Hardware.** A machine with a TPM 2.0 (discrete or firmware). No special
peripheral is needed; the ceremony uses only standard PCR and quote operations.

**Software.** Any recent Linux with:

- a TPM 2.0 exposed at `/dev/tpmrm0` (in-kernel resource manager) and the
  invoking user in group `tss` (so no root is required);
- `tpm2-tools` ≥ 5.x;
- Rust ≥ 1.75 with `cargo`.

**Reference environment** (the one used to produce the transcript in §4):

| Component | Version |
|---|---|
| OS | Linux Mint 21.3 (Ubuntu 22.04 base) |
| Kernel | 6.8.0-84-generic |
| TPM | 2.0 (hardware, via `/dev/tpmrm0`) |
| tpm2-tools | 5.2 |
| Rust | 1.95.0 |

Override the device with `ASC_TCTI` (e.g. `ASC_TCTI=device:/dev/tpm0`, or a
`swtpm` simulator socket such as `ASC_TCTI=swtpm:host=localhost,port=2321`) if
your setup differs.

## 2. Build

```bash
cargo build --release
cargo test  --release      # unit tests for the OP_RETURN encoder
```

Expected: a clean build and `test result: ok. 2 passed`.

## 3. Run

```bash
./target/release/asc setup          # provision the hardware Attestation Key (once)
./target/release/asc demo-tamper    # the end-to-end presentation-layer attack demo
```

The `demo-tamper` command:

1. signs a **malicious** payload while "displaying" a **benign** one;
2. verifies the receipt against the benign (displayed) payload — expect
   **REJECTED**, because PCR23 does not match;
3. verifies against the real (signed) payload — expect **CEREMONY VALID**.

Manual driving:

```bash
./target/release/asc ceremony --payload "TRANSFER 0.10 BTC -> alice"
./target/release/asc verify --receipt asc-work/receipt-0.json --expect "TRANSFER 0.10 BTC -> alice"   # PASS
./target/release/asc verify --receipt asc-work/receipt-0.json --expect "TRANSFER 0.10 BTC -> attacker" # REJECTED, exit 1
```

## 4. Expected output (reference transcript)

Values are hardware- and time-specific; the **structure** and the **pass/fail
pattern** are what reproduce. Boot PCRs (0–7) will differ per machine; PCR23 is
deterministic given the payload: `PCR23 = SHA256( 0^32 || SHA256(payload) )`.

### 4.1 `demo-tamper` (abridged)

```
 UI SHOWED  : TRANSFER 0.10 BTC -> bc1q-alice-legitimate-client
 DEVICE SIGNED: TRANSFER 10.00 BTC -> bc1q-attacker-lazarus-group
  SIGNED payload      sha256:f091af901bd9f82ecdc3037caa017b966121b1202db1c2bd65d673b46e347d5d
  attested PCR23      b5c2c2b90cb62a49d8dc12f68fbaff06c4f1e0d889484522c650471eb2328eb9
  attestation digest  2974e8104671a95cc9709c4d24689a09f11f9d7e01d584fd474ebb5c8480d49d
  OP_RETURN script    6a202974e8104671a95cc9709c4d24689a09f11f9d7e01d584fd474ebb5c8480d49d

── verification: auditor checks against what the UI DISPLAYED
  [FAIL] payload binding (PCR23 matches expected)   => REJECTED

── verification: auditor checks against what was ACTUALLY signed
  [PASS] AK signature + nonce (hardware attested)
  [PASS] payload binding (PCR23 matches expected)   => CEREMONY VALID
```

### 4.2 Independent quote verification (`tpm2_checkquote`)

The auditor's PCR values come from the cryptographically verified quote, not
from the receipt:

```
pcrs:
  sha256:
    0 : 0x490BF81168FEBE08498923675580921E354DA10040B1A373B6F75E8DC19BA5D8
    ...
    7 : 0x14125A871E202034426FC6A8CE8D6B2251290073B30B9B331AB6E14B60C1B11D
    23: 0x41DDD409DE053BE21B3718D9D1678D196159F8E6690FC939FFAD6CB36B17F871
sig: 98b30063ae8f7fac...   (RSA-2048, AK-signed)
```

### 4.3 SCITT transparency log (hash-chained)

Each entry's `prev_entry_hash` equals the previous entry's `entry_hash`:

```
{"seq":0,...,"prev_entry_hash":"000...000","entry_hash":"49b5958a...dbba7"}
{"seq":1,...,"prev_entry_hash":"49b5958a...dbba7","entry_hash":"9158ad06...f822e"}
```

## 5. Independent cross-check without this tool

A reviewer can validate the core binding with only `openssl` and the receipt:

```bash
# expected PCR23 = SHA256( 32 zero bytes || SHA256(payload) )
PAYLOAD='TRANSFER 0.10 BTC -> alice'
H=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -binary | xxd -p -c256)
( printf '%064x' 0 | xxd -r -p; printf '%s' "$H" | xxd -r -p ) | openssl dgst -sha256
# compare to `attested_pcr23` in the receipt
```

## 6. What is real vs. scaffolded

See README §"What is real vs. scaffolded". In short: all TPM/attestation
operations and their verification are real; the AK enrolment, the on-chain
broadcast and the networked SCITT service are deployment steps, deliberately
left as clearly-marked hardening TODOs.
