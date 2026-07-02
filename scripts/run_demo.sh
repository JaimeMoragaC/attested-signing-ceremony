#!/usr/bin/env bash
# End-to-end demo of the Attested Signing Ceremony against the real hardware TPM.
set -euo pipefail
cd "$(dirname "$0")/.."

echo ">> building (release)"
cargo build --release

BIN=./target/release/asc

echo; echo ">> provisioning hardware Attestation Key"
"$BIN" setup

echo; echo ">> tamper demo (presentation-layer attack)"
"$BIN" demo-tamper

echo; echo ">> artifacts in ./asc-work:"
ls -1 asc-work
echo; echo ">> SCITT transparency log:"
cat asc-work/scitt-log.jsonl
