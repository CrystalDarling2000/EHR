#!/usr/bin/env bash
# Reproduce every number and figure of the report.
set -e
cd "$(dirname "$0")/experiments"
python3 demo.py           | tee ../results/demo.txt
python3 e6_security.py    | tee ../results/e6_security.txt
python3 e1_crypto.py      | tee ../results/e1_crypto.txt
python3 e2_transfer.py    | tee ../results/e2_transfer.txt
python3 e3_ledger.py      | tee ../results/e3_ledger.txt
python3 e5_proofs.py      | tee ../results/e5_proofs.txt
python3 e7_vectors.py     | tee ../results/e7_vectors.txt
(cd ../evm && node measure_gas.js) | tee ../results/e7_gas.txt
python3 e4_anchoring.py   | tee ../results/e4_anchoring.txt
