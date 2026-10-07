# HyL-EHR prototype (Phase I)

Simulator and experiments for the project report *Consent-Bound Secure Transmission of
Electronic Health Records over a Hybrid Blockchain Ledger with Sensitivity-Aware Adaptive
Anchoring*.

Everything runs on one machine. No real patient data is used; records are random bytes inside
a FHIR-style envelope.

## Layout

| Path | What it is |
|---|---|
| `hylehr/` | The framework: crypto helpers, private and public ledger, CBKD transfer, SAAA policy, off-chain store, workload generator |
| `contracts/AnchorRegistry.sol` | Public-chain anchor contract (Solidity 0.8) |
| `evm/measure_gas.js` | Compiles the contract and measures gas on a local EVM (no network, no ether) |
| `experiments/` | `demo.py`, the security suite `e6_security.py`, and experiments E1 to E7 |
| `results/` | Output of the run reported in the thesis (JSON + console text) |
| `charts/` | Scripts that draw the report's charts, diagrams and code figures from `results/` |
| `run_all.sh` | Runs every experiment in order and rewrites `results/` |
| `demo_app/` | Demo console: a small local web app over the same `hylehr/` code, for showing the system live |
| `run_demo.sh`, `run_demo.bat` | Start the demo console (Linux/macOS, Windows) |

## Demo console (for the review)

The console needs Python 3.10 or newer and one package. It does not need NumPy, Node.js or
an internet connection.

```bash
pip install cryptography
python3 demo_app/app.py          # Windows: double-click run_demo.bat
```

It opens http://127.0.0.1:8765 in your browser. To use another port, set `HYLEHR_PORT`; to stop
it from opening a browser, add `--no-browser`. Stop the server with Ctrl+C.

The top panel is a live picture of the three places data lives: public anchors, private blocks
(coloured by the most sensitive transaction inside) and the encrypted off-chain store. Below it
are four tabs.

| Tab | What it shows |
|---|---|
| Walk-through | Add a record, grant consent, request a transfer, revoke. Every transfer is traced message by message with timings. |
| Attack lab | Eleven attacks, each run against a fresh sandbox consortium. Ten are blocked; the last is a control that shows what is still possible before a block is anchored. |
| Anchoring lab | One simulated day anchored two ways at the same budget: fixed interval against SAAA-B. Budget, critical share and load can be changed. |
| Ledger explorer | Every block, anchor and consent entry. "Prove" builds a dual-ledger proof for a transaction and checks it against the public chain. |

A five-minute script that works well in front of a panel:

1. Walk-through: add a lab report, then press **Request transfer**. It is refused, because there is no consent yet.
2. Press **Grant consent**, then **Request transfer** again. Read out the trace: signed request, consent digest, session key, wrapped data key, receipt.
3. Press **Revoke consent**. Point at the top panel: the revocation is a critical event, so a new public anchor appears at once.
4. Press **Request transfer** once more. It is refused.
5. Ledger explorer: open the block that holds `CONSENT_REVOKE` and press **Prove**. The proof is checked against the public anchor only.
6. Attack lab: press **Run all attacks**. Point at the two rows stopped by the consent-bound key, and at the control row.
7. Anchoring lab: run at the defaults, then set critical transactions to 0.5% to show where the budget stops holding.

The anchoring lab is a single one-day run with one random seed, so its figures differ slightly
from experiment E4, which averages ten seeds over three days.

## Running it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
(cd evm && npm install)          # solc, ethers, @ethereumjs/vm  (Node.js 20 or newer)

python3 experiments/demo.py      # 5-second walk-through
python3 experiments/e6_security.py
./run_all.sh                     # everything; a few minutes
python3 charts/make_charts.py    # redraw the result charts into charts/out/
```

`run_all.sh` overwrites the files in `results/`. Timings depend on the machine, so the numbers
you get will differ from the ones in the report; replace the tables and Table 3.1 with your own
when you re-run. The anchoring simulation (E4) and the gas figures (E7) are deterministic and
should reproduce exactly.

## What each experiment measures

| Id | Script | Question |
|---|---|---|
| E1 | `e1_crypto.py` | Cost of each cryptographic primitive |
| E2 | `e2_transfer.py` | CBKD transfer time by stage, record size and scheme |
| E3 | `e3_ledger.py` | Commit cost of the simulated private ledger |
| E4 | `e4_anchoring.py` | SAAA against fixed-interval and per-block anchoring |
| E5 | `e5_proofs.py` | Dual-ledger proof size and verification time; on-chain footprint |
| E6 | `e6_security.py` | 21 scripted attack and control cases |
| E7 | `e7_vectors.py` + `evm/measure_gas.js` | Gas used by the anchor contract; Python/Solidity agreement |

## Known limits

Single process, no network delay, assumed workload, simplified public chain. See Chapter 8 of
the report.
