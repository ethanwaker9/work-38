# Optimal Communication for Post-Quantum Authentication in IoT

CLASP is a mutually authenticated key establishment protocol for device to gateway IoT links.
It is built only from NIST standardized primitives, ML-KEM (FIPS 203) and SHAKE256 (FIPS 202),
and transmits exactly two ML-KEM ciphertexts per session, which is shown in our research to be
optimal for the security goals it attains.

## Files and Content

```
clasp/
  primitives.py    ML-KEM / ML-DSA / Falcon wrappers and the SHAKE256 key derivation and tag functions
  lookup.py        constant time indexed pseudonym table used by the gateway
  protocol.py      CLASP device and gateway state machines, and the CLASP-0 enrolment exchange
  baselines.py     reimplementations of the ten protocols CLASP is compared against
experiments/
  common.py            shared cost models (Cortex-M4 cycles and stack, link layers, radio energy)
  bench_handshake.py   sizes, operation counts, host timings, composed asymmetric timings
  bench_scaling.py     gateway lookup cost against the number of enrolled devices
  bench_robustness.py  expected device energy under frame loss, analytic and Monte-Carlo
  bench_throughput.py  gateway handshake throughput
  bench_longrun.py     long chain evolution and pseudonym uniqueness
  run_all.py           runs the whole pipeline
tests/
  test_correctness.py  functional tests for CLASP and for all baselines
  test_security.py     replay, tampering, desynchronization, state compromise, unlinkability
results/   generated JSON and fragments
```

## Implemented Protocols

| Protocol | Origin |
| --- | --- |
| PQ-TLS 1.3 with ML-DSA / padded Falcon | RFC 8446 with PQ primitives |
| EDHOC method 0 | RFC 9528 with PQ primitives |
| KEMTLS | ACM CCS 2020 |
| KEMTLS-PDK | ESORICS 2021 |
| PQ-WireGuard | IEEE S&P 2021 |
| FSXY generic KEM-AKE | AsiaCCS 2013 |
| Kyber.AKE | IEEE EuroS&P 2018 |
| EDHOC-KEM | KEM variant analyzed at USENIX Security 2023 |
| TLS 1.3 PSK with an ephemeral KEM | RFC 8446 resumption |
| CLASP-0, CLASP | this work |

All baselines are instantiated with the same ML-KEM parameter set, the same transcript hash and
tag functions, and the same liboqs build, so that the reported differences come from the protocol
structure.

## Requirements

* Python 3.10 or newer
* `liboqs-python` (which builds or links liboqs, providing ML-KEM, ML-DSA and Falcon)
* `matplotlib`, `numpy`
* `pytest` for the test suite

Install with
```
pip install -r requirements.txt
```

## Running Experiments
```
cd experiments
python3 run_all.py
```
The pipeline completes in about one minute on a current laptop and needs well below 1 GiB of
memory. It writes `results/handshake.json`, `results/scaling.json`, `results/robustness.json`,
`results/throughput.json`, `results/longrun.json`, `results/primitives.json`,
`results/tables.tex`, and every figure in `figures/`.

Three environment variables control the measurement effort:
| Variable | Default | Meaning |
| --- | --- | --- |
| `CLASP_ITERS` | 1500 | handshake repetitions per protocol and parameter set |
| `CLASP_DURATION` | 2.5 | seconds of throughput measurement per protocol |
| `CLASP_EPOCHS` | 50000 | sessions in the long-run chain-evolution experiment |

## Running the Tests
```
python3 -m pytest tests -q
```
The suite checks that every protocol completes, that CLASP message sizes match the specification
at all three ML-KEM parameter sets, that CLASP produces a distinct session key in every epoch,
and that the protocol rejects unknown pseudonyms, tampered ciphertexts, tampered tags, and
replayed transcripts. It also checks recovery from the loss of the second and third messages,
that an adversary holding the current chain state cannot impersonate the device, that a device
holding its own long term key cannot be used to impersonate the gateway, and that pseudonyms
observed across epochs are distinct and balanced.

## Measurement Methodology

Three timing quantities are shown for each protocol.

1. *Composed asymmetric time*: each ML-KEM and signature operation is micro benchmarked in
   isolation, which takes the fastest of nine batches of 600 repetitions so that scheduler noise is
   suppressed, and the per role totals follow from the operation counts of the protocol. 
2. *End-to-end host time*: the wall clock time of a complete session in this Python harness,
   which additionally contains the protocol logic and the message parsing.
3. *Cortex-M4 cycles and peak stack*: obtained by weighting the operation counts with the
   published pqm4 figures for ML-KEM and ML-DSA. Falcon is not covered by pqm4 and is therefore
   marked as unavailable in the Cortex-M4 columns in our research.

The radio energy model uses 3.0 V, 250 kbit/s, 24 mA while transmitting and 20 mA while
receiving, and a 64 MHz core drawing 10 mA. Link layer payload sizes are 81 B for IEEE 802.15.4
with 6LoWPAN, 244 B for Bluetooth Low Energy, 222 B for LoRaWAN, 1358 B for NB-IoT, and 1232 B
for the smallest guaranteed IPv6 datagram.

