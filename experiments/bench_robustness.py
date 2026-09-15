import json
import os
import random

from common import RESULTS, E_TX_PER_BYTE, E_RX_PER_BYTE, frames

HANDSHAKE_JSON = os.path.join(RESULTS, "handshake.json")
LOSS_GRID = [0.0, 0.02, 0.04, 0.06, 0.08, 0.10, 0.12, 0.15, 0.20]
PAYLOAD_GRID = list(range(40, 250, 6))
TRIALS = 3000
ARQ_RETRIES = 3
SURFACES = ["CLASP", "KEMTLS-PDK", "PQ-WireGuard", "PQ-TLS 1.3/ML-DSA-44", "TLS 1.3 PSK+KEM"]


def frame_profile(msgs, payload):
    up = dn = 0
    for d, n in msgs:
        f = frames(n, payload)
        if d == "I":
            up += f
        else:
            dn += f
    return up, dn


def expected_energy(msgs, payload, rho, cpu_mJ, retries=ARQ_RETRIES):
    up, dn = frame_profile(msgs, payload)
    total = up + dn
    if rho == 0.0:
        tx_per_frame = 1.0
        p_frame = 1.0
    else:
        p_frame = 1.0 - rho ** (retries + 1)
        tx_per_frame = (1.0 - rho ** (retries + 1)) / (1.0 - rho)
    p_hs = p_frame ** total
    e_attempt = (up * payload * E_TX_PER_BYTE + dn * payload * E_RX_PER_BYTE) * 1e3 * tx_per_frame
    e_attempt += cpu_mJ
    return e_attempt / p_hs, p_hs, total


def simulate(msgs, payload, rho, rng, cpu_mJ, retries=ARQ_RETRIES, max_attempts=60):
    energy = 0.0
    for attempt in range(max_attempts):
        ok = True
        for d, n in msgs:
            f = frames(n, payload)
            for _ in range(f):
                sent = 0
                delivered = False
                while sent <= retries:
                    sent += 1
                    energy += payload * (E_TX_PER_BYTE if d == "I" else E_RX_PER_BYTE) * 1e3
                    if rng.random() >= rho:
                        delivered = True
                        break
                if not delivered:
                    ok = False
                    break
            if not ok:
                break
        energy += cpu_mJ
        if ok:
            return energy, attempt + 1
    return energy, max_attempts


def main():
    with open(HANDSHAKE_JSON) as f:
        data = json.load(f)
    sel = {}
    for r in data["ML-KEM-768"]:
        sel[r["name"] + ("/" + r["sig"] if r["sig"] else "")] = r

    surfaces = {}
    for key in SURFACES:
        r = sel[key]
        msgs = list(zip(r["msg_dirs"], r["msg_sizes"]))
        cpu = r["m4_cpu_mJ_init"]
        surfaces[key] = [[expected_energy(msgs, p, rho, cpu)[0] for rho in LOSS_GRID]
                         for p in PAYLOAD_GRID]

    rng = random.Random(20260914)
    monte = {}
    for key in sel:
        r = sel[key]
        if r["m4_cpu_mJ_init"] is None:
            continue
        msgs = list(zip(r["msg_dirs"], r["msg_sizes"]))
        cpu = r["m4_cpu_mJ_init"]
        out = []
        for rho in LOSS_GRID:
            vals = [simulate(msgs, 81, rho, rng, cpu) for _ in range(TRIALS)]
            e = sum(v[0] for v in vals) / TRIALS
            a = sum(v[1] for v in vals) / TRIALS
            analytic, p_hs, nf = expected_energy(msgs, 81, rho, cpu)
            out.append({"rho": rho, "sim_mJ": e, "analytic_mJ": analytic,
                        "attempts": a, "p_handshake": p_hs, "frames": nf})
        monte[key] = out
        print(f"{key:24s}", [round(o["sim_mJ"], 2) for o in out])

    with open(os.path.join(RESULTS, "robustness.json"), "w") as f:
        json.dump({"payload_grid": PAYLOAD_GRID, "loss_grid": LOSS_GRID,
                   "arq_retries": ARQ_RETRIES,
                   "surfaces": surfaces, "monte_carlo": monte}, f)


if __name__ == "__main__":
    main()
