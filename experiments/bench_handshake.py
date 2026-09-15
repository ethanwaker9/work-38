import json
import os
import statistics
import time

from common import (
    RESULTS, Timer, protocol_suite, cpu_cycles, peak_stack, frames, LINKS,
    E_TX_PER_BYTE, E_RX_PER_BYTE, E_PER_CYCLE, KEM_SIZES, SIG_SIZES,
    primitive_costs, state_profile,
)

WARMUP = 40
ITERS = int(os.environ.get("CLASP_ITERS", "1500"))


PRIM = None


def asym_time(ops, kem_name, sig_name):
    total = 0.0
    for k, n in ops.items():
        if k in ("keygen", "encaps", "decaps"):
            total += n * PRIM[kem_name][k]
        elif k in ("sign", "verify"):
            total += n * PRIM[sig_name][k]
    return total


def measure(cls, kwargs):
    proto = cls(**kwargs)
    for _ in range(WARMUP):
        proto.reset_ops()
        assert proto.session(Timer()) is not None
    proto.reset_ops()
    t = Timer()
    msgs = proto.session(t)
    ops = {"I": dict(proto.ops["I"]), "R": dict(proto.ops["R"])}
    sizes = [len(m) for _, m in msgs]
    dirs = [d for d, _ in msgs]
    up = sum(len(m) for d, m in msgs if d == "I")
    dn = sum(len(m) for d, m in msgs if d == "R")

    ti, tr, tt = [], [], []
    for _ in range(ITERS):
        proto.reset_ops()
        t = Timer()
        s = time.perf_counter_ns()
        r = proto.session(t)
        e = time.perf_counter_ns()
        assert r is not None
        ti.append(t.acc["I"] / 1000.0)
        tr.append(t.acc["R"] / 1000.0)
        tt.append((e - s) / 1000.0)
    proto.free()

    kem_name = kwargs.get("kem_name")
    sig_name = kwargs.get("sig_name")
    cyc_i = cpu_cycles(ops["I"], kem_name, sig_name)
    cyc_r = cpu_cycles(ops["R"], kem_name, sig_name)
    stack_i = peak_stack(ops["I"], kem_name, sig_name)
    stack_r = peak_stack(ops["R"], kem_name, sig_name)

    energy = {}
    for link, payload in LINKS.items():
        f_up = sum(frames(len(m), payload) for d, m in msgs if d == "I")
        f_dn = sum(frames(len(m), payload) for d, m in msgs if d == "R")
        b_up = f_up * payload
        b_dn = f_dn * payload
        energy[link] = {
            "frames_up": f_up,
            "frames_dn": f_dn,
            "frames": f_up + f_dn,
            "radio_mJ": (b_up * E_TX_PER_BYTE + b_dn * E_RX_PER_BYTE) * 1e3,
        }

    dev_state, gw_state = state_profile(cls.name, kem_name, sig_name)

    return {
        "name": cls.name,
        "venue": cls.venue,
        "year": cls.year,
        "family": cls.family,
        "suite": proto.label() if hasattr(proto, "label") else kem_name,
        "kem": kem_name,
        "sig": sig_name,
        "flows": len(msgs),
        "msg_sizes": sizes,
        "msg_dirs": dirs,
        "bytes_up": up,
        "bytes_dn": dn,
        "bytes_total": up + dn,
        "ops": ops,
        "t_init_us": statistics.mean(ti),
        "t_init_sd": statistics.pstdev(ti),
        "t_resp_us": statistics.mean(tr),
        "t_resp_sd": statistics.pstdev(tr),
        "t_total_us": statistics.mean(tt),
        "t_total_sd": statistics.pstdev(tt),
        "t_init_med": statistics.median(ti),
        "t_resp_med": statistics.median(tr),
        "m4_cycles_init": cyc_i,
        "m4_cycles_resp": cyc_r,
        "m4_stack_init": stack_i,
        "m4_stack_resp": stack_r,
        "m4_cpu_mJ_init": cyc_i * E_PER_CYCLE * 1e3 if cyc_i is not None else None,
        "m4_cpu_mJ_resp": cyc_r * E_PER_CYCLE * 1e3 if cyc_r is not None else None,
        "asym_init_us": asym_time(ops["I"], kem_name, sig_name),
        "asym_resp_us": asym_time(ops["R"], kem_name, sig_name),
        "device_state_bytes": dev_state,
        "gateway_state_per_device": gw_state,
        "links": energy,
    }


def main():
    global PRIM
    os.makedirs(RESULTS, exist_ok=True)
    PRIM = primitive_costs()
    with open(os.path.join(RESULTS, "primitives.json"), "w") as f:
        json.dump(PRIM, f, indent=1)
    out = {}
    for level in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        rows = []
        for cls, kwargs in protocol_suite(level):
            r = measure(cls, kwargs)
            rows.append(r)
            print(f"[{level}] {r['name']:22s} {r['suite']:30s} tot={r['bytes_total']:6d} "
                  f"tI={r['t_init_us']:9.1f}us tR={r['t_resp_us']:9.1f}us "
                  f"aI={r['asym_init_us']:8.1f} cycI={r['m4_cycles_init']}")
        out[level] = rows
    with open(os.path.join(RESULTS, "handshake.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
