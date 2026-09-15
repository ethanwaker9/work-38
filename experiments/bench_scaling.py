import json
import os
import statistics
import time

from common import RESULTS
from clasp.primitives import KEM, random_bytes, xof
from clasp.protocol import Device, Gateway, bootstrap, pseudonym

LEVEL = os.environ.get("CLASP_LEVEL", "ML-KEM-768")
POPULATIONS = [1000, 5000, 20000, 50000, 100000, 200000]
PROBES = 2000


def main():
    os.makedirs(RESULTS, exist_ok=True)
    kem = KEM(LEVEL)
    ek_g, dk_g = kem.keygen()
    ek_d, dk_d = kem.keygen()
    ok, chain0, _ = bootstrap(kem, ek_d, dk_d, ek_g, dk_g)
    assert ok
    gw = Gateway(kem, ek_g, dk_g)
    rows = []
    enrolled = 0
    for n in POPULATIONS:
        while enrolled < n:
            did = enrolled.to_bytes(8, "big")
            gw.enroll(did, ek_d, xof(b"seed", did, outlen=32))
            enrolled += 1
        probes = [pseudonym(xof(b"seed", (i * (n // PROBES + 1) % n).to_bytes(8, "big"), outlen=32))
                  for i in range(PROBES)]
        t = time.perf_counter_ns()
        hits = 0
        for p in probes:
            if gw.table.lookup(p) is not None:
                hits += 1
        dt = (time.perf_counter_ns() - t) / PROBES
        miss = [random_bytes(16) for _ in range(PROBES)]
        t = time.perf_counter_ns()
        for p in miss:
            gw.table.lookup(p)
        dtm = (time.perf_counter_ns() - t) / PROBES
        scan_n = min(n, 20000)
        target = xof(b"seed", (scan_n - 1).to_bytes(8, "big"), outlen=32)
        tp = pseudonym(target)
        t = time.perf_counter_ns()
        for _ in range(5):
            for i in range(scan_n):
                if pseudonym(xof(b"seed", i.to_bytes(8, "big"), outlen=32)) == tp:
                    break
        scan_ns = (time.perf_counter_ns() - t) / 5
        rows.append({
            "devices": n,
            "linear_scan_ns": scan_ns * (n / float(scan_n)),
            "linear_scan_measured_n": scan_n,
            "lookup_hit_ns": dt,
            "lookup_miss_ns": dtm,
            "hits": hits,
            "entries": len(gw.table),
            "table_bytes": gw.table.memory_bytes(16),
            "per_device_bytes": gw.state_bytes_per_device(),
        })
        print(f"n={n:7d} hit={dt:7.1f}ns miss={dtm:7.1f}ns entries={len(gw.table)}")
    gw.free()
    with open(os.path.join(RESULTS, "scaling.json"), "w") as f:
        json.dump({"level": LEVEL, "rows": rows}, f, indent=1)


if __name__ == "__main__":
    main()
