import json
import os
import statistics
import time

from common import RESULTS, Timer, protocol_suite

DURATION = float(os.environ.get("CLASP_DURATION", "2.5"))
LEVEL = os.environ.get("CLASP_LEVEL", "ML-KEM-768")


def main():
    os.makedirs(RESULTS, exist_ok=True)
    rows = []
    for cls, kwargs in protocol_suite(LEVEL):
        proto = cls(**kwargs)
        for _ in range(30):
            proto.session(Timer())
        n = 0
        t_resp = 0
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < DURATION:
            t = Timer()
            assert proto.session(t) is not None
            t_resp += t.acc["R"]
            n += 1
        wall = time.perf_counter() - t0
        resp_s = t_resp / 1e9
        rows.append({
            "name": cls.name,
            "suite": proto.label(),
            "sessions": n,
            "wall_s": wall,
            "responder_s": resp_s,
            "sessions_per_s_end_to_end": n / wall,
            "responder_throughput": n / resp_s if resp_s > 0 else 0.0,
        })
        print(f"{cls.name:22s} {proto.label():28s} e2e={n/wall:9.1f}/s  responder={n/resp_s:10.1f}/s")
        proto.free()
    with open(os.path.join(RESULTS, "throughput.json"), "w") as f:
        json.dump({"level": LEVEL, "rows": rows}, f, indent=1)


if __name__ == "__main__":
    main()
