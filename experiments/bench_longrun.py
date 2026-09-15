import json
import os
import time

from common import RESULTS
from clasp.primitives import KEM, random_bytes, xof
from clasp.protocol import Device, Gateway, bootstrap

LEVEL = os.environ.get("CLASP_LEVEL", "ML-KEM-768")
EPOCHS = int(os.environ.get("CLASP_EPOCHS", "50000"))
DEVICES = int(os.environ.get("CLASP_DEVICES", "50"))


def main():
    os.makedirs(RESULTS, exist_ok=True)
    kem = KEM(LEVEL)
    ek_g, dk_g = kem.keygen()
    gw = Gateway(kem, ek_g, dk_g)
    devices = []
    for i in range(DEVICES):
        ek_d, dk_d = kem.keygen()
        ok, chain0, _ = bootstrap(kem, ek_d, dk_d, ek_g, dk_g)
        assert ok
        did = i.to_bytes(8, "big")
        gw.enroll(did, ek_d, chain0)
        devices.append(Device(kem, ek_g, ek_d, dk_d, chain0, did))

    seen = set()
    collisions = 0
    completed = 0
    t0 = time.perf_counter()
    for e in range(EPOCHS):
        d = devices[e % DEVICES]
        m1 = d.message1()
        p = m1[:16]
        if p in seen:
            collisions += 1
        seen.add(p)
        r = gw.process_message1(m1)
        assert r is not None, e
        h, m2 = r
        r2 = d.process_message2(m2)
        assert r2 is not None, e
        t3, k_d = r2
        k_g = gw.process_message3(h, t3)
        assert k_g == k_d, e
        completed += 1
    wall = time.perf_counter() - t0
    slots = [len(rec["slots"]) for rec in gw.devices.values()]
    out = {
        "level": LEVEL,
        "devices": DEVICES,
        "epochs": EPOCHS,
        "completed": completed,
        "distinct_pseudonyms": len(seen),
        "pseudonym_collisions": collisions,
        "wall_s": wall,
        "sessions_per_s": EPOCHS / wall,
        "max_gateway_slots": max(slots),
        "gateway_state_per_device": gw.state_bytes_per_device(),
        "device_state_bytes": devices[0].state_bytes(),
    }
    print(out)
    for d in devices:
        d.free()
    gw.free()
    with open(os.path.join(RESULTS, "longrun.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
