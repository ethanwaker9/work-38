import json
import os

from common import RESULTS, PROPERTIES

ORDER = [
    ("PQ-TLS 1.3", "ML-DSA"), ("PQ-TLS 1.3", "Falcon"), ("EDHOC (method 0)", "ML-DSA"),
    ("KEMTLS", None), ("KEMTLS-PDK", None), ("PQ-WireGuard", None),
    ("FSXY KEM-AKE", None), ("Kyber.AKE", None), ("EDHOC-KEM", None),
    ("TLS 1.3 PSK+KEM", None), ("CLASP-0 (enrolment)", None), ("CLASP", None),
]

TEXNAME = {
    ("PQ-TLS 1.3", "ML-DSA"): "PQ-TLS 1.3 with ML-DSA",
    ("PQ-TLS 1.3", "Falcon"): "PQ-TLS 1.3 with Falcon",
    ("EDHOC (method 0)", "ML-DSA"): "EDHOC method 0 with ML-DSA",
    ("KEMTLS", None): "KEMTLS",
    ("KEMTLS-PDK", None): "KEMTLS-PDK",
    ("PQ-WireGuard", None): "PQ-WireGuard",
    ("FSXY KEM-AKE", None): "FSXY",
    ("Kyber.AKE", None): "Kyber.AKE",
    ("EDHOC-KEM", None): "EDHOC-KEM",
    ("TLS 1.3 PSK+KEM", None): "TLS 1.3 PSK with KEM",
    ("CLASP-0 (enrolment)", None): "CLASP-0 (enrolment)",
    ("CLASP", None): "CLASP (this work)",
}

VENUE = {
    "PQ-TLS 1.3": "RFC 8446",
    "EDHOC (method 0)": "RFC 9528",
    "KEMTLS": "CCS 2020",
    "KEMTLS-PDK": "ESORICS 2021",
    "PQ-WireGuard": "S\\&P 2021",
    "FSXY KEM-AKE": "AsiaCCS 2013",
    "Kyber.AKE": "EuroS\\&P 2018",
    "EDHOC-KEM": "USENIX Sec. 2023",
    "TLS 1.3 PSK+KEM": "RFC 8446",
    "CLASP-0 (enrolment)": "this work",
    "CLASP": "this work",
}


def select(rows, name, sigfam):
    for r in rows:
        if r["name"] != name:
            continue
        if sigfam is None and not r["sig"]:
            return r
        if sigfam and r["sig"] and r["sig"].startswith(sigfam):
            return r
    raise KeyError((name, sigfam))


def num(v, digits=1):
    return "---" if v is None else f"{v:.{digits}f}"


def mark(b):
    return "\\cmark" if b else "\\xmark"


def table_main(hs):
    rows = hs["ML-KEM-768"]
    out = []
    for key in ORDER:
        r = select(rows, *key)
        p = PROPERTIES[r["name"]]
        cyc = "---" if r["m4_cycles_init"] is None else f"{r['m4_cycles_init']/1e6:.2f}"
        stk = "---" if r["m4_stack_init"] is None else f"{r['m4_stack_init']/1024.0:.1f}"
        out.append(
            f"{TEXNAME[key]} & {VENUE[r['name']]} & {r['flows']} & {r['bytes_total']} & "
            f"{r['links']['802.15.4']['frames']} & {r['links']['IPv6 min']['frames']} & "
            f"{num(r['asym_init_us'])} & {cyc} & {stk} & "
            f"{mark(p['mauth'])} & {mark(p['fs'])} & {mark(p['anchored'])} & "
            f"{mark(p['nofresh'])} & {mark(p['twofactor'])} \\\\")
    return "\n".join(out)


def table_sizes(hs):
    out = []
    for level in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        for key in ORDER:
            r = select(hs[level], *key)
            out.append(f"{level.replace('ML-KEM-', '')} & {TEXNAME[key]} & {r['bytes_up']} & "
                       f"{r['bytes_dn']} & {r['bytes_total']} & {num(r['asym_init_us'])} & "
                       f"{num(r['asym_resp_us'])} & {num(r['t_init_us'])} & "
                       f"{num(r['t_resp_us'])} \\\\")
        out.append("\\midrule")
    return "\n".join(out)


def table_ops(hs):
    out = []
    for key in ORDER:
        r = select(hs["ML-KEM-768"], *key)
        oi, orr = r["ops"]["I"], r["ops"]["R"]
        g = lambda o, n: o.get(n, 0)
        out.append(
            f"{TEXNAME[key]} & {g(oi,'keygen')} & {g(oi,'encaps')} & {g(oi,'decaps')} & "
            f"{g(oi,'sign')} & {g(oi,'verify')} & {g(orr,'keygen')} & {g(orr,'encaps')} & "
            f"{g(orr,'decaps')} & {g(orr,'sign')} & {g(orr,'verify')} \\\\")
    return "\n".join(out)


def table_energy(rb):
    out = []
    for k, rows in rb["monte_carlo"].items():
        cells = " & ".join(f"{r['sim_mJ']:.2f}" for r in rows)
        out.append(f"{k} & {rows[0]['frames']} & {cells} \\\\")
    out.append("%% pairs at rho=0 and rho=0.2")
    for k, rows in rb["monte_carlo"].items():
        out.append(f"%% {k}: {rows[0]['sim_mJ']:.2f} / {rows[-1]['sim_mJ']:.2f}")
    return "\n".join(out) + "\n%% loss grid: " + " ".join(str(g) for g in rb["loss_grid"])


def table_scaling(sc):
    out = []
    for r in sc["rows"]:
        out.append(f"{r['devices']} & {r['lookup_hit_ns']:.0f} & {r['lookup_miss_ns']:.0f} & "
                   f"{r['linear_scan_ns']/1e6:.2f} & {r['table_bytes']/1024.0:.0f} \\\\")
    return "\n".join(out)


def table_state(hs):
    out = []
    for key in ORDER:
        r = select(hs["ML-KEM-768"], *key)
        out.append(f"{TEXNAME[key]} & {r['device_state_bytes']} & "
                   f"{r['gateway_state_per_device']} & "
                   f"{'---' if r['m4_stack_init'] is None else r['m4_stack_init']} & "
                   f"{'---' if r['m4_stack_resp'] is None else r['m4_stack_resp']} \\\\")
    return "\n".join(out)


def table_throughput(tp):
    out = []
    for key in ORDER:
        for r in tp["rows"]:
            if r["name"] != key[0]:
                continue
            if key[1] is None and "+" in r["suite"]:
                continue
            if key[1] and key[1] not in r["suite"]:
                continue
            out.append(f"{TEXNAME[key]} & {r['responder_throughput']:.0f} & "
                       f"{r['sessions_per_s_end_to_end']:.0f} \\\\")
            break
    return "\n".join(out)


def main():
    def load(n):
        with open(os.path.join(RESULTS, n)) as f:
            return json.load(f)
    hs, rb, sc, tp = load("handshake.json"), load("robustness.json"), \
        load("scaling.json"), load("throughput.json")
    blocks = {
        "main": table_main(hs),
        "sizes": table_sizes(hs),
        "ops": table_ops(hs),
        "energy": table_energy(rb),
        "scaling": table_scaling(sc),
        "throughput": table_throughput(tp),
        "state": table_state(hs),
    }
    with open(os.path.join(RESULTS, "tables.tex"), "w") as f:
        for k, v in blocks.items():
            f.write("%%%% " + k + "\n" + v + "\n\n")
    print(blocks["main"])
    print()
    print(blocks["ops"])


if __name__ == "__main__":
    main()
