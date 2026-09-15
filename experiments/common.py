import os
import sys
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clasp.baselines import (
    Timer, ClaspSession, ClaspBootstrap, PQTLS13, KEMTLS, KEMTLSPDK,
    PQWireGuard, FSXY, KyberAKE, EDHOCSig, EDHOCKem, TLS13PSKKEM,
)

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
FIGURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "figures")

M4_CYCLES = {
    "ML-KEM-512": {"keygen": 392423, "encaps": 390881, "decaps": 428167},
    "ML-KEM-768": {"keygen": 642096, "encaps": 658754, "decaps": 707827},
    "ML-KEM-1024": {"keygen": 1018976, "encaps": 1031565, "decaps": 1094008},
    "ML-DSA-44": {"keygen": 1426025, "sign": 3943121, "verify": 1421623},
    "ML-DSA-65": {"keygen": 2516006, "sign": 6193171, "verify": 2415944},
    "ML-DSA-87": {"keygen": 4275859, "sign": 7947380, "verify": 4193104},
}

M4_STACK = {
    "ML-KEM-512": {"keygen": 4372, "encaps": 5436, "decaps": 5412},
    "ML-KEM-768": {"keygen": 5396, "encaps": 6468, "decaps": 6452},
    "ML-KEM-1024": {"keygen": 6436, "encaps": 7500, "decaps": 7484},
    "ML-DSA-44": {"keygen": 38296, "sign": 44816, "verify": 8912},
    "ML-DSA-65": {"keygen": 60824, "sign": 68872, "verify": 9888},
    "ML-DSA-87": {"keygen": 97688, "sign": 107892, "verify": 12060},
}

KEM_SIZES = {
    "ML-KEM-512": {"ek": 800, "dk": 1632, "ct": 768},
    "ML-KEM-768": {"ek": 1184, "dk": 2400, "ct": 1088},
    "ML-KEM-1024": {"ek": 1568, "dk": 3168, "ct": 1568},
    "Classic-McEliece-460896": {"ek": 524160, "dk": 13608, "ct": 156},
}

SIG_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
    "Falcon-padded-512": {"pk": 897, "sk": 1281, "sig": 666},
    "Falcon-padded-1024": {"pk": 1793, "sk": 2305, "sig": 1280},
}

LINKS = {
    "802.15.4": 81,
    "BLE 5": 244,
    "LoRaWAN": 222,
    "NB-IoT": 1358,
    "IPv6 min": 1232,
}

VOLTAGE = 3.0
I_TX = 24.0e-3
I_RX = 20.0e-3
I_CPU = 10.0e-3
BITRATE = 250e3
CPU_HZ = 64e6

E_TX_PER_BYTE = 8.0 / BITRATE * VOLTAGE * I_TX
E_RX_PER_BYTE = 8.0 / BITRATE * VOLTAGE * I_RX
E_PER_CYCLE = VOLTAGE * I_CPU / CPU_HZ


def frames(nbytes, payload):
    return int(math.ceil(nbytes / float(payload)))


def cpu_cycles(ops, kem_name, sig_name):
    total = 0
    for k, n in ops.items():
        if k in ("keygen", "encaps", "decaps"):
            total += n * M4_CYCLES[kem_name][k]
        elif k in ("sign", "verify"):
            if sig_name not in M4_CYCLES:
                return None
            total += n * M4_CYCLES[sig_name][k]
    return total


def peak_stack(ops, kem_name, sig_name):
    best = 0
    for k, n in ops.items():
        if n == 0:
            continue
        if k in ("keygen", "encaps", "decaps"):
            best = max(best, M4_STACK[kem_name][k])
        elif k in ("sign", "verify"):
            if sig_name not in M4_STACK:
                return None
            best = max(best, M4_STACK[sig_name][k])
    return best


def protocol_suite(level="ML-KEM-768"):
    sig = {"ML-KEM-512": "ML-DSA-44", "ML-KEM-768": "ML-DSA-44", "ML-KEM-1024": "ML-DSA-87"}[level]
    fal = {"ML-KEM-512": "Falcon-padded-512", "ML-KEM-768": "Falcon-padded-512",
           "ML-KEM-1024": "Falcon-padded-1024"}[level]
    return [
        (PQTLS13, {"kem_name": level, "sig_name": sig}),
        (PQTLS13, {"kem_name": level, "sig_name": fal}),
        (EDHOCSig, {"kem_name": level, "sig_name": sig}),
        (KEMTLS, {"kem_name": level}),
        (KEMTLSPDK, {"kem_name": level}),
        (PQWireGuard, {"kem_name": level}),
        (FSXY, {"kem_name": level}),
        (KyberAKE, {"kem_name": level}),
        (EDHOCKem, {"kem_name": level}),
        (TLS13PSKKEM, {"kem_name": level}),
        (ClaspBootstrap, {"kem_name": level}),
        (ClaspSession, {"kem_name": level}),
    ]


STATE_MODEL = {
    "PQ-TLS 1.3": ("sig", 0, 0),
    "EDHOC (method 0)": ("sig", 0, 0),
    "KEMTLS": ("kem", 0, 0),
    "KEMTLS-PDK": ("kem", 0, 0),
    "PQ-WireGuard": ("kem", 0, 0),
    "FSXY KEM-AKE": ("kem", 0, 0),
    "Kyber.AKE": ("kem", 0, 0),
    "EDHOC-KEM": ("kem", 0, 0),
    "TLS 1.3 PSK+KEM": ("psk", 32, 64),
    "CLASP-0 (enrolment)": ("kem", 0, 0),
    "CLASP": ("kem", 32, 48),
}


def state_profile(name, kem_name, sig_name):
    kind, dev_extra, gw_extra = STATE_MODEL[name]
    if kind == "sig":
        dev = SIG_SIZES[sig_name]["sk"] + SIG_SIZES[sig_name]["pk"]
        gw = SIG_SIZES[sig_name]["pk"]
    elif kind == "kem":
        dev = KEM_SIZES[kem_name]["dk"] + KEM_SIZES[kem_name]["ek"]
        gw = KEM_SIZES[kem_name]["ek"]
    else:
        dev = 0
        gw = 0
    return dev + dev_extra, gw + gw_extra


PROPERTIES = {
    "PQ-TLS 1.3": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "EDHOC (method 0)": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "KEMTLS": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "KEMTLS-PDK": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "PQ-WireGuard": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "FSXY KEM-AKE": dict(mauth=0, fs=1, anchored=1, nofresh=0, twofactor=0),
    "Kyber.AKE": dict(mauth=0, fs=1, anchored=1, nofresh=0, twofactor=0),
    "EDHOC-KEM": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "TLS 1.3 PSK+KEM": dict(mauth=1, fs=1, anchored=0, nofresh=0, twofactor=0),
    "CLASP-0 (enrolment)": dict(mauth=1, fs=1, anchored=1, nofresh=0, twofactor=0),
    "CLASP": dict(mauth=1, fs=1, anchored=1, nofresh=1, twofactor=1),
}


def primitive_costs(iters=600, batches=9):
    import time
    from clasp.primitives import KEM, SIG, PersistentSigner, PersistentDecapsulator

    def timed(fn, n):
        t = time.perf_counter_ns()
        for _ in range(n):
            fn()
        return (time.perf_counter_ns() - t) / n / 1000.0

    def stable(fn, n):
        for _ in range(max(20, n // 10)):
            fn()
        return min(timed(fn, n) for _ in range(batches))

    out = {}
    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        kem = KEM(name)
        ek, dk = kem.keygen()
        dec = PersistentDecapsulator(name, dk)
        _, ct = kem.encaps(ek)
        out[name] = {
            "keygen": stable(lambda: kem.eph_keygen(), iters),
            "encaps": stable(lambda: kem.encaps(ek), iters),
            "decaps": stable(lambda: dec.decaps(ct), iters),
        }
        dec.free()
        kem.free()
    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-padded-512",
                 "Falcon-padded-1024"]:
        sig = SIG(name)
        pk, sk = sig.keygen()
        signer = PersistentSigner(name, sk)
        msg = b"benchmark-message" * 2
        sg = signer.sign(msg)
        out[name] = {
            "sign": stable(lambda: signer.sign(msg), max(120, iters // 4)),
            "verify": stable(lambda: sig.verify(pk, msg, sg), max(120, iters // 4)),
            "keygen": 0.0,
        }
        signer.free()
        sig.free()
    return out
