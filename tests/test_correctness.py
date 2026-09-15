import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from clasp.primitives import KEM
from clasp.protocol import Device, Gateway, bootstrap
from clasp.baselines import (
    Timer, ClaspSession, ClaspBootstrap, PQTLS13, KEMTLS, KEMTLSPDK,
    PQWireGuard, FSXY, KyberAKE, EDHOCSig, EDHOCKem, TLS13PSKKEM,
)

LEVELS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


@pytest.mark.parametrize("level", LEVELS)
def test_clasp_many_epochs(level):
    kem = KEM(level)
    ek_d, dk_d = kem.keygen()
    ek_g, dk_g = kem.keygen()
    ok, chain0, msgs = bootstrap(kem, ek_d, dk_d, ek_g, dk_g)
    assert ok
    gw = Gateway(kem, ek_g, dk_g)
    gw.enroll(b"device01", ek_d, chain0)
    dev = Device(kem, ek_g, ek_d, dk_d, chain0, b"device01")
    keys = set()
    for _ in range(200):
        m1 = dev.message1()
        handle, m2 = gw.process_message1(m1)
        m3, k_dev = dev.process_message2(m2)
        k_gw = gw.process_message3(handle, m3)
        assert k_gw == k_dev
        assert k_dev not in keys
        keys.add(k_dev)
    dev.free()
    gw.free()


@pytest.mark.parametrize("level", LEVELS)
def test_message_sizes(level):
    kem = KEM(level)
    proto = ClaspSession(level)
    msgs = proto.session(Timer())
    sizes = [len(m) for _, m in msgs]
    assert sizes == [16 + kem.ct_len + 16, kem.ct_len + 16, 16]
    assert sum(sizes) == 2 * kem.ct_len + 64
    proto.free()


@pytest.mark.parametrize("cls,kwargs", [
    (PQTLS13, {"kem_name": "ML-KEM-768", "sig_name": "ML-DSA-44"}),
    (PQTLS13, {"kem_name": "ML-KEM-768", "sig_name": "Falcon-padded-512"}),
    (EDHOCSig, {"kem_name": "ML-KEM-768", "sig_name": "ML-DSA-44"}),
    (KEMTLS, {"kem_name": "ML-KEM-768"}),
    (KEMTLSPDK, {"kem_name": "ML-KEM-768"}),
    (PQWireGuard, {"kem_name": "ML-KEM-768"}),
    (FSXY, {"kem_name": "ML-KEM-768"}),
    (KyberAKE, {"kem_name": "ML-KEM-768"}),
    (EDHOCKem, {"kem_name": "ML-KEM-768"}),
    (TLS13PSKKEM, {"kem_name": "ML-KEM-768"}),
    (ClaspBootstrap, {"kem_name": "ML-KEM-768"}),
    (ClaspSession, {"kem_name": "ML-KEM-768"}),
])
def test_baseline_runs(cls, kwargs):
    proto = cls(**kwargs)
    for _ in range(5):
        assert proto.session(Timer()) is not None
    proto.free()


def test_clasp_is_smallest():
    level = "ML-KEM-768"
    others = [PQTLS13(level, "ML-DSA-44"), PQTLS13(level, "Falcon-padded-512"),
              EDHOCSig(level, "ML-DSA-44"), KEMTLS(level), KEMTLSPDK(level),
              PQWireGuard(level), FSXY(level), KyberAKE(level), EDHOCKem(level),
              TLS13PSKKEM(level)]
    clasp = ClaspSession(level)
    total = sum(len(m) for _, m in clasp.session(Timer()))
    for p in others:
        t = sum(len(m) for _, m in p.session(Timer()))
        assert total < t, p.name
        p.free()
    clasp.free()
