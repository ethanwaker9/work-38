import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from clasp.primitives import KEM, random_bytes, xof, mac, PersistentDecapsulator
from clasp.protocol import (
    Device, Gateway, bootstrap, pseudonym, bind_key, schedule,
    transcript_hash, message1_hash, L_BIND, L_G, L_D,
)

LEVEL = "ML-KEM-768"


def fresh():
    kem = KEM(LEVEL)
    ek_d, dk_d = kem.keygen()
    ek_g, dk_g = kem.keygen()
    ok, chain0, _ = bootstrap(kem, ek_d, dk_d, ek_g, dk_g)
    assert ok
    gw = Gateway(kem, ek_g, dk_g)
    gw.enroll(b"device01", ek_d, chain0)
    dev = Device(kem, ek_g, ek_d, dk_d, chain0, b"device01")
    return kem, dev, gw, chain0, ek_d, dk_d, ek_g, dk_g


def run(dev, gw):
    m1 = dev.message1()
    out = gw.process_message1(m1)
    if out is None:
        return None
    handle, m2 = out
    r = dev.process_message2(m2)
    if r is None:
        return None
    m3, k = r
    return gw.process_message3(handle, m3), k


def test_unknown_pseudonym_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    forged = random_bytes(16) + m1[16:]
    assert gw.process_message1(forged) is None


def test_tag1_tampering_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = bytearray(dev.message1())
    m1[-1] ^= 0x01
    assert gw.process_message1(bytes(m1)) is None


def test_ciphertext_tampering_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = bytearray(dev.message1())
    m1[20] ^= 0x01
    assert gw.process_message1(bytes(m1)) is None


def test_msg2_tampering_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    handle, m2 = gw.process_message1(m1)
    m2 = bytearray(m2)
    m2[-1] ^= 0x01
    assert dev.process_message2(bytes(m2)) is None


def test_msg3_tampering_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    handle, m2 = gw.process_message1(m1)
    m3, k = dev.process_message2(m2)
    bad = bytearray(m3)
    bad[0] ^= 0x01
    assert gw.process_message3(handle, bytes(bad)) is None


def test_replay_of_message1_is_idempotent():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    h1, a = gw.process_message1(m1)
    h2, b = gw.process_message1(m1)
    assert a == b and h1 == h2
    m3, k = dev.process_message2(a)
    assert gw.process_message3(h1, m3) == k
    assert gw.process_message1(m1) is None


def test_replay_after_completion_rejected():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    handle, m2 = gw.process_message1(m1)
    m3, k = dev.process_message2(m2)
    assert gw.process_message3(handle, m3) == k
    assert gw.process_message1(m1) is None


def test_recovery_after_lost_message2():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    handle, m2 = gw.process_message1(m1)
    handle2, m2b = gw.process_message1(m1)
    assert m2 == m2b
    m3, k = dev.process_message2(m2b)
    assert gw.process_message3(handle2, m3) == k
    assert run(dev, gw)[0] is not None


def test_recovery_after_lost_message3():
    kem, dev, gw, *_ = fresh()
    m1 = dev.message1()
    handle, m2 = gw.process_message1(m1)
    m3, k = dev.process_message2(m2)
    assert len(gw.devices[b"device01"]["slots"]) == 2
    a, b = run(dev, gw)
    assert a == b
    assert len(gw.devices[b"device01"]["slots"]) == 1


def test_state_compromise_does_not_allow_device_impersonation():
    kem, dev, gw, chain0, ek_d, dk_d, ek_g, dk_g = fresh()
    stolen = dev.chain
    p = pseudonym(stolen)
    ss1, ct1 = kem.encaps(ek_g)
    tag1 = mac(bind_key(stolen), L_BIND, p, ct1)
    m1 = p + ct1 + tag1
    handle, m2 = gw.process_message1(m1)
    ct2 = m2[: kem.ct_len]
    th = transcript_hash(gw.devices[b"device01"]["binder"], message1_hash(m1), ct2)
    forged = b""
    for guess in [b"\x00" * 32, random_bytes(32)]:
        _, k_d, _, _ = schedule(stolen, ss1, guess, th)
        forged = mac(k_d, L_D, th)
        assert gw.process_message3(handle, forged) is None


def test_state_compromise_heals_after_one_epoch():
    kem, dev, gw, chain0, ek_d, dk_d, ek_g, dk_g = fresh()
    stolen = dev.chain
    assert run(dev, gw)[0] is not None
    assert dev.chain != stolen
    p_old = pseudonym(stolen)
    assert gw.table.lookup(p_old) is None


def test_key_compromise_impersonation_resistance():
    kem, dev, gw, chain0, ek_d, dk_d, ek_g, dk_g = fresh()
    m1 = dev.message1()
    ss2, ct2 = kem.encaps(ek_d)
    h1 = message1_hash(m1)
    binder = gw.devices[b"device01"]["binder"]
    th = transcript_hash(binder, h1, ct2)
    k_g, _, _, _ = schedule(dev.chain, random_bytes(32), ss2, th)
    forged_m2 = ct2 + mac(k_g, L_G, th)
    assert dev.process_message2(forged_m2) is None


def test_forward_secrecy_chain_is_one_way():
    kem, dev, gw, chain0, *_ = fresh()
    seen = [dev.chain]
    for _ in range(6):
        assert run(dev, gw)[0] is not None
        seen.append(dev.chain)
    assert len(set(seen)) == len(seen)
    assert chain0 not in seen[1:]


def test_pseudonyms_are_unlinkable_across_epochs():
    kem, dev, gw, *_ = fresh()
    ps = []
    for _ in range(64):
        m1 = dev.message1()
        ps.append(m1[:16])
        handle, m2 = gw.process_message1(m1)
        m3, k = dev.process_message2(m2)
        gw.process_message3(handle, m3)
    assert len(set(ps)) == 64
    bits = sum(bin(int.from_bytes(p, "big")).count("1") for p in ps)
    assert 0.40 < bits / (64 * 128) < 0.60


def test_distinct_devices_are_isolated():
    kem = KEM(LEVEL)
    ek_g, dk_g = kem.keygen()
    gw = Gateway(kem, ek_g, dk_g)
    devs = []
    for i in range(4):
        ek_d, dk_d = kem.keygen()
        ok, c0, _ = bootstrap(kem, ek_d, dk_d, ek_g, dk_g)
        did = i.to_bytes(8, "big")
        gw.enroll(did, ek_d, c0)
        devs.append(Device(kem, ek_g, ek_d, dk_d, c0, did))
    for d in devs:
        assert run(d, gw)[0] is not None
    keys = set()
    for d in devs:
        r = run(d, gw)
        keys.add(r[1])
    assert len(keys) == 4
