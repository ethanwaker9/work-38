import time
from .primitives import (
    KEM, SIG, PersistentDecapsulator, PersistentSigner, xof, mac, ct_eq,
    random_bytes, TAG_LEN, PSEUDONYM_LEN,
)
from .protocol import Device, Gateway, BootstrapContext, bootstrap, pseudonym

NONCE = 32
FIN = 32


class Timer:
    def __init__(self):
        self.acc = {"I": 0, "R": 0}
        self._role = None
        self._t0 = 0

    def start(self, role):
        self._role = role
        self._t0 = time.perf_counter_ns()

    def stop(self):
        self.acc[self._role] += time.perf_counter_ns() - self._t0


class Protocol:
    name = "abstract"
    venue = "-"
    year = 0
    family = "-"
    flows = 0
    rtt = 0.0

    def __init__(self, kem_name="ML-KEM-768", sig_name=None, static_kem_name=None):
        self.kem_name = kem_name
        self.sig_name = sig_name
        self.static_kem_name = static_kem_name or kem_name
        self.kem = KEM(kem_name)
        self.skem = KEM(self.static_kem_name) if self.static_kem_name != kem_name else self.kem
        self.sig = SIG(sig_name) if sig_name else None
        self.ops = {"I": {}, "R": {}}
        self.setup()

    def _op(self, role, kind, n=1):
        self.ops[role][kind] = self.ops[role].get(kind, 0) + n

    def reset_ops(self):
        self.ops = {"I": {}, "R": {}}

    def setup(self):
        raise NotImplementedError

    def session(self, timer):
        raise NotImplementedError

    def label(self):
        s = self.kem_name
        if self.static_kem_name != self.kem_name:
            s = self.static_kem_name + "/" + self.kem_name
        if self.sig_name:
            s += "+" + self.sig_name
        return s

    def free(self):
        pass


class ClaspSession(Protocol):
    name = "CLASP"
    venue = "this work"
    year = 2026
    family = "KEM"
    flows = 3
    rtt = 1.0

    def setup(self):
        self.ek_d, dk_d = self.kem.keygen()
        self.ek_g, dk_g = self.kem.keygen()
        ok, chain0, _ = bootstrap(self.kem, self.ek_d, dk_d, self.ek_g, dk_g)
        self.gateway = Gateway(self.kem, self.ek_g, dk_g)
        self.gateway.enroll(b"device01", self.ek_d, chain0)
        self.device = Device(self.kem, self.ek_g, self.ek_d, dk_d, chain0, b"device01")

    def session(self, timer):
        timer.start("I")
        m1 = self.device.message1()
        timer.stop()
        self._op("I", "encaps")
        timer.start("R")
        out = self.gateway.process_message1(m1)
        timer.stop()
        if out is None:
            return None
        handle, m2 = out
        self._op("R", "decaps")
        self._op("R", "encaps")
        timer.start("I")
        res = self.device.process_message2(m2)
        timer.stop()
        if res is None:
            return None
        m3, key_i = res
        self._op("I", "decaps")
        timer.start("R")
        key_r = self.gateway.process_message3(handle, m3)
        timer.stop()
        if key_r is None or key_r != key_i:
            return None
        return [("I", m1), ("R", m2), ("I", m3)]

    def free(self):
        self.device.free()
        self.gateway.free()


class ClaspBootstrap(Protocol):
    name = "CLASP-0 (enrolment)"
    venue = "this work"
    year = 2026
    family = "KEM"
    flows = 3
    rtt = 1.0

    def setup(self):
        self.ek_d, self.dk_d = self.kem.keygen()
        self.ek_g, self.dk_g = self.kem.keygen()
        self.ctx = BootstrapContext(self.kem, self.ek_d, self.dk_d, self.ek_g, self.dk_g)

    def session(self, timer):
        timer.start("I")
        m1 = self.ctx.phase1()
        timer.stop()
        self._op("I", "keygen")
        self._op("I", "encaps", 1)
        timer.start("R")
        m2 = self.ctx.phase2(m1)
        timer.stop()
        self._op("R", "decaps", 1)
        self._op("R", "encaps", 2)
        timer.start("I")
        ok, chain0, m3 = self.ctx.phase3(m1, m2)
        timer.stop()
        self._op("I", "decaps", 2)
        timer.start("R")
        ok = ok and self.ctx.verify_final(m3, chain0)
        timer.stop()
        if not ok:
            return None
        return [("I", m1), ("R", m2), ("I", m3)]

    def free(self):
        self.ctx.free()


class PQTLS13(Protocol):
    name = "PQ-TLS 1.3"
    venue = "RFC 8446"
    year = 2018
    family = "SIG"
    flows = 3
    rtt = 1.0

    def setup(self):
        self.pk_s, sk_s = self.sig.keygen()
        self.pk_c, sk_c = self.sig.keygen()
        self.signer_s = PersistentSigner(self.sig_name, sk_s)
        self.signer_c = PersistentSigner(self.sig_name, sk_c)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        n_c = random_bytes(NONCE)
        m1 = ek_e + n_c
        timer.stop()
        self._op("I", "keygen")

        timer.start("R")
        ss, ct = self.kem.encaps(ek_e)
        n_s = random_bytes(NONCE)
        th1 = xof(b"tls-th", m1, ct, n_s, outlen=32)
        sig_s = self.signer_s.sign(th1)
        hs = xof(b"tls-hs", ss, th1, outlen=64)
        fin_s = mac(hs[:32], b"sfin", th1, sig_s, taglen=FIN)
        m2 = ct + n_s + sig_s + fin_s
        timer.stop()
        self._op("R", "encaps")
        self._op("R", "sign")

        timer.start("I")
        ss_i = self.kem.eph_decaps(ct)
        th1_i = xof(b"tls-th", m1, ct, n_s, outlen=32)
        okv = self.sig.verify(self.pk_s, th1_i, sig_s)
        hs_i = xof(b"tls-hs", ss_i, th1_i, outlen=64)
        ok = okv and ct_eq(fin_s, mac(hs_i[:32], b"sfin", th1_i, sig_s, taglen=FIN))
        th2 = xof(b"tls-th2", th1_i, m2, outlen=32)
        sig_c = self.signer_c.sign(th2)
        fin_c = mac(hs_i[32:], b"cfin", th2, sig_c, taglen=FIN)
        key_i = xof(b"tls-key", hs_i, th2, outlen=32)
        m3 = sig_c + fin_c
        timer.stop()
        self._op("I", "decaps")
        self._op("I", "verify")
        self._op("I", "sign")

        timer.start("R")
        th2_r = xof(b"tls-th2", th1, m2, outlen=32)
        ok2 = self.sig.verify(self.pk_c, th2_r, sig_c)
        ok2 = ok2 and ct_eq(fin_c, mac(hs[32:], b"cfin", th2_r, sig_c, taglen=FIN))
        key_r = xof(b"tls-key", hs, th2_r, outlen=32)
        timer.stop()
        self._op("R", "verify")
        if not (ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", m3)]

    def free(self):
        self.signer_s.free()
        self.signer_c.free()


class KEMTLS(Protocol):
    name = "KEMTLS"
    venue = "CCS"
    year = 2020
    family = "KEM"
    flows = 5
    rtt = 2.0

    def setup(self):
        self.ek_s, dk_s = self.skem.keygen()
        self.ek_c, dk_c = self.skem.keygen()
        self.dec_s = PersistentDecapsulator(self.static_kem_name, dk_s)
        self.dec_c = PersistentDecapsulator(self.static_kem_name, dk_c)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        n_c = random_bytes(NONCE)
        m1 = ek_e + n_c
        timer.stop()
        self._op("I", "keygen")

        timer.start("R")
        ss_e, ct_e = self.kem.encaps(ek_e)
        n_s = random_bytes(NONCE)
        m2 = ct_e + n_s
        timer.stop()
        self._op("R", "encaps")

        timer.start("I")
        ss_e_i = self.kem.eph_decaps(ct_e)
        ss_s, ct_s = self.skem.encaps(self.ek_s)
        m3 = ct_s
        timer.stop()
        self._op("I", "decaps")
        self._op("I", "encaps")

        timer.start("R")
        ss_s_r = self.dec_s.decaps(ct_s)
        ss_c, ct_c = self.skem.encaps(self.ek_c)
        th = xof(b"kemtls-th", m1, m2, m3, ct_c, outlen=32)
        ms = xof(b"kemtls-ms", ss_e, ss_s_r, ss_c, th, outlen=96)
        sf = mac(ms[:32], b"sf", th, taglen=FIN)
        m4 = ct_c + sf
        timer.stop()
        self._op("R", "decaps")
        self._op("R", "encaps")

        timer.start("I")
        ss_c_i = self.dec_c.decaps(ct_c)
        th_i = xof(b"kemtls-th", m1, m2, m3, ct_c, outlen=32)
        ms_i = xof(b"kemtls-ms", ss_e_i, ss_s, ss_c_i, th_i, outlen=96)
        ok = ct_eq(sf, mac(ms_i[:32], b"sf", th_i, taglen=FIN))
        cf = mac(ms_i[32:64], b"cf", th_i, taglen=FIN)
        key_i = ms_i[64:]
        m5 = cf
        timer.stop()
        self._op("I", "decaps")

        timer.start("R")
        ok2 = ct_eq(cf, mac(ms[32:64], b"cf", th, taglen=FIN))
        key_r = ms[64:]
        timer.stop()
        if not (ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", m3), ("R", m4), ("I", m5)]

    def free(self):
        self.dec_s.free()
        self.dec_c.free()


class KEMTLSPDK(Protocol):
    name = "KEMTLS-PDK"
    venue = "ESORICS"
    year = 2021
    family = "KEM"
    flows = 3
    rtt = 1.0

    def setup(self):
        self.ek_s, dk_s = self.skem.keygen()
        self.ek_c, dk_c = self.skem.keygen()
        self.dec_s = PersistentDecapsulator(self.static_kem_name, dk_s)
        self.dec_c = PersistentDecapsulator(self.static_kem_name, dk_c)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        n_c = random_bytes(NONCE)
        ss_s, ct_s = self.skem.encaps(self.ek_s)
        m1 = ek_e + n_c + ct_s
        timer.stop()
        self._op("I", "keygen")
        self._op("I", "encaps")

        timer.start("R")
        ss_s_r = self.dec_s.decaps(ct_s)
        ss_e, ct_e = self.kem.encaps(ek_e)
        ss_c, ct_c = self.skem.encaps(self.ek_c)
        n_s = random_bytes(NONCE)
        th = xof(b"pdk-th", m1, ct_e, n_s, ct_c, outlen=32)
        ms = xof(b"pdk-ms", ss_s_r, ss_e, ss_c, th, outlen=96)
        sf = mac(ms[:32], b"sf", th, taglen=FIN)
        m2 = ct_e + n_s + ct_c + sf
        timer.stop()
        self._op("R", "decaps")
        self._op("R", "encaps", 2)

        timer.start("I")
        ss_e_i = self.kem.eph_decaps(ct_e)
        ss_c_i = self.dec_c.decaps(ct_c)
        th_i = xof(b"pdk-th", m1, ct_e, n_s, ct_c, outlen=32)
        ms_i = xof(b"pdk-ms", ss_s, ss_e_i, ss_c_i, th_i, outlen=96)
        ok = ct_eq(sf, mac(ms_i[:32], b"sf", th_i, taglen=FIN))
        cf = mac(ms_i[32:64], b"cf", th_i, taglen=FIN)
        key_i = ms_i[64:]
        timer.stop()
        self._op("I", "decaps", 2)

        timer.start("R")
        ok2 = ct_eq(cf, mac(ms[32:64], b"cf", th, taglen=FIN))
        key_r = ms[64:]
        timer.stop()
        if not (ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", cf)]

    def free(self):
        self.dec_s.free()
        self.dec_c.free()


class PQWireGuard(Protocol):
    name = "PQ-WireGuard"
    venue = "IEEE S&P"
    year = 2021
    family = "KEM"
    flows = 3
    rtt = 1.0
    HDR1 = 116
    HDR2 = 64

    def setup(self):
        self.ek_r, dk_r = self.skem.keygen()
        self.ek_i, dk_i = self.skem.keygen()
        self.dec_r = PersistentDecapsulator(self.static_kem_name, dk_r)
        self.dec_i = PersistentDecapsulator(self.static_kem_name, dk_i)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        ss_r, ct_r = self.skem.encaps(self.ek_r)
        hdr1 = random_bytes(self.HDR1)
        m1 = hdr1 + ek_e + ct_r
        timer.stop()
        self._op("I", "keygen")
        self._op("I", "encaps")

        timer.start("R")
        ss_r_r = self.dec_r.decaps(ct_r)
        ss_e, ct_e = self.kem.encaps(ek_e)
        ss_i, ct_i = self.skem.encaps(self.ek_i)
        hdr2 = random_bytes(self.HDR2)
        th = xof(b"wg-th", m1, ct_e, ct_i, hdr2, outlen=32)
        ck = xof(b"wg-ck", ss_r_r, ss_e, ss_i, th, outlen=96)
        m2 = hdr2 + ct_e + ct_i
        timer.stop()
        self._op("R", "decaps")
        self._op("R", "encaps", 2)

        timer.start("I")
        ss_e_i = self.kem.eph_decaps(ct_e)
        ss_i_i = self.dec_i.decaps(ct_i)
        th_i = xof(b"wg-th", m1, ct_e, ct_i, hdr2, outlen=32)
        ck_i = xof(b"wg-ck", ss_r, ss_e_i, ss_i_i, th_i, outlen=96)
        conf = mac(ck_i[:32], b"conf", th_i, taglen=FIN)
        key_i = ck_i[64:]
        timer.stop()
        self._op("I", "decaps", 2)

        timer.start("R")
        ok = ct_eq(conf, mac(ck[:32], b"conf", th, taglen=FIN))
        key_r = ck[64:]
        timer.stop()
        if not (ok and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", conf)]

    def free(self):
        self.dec_r.free()
        self.dec_i.free()


class FSXY(Protocol):
    name = "FSXY KEM-AKE"
    venue = "CT-RSA"
    year = 2012
    family = "KEM"
    flows = 2
    rtt = 1.0

    def setup(self):
        self.ek_a, dk_a = self.skem.keygen()
        self.ek_b, dk_b = self.skem.keygen()
        self.dec_a = PersistentDecapsulator(self.static_kem_name, dk_a)
        self.dec_b = PersistentDecapsulator(self.static_kem_name, dk_b)

    def session(self, timer):
        timer.start("I")
        ss_b, ct_b = self.skem.encaps(self.ek_b)
        ek_e = self.kem.eph_keygen()
        m1 = ct_b + ek_e
        timer.stop()
        self._op("I", "encaps")
        self._op("I", "keygen")

        timer.start("R")
        ss_b_r = self.dec_b.decaps(ct_b)
        ss_a, ct_a = self.skem.encaps(self.ek_a)
        ss_e, ct_e = self.kem.encaps(ek_e)
        m2 = ct_a + ct_e
        th = xof(b"fsxy-th", m1, m2, outlen=32)
        key_r = xof(b"fsxy-key", ss_b_r, ss_a, ss_e, th, outlen=32)
        timer.stop()
        self._op("R", "decaps")
        self._op("R", "encaps", 2)

        timer.start("I")
        ss_a_i = self.dec_a.decaps(ct_a)
        ss_e_i = self.kem.eph_decaps(ct_e)
        th_i = xof(b"fsxy-th", m1, m2, outlen=32)
        key_i = xof(b"fsxy-key", ss_b, ss_a_i, ss_e_i, th_i, outlen=32)
        timer.stop()
        self._op("I", "decaps", 2)
        if key_i != key_r:
            return None
        return [("I", m1), ("R", m2)]

    def free(self):
        self.dec_a.free()
        self.dec_b.free()


class KyberAKE(Protocol):
    name = "Kyber.AKE"
    venue = "IEEE EuroS&P"
    year = 2018
    family = "KEM"
    flows = 2
    rtt = 1.0

    def setup(self):
        self.ek_a, dk_a = self.skem.keygen()
        self.ek_b, dk_b = self.skem.keygen()
        self.dec_a = PersistentDecapsulator(self.static_kem_name, dk_a)
        self.dec_b = PersistentDecapsulator(self.static_kem_name, dk_b)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        ss1, ct1 = self.skem.encaps(self.ek_b)
        m1 = ek_e + ct1
        timer.stop()
        self._op("I", "keygen")
        self._op("I", "encaps")

        timer.start("R")
        ss1_r = self.dec_b.decaps(ct1)
        ss2, ct2 = self.kem.encaps(ek_e)
        ss3, ct3 = self.skem.encaps(self.ek_a)
        m2 = ct2 + ct3
        key_r = xof(b"kyber-ake", ss1_r, ss2, ss3, m1, m2, outlen=32)
        timer.stop()
        self._op("R", "decaps")
        self._op("R", "encaps", 2)

        timer.start("I")
        ss2_i = self.kem.eph_decaps(ct2)
        ss3_i = self.dec_a.decaps(ct3)
        key_i = xof(b"kyber-ake", ss1, ss2_i, ss3_i, m1, m2, outlen=32)
        timer.stop()
        self._op("I", "decaps", 2)
        if key_i != key_r:
            return None
        return [("I", m1), ("R", m2)]

    def free(self):
        self.dec_a.free()
        self.dec_b.free()


class EDHOCSig(Protocol):
    name = "EDHOC (method 0)"
    venue = "RFC 9528"
    year = 2024
    family = "SIG"
    flows = 3
    rtt = 1.0
    HDR1 = 12
    HDR2 = 10
    HDR3 = 8

    def setup(self):
        self.pk_r, sk_r = self.sig.keygen()
        self.pk_i, sk_i = self.sig.keygen()
        self.signer_r = PersistentSigner(self.sig_name, sk_r)
        self.signer_i = PersistentSigner(self.sig_name, sk_i)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        m1 = random_bytes(self.HDR1) + ek_e
        timer.stop()
        self._op("I", "keygen")

        timer.start("R")
        ss, ct = self.kem.encaps(ek_e)
        th2 = xof(b"edhoc-th2", m1, ct, outlen=32)
        prk = xof(b"edhoc-prk", ss, th2, outlen=96)
        mac2 = mac(prk[:32], b"mac2", th2, taglen=TAG_LEN)
        sig_r = self.signer_r.sign(th2 + mac2)
        m2 = random_bytes(self.HDR2) + ct + sig_r
        timer.stop()
        self._op("R", "encaps")
        self._op("R", "sign")

        timer.start("I")
        ss_i = self.kem.eph_decaps(ct)
        th2_i = xof(b"edhoc-th2", m1, ct, outlen=32)
        prk_i = xof(b"edhoc-prk", ss_i, th2_i, outlen=96)
        mac2_i = mac(prk_i[:32], b"mac2", th2_i, taglen=TAG_LEN)
        ok = self.sig.verify(self.pk_r, th2_i + mac2_i, sig_r)
        th3 = xof(b"edhoc-th3", th2_i, m2, outlen=32)
        mac3 = mac(prk_i[32:64], b"mac3", th3, taglen=TAG_LEN)
        sig_i = self.signer_i.sign(th3 + mac3)
        m3 = random_bytes(self.HDR3) + sig_i
        key_i = xof(b"edhoc-key", prk_i, th3, outlen=32)
        timer.stop()
        self._op("I", "decaps")
        self._op("I", "verify")
        self._op("I", "sign")

        timer.start("R")
        th3_r = xof(b"edhoc-th3", th2, m2, outlen=32)
        mac3_r = mac(prk[32:64], b"mac3", th3_r, taglen=TAG_LEN)
        ok2 = self.sig.verify(self.pk_i, th3_r + mac3_r, sig_i)
        key_r = xof(b"edhoc-key", prk, th3_r, outlen=32)
        timer.stop()
        self._op("R", "verify")
        if not (ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", m3)]

    def free(self):
        self.signer_r.free()
        self.signer_i.free()


class EDHOCKem(Protocol):
    name = "EDHOC-KEM"
    venue = "USENIX Sec."
    year = 2023
    family = "KEM"
    flows = 3
    rtt = 1.0
    HDR1 = 12
    HDR2 = 10
    HDR3 = 8

    def setup(self):
        self.ek_r, dk_r = self.skem.keygen()
        self.ek_i, dk_i = self.skem.keygen()
        self.dec_r = PersistentDecapsulator(self.static_kem_name, dk_r)
        self.dec_i = PersistentDecapsulator(self.static_kem_name, dk_i)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        m1 = random_bytes(self.HDR1) + ek_e
        timer.stop()
        self._op("I", "keygen")

        timer.start("R")
        ss_e, ct_e = self.kem.encaps(ek_e)
        ss_i, ct_i = self.skem.encaps(self.ek_i)
        th2 = xof(b"ek-th2", m1, ct_e, ct_i, outlen=32)
        prk = xof(b"ek-prk", ss_e, ss_i, th2, outlen=96)
        mac2 = mac(prk[:32], b"mac2", th2, taglen=TAG_LEN)
        m2 = random_bytes(self.HDR2) + ct_e + ct_i + mac2
        timer.stop()
        self._op("R", "encaps", 2)

        timer.start("I")
        ss_e_i = self.kem.eph_decaps(ct_e)
        ss_i_i = self.dec_i.decaps(ct_i)
        th2_i = xof(b"ek-th2", m1, ct_e, ct_i, outlen=32)
        prk_i = xof(b"ek-prk", ss_e_i, ss_i_i, th2_i, outlen=96)
        ok = ct_eq(mac2, mac(prk_i[:32], b"mac2", th2_i, taglen=TAG_LEN))
        ss_r, ct_r = self.skem.encaps(self.ek_r)
        th3 = xof(b"ek-th3", th2_i, m2, ct_r, outlen=32)
        prk2_i = xof(b"ek-prk2", prk_i, ss_r, th3, outlen=64)
        mac3 = mac(prk2_i[:32], b"mac3", th3, taglen=TAG_LEN)
        m3 = random_bytes(self.HDR3) + ct_r + mac3
        key_i = prk2_i[32:]
        timer.stop()
        self._op("I", "decaps", 2)
        self._op("I", "encaps")

        timer.start("R")
        ss_r_r = self.dec_r.decaps(ct_r)
        th3_r = xof(b"ek-th3", th2, m2, ct_r, outlen=32)
        prk2 = xof(b"ek-prk2", prk, ss_r_r, th3_r, outlen=64)
        ok2 = ct_eq(mac3, mac(prk2[:32], b"mac3", th3_r, taglen=TAG_LEN))
        key_r = prk2[32:]
        timer.stop()
        self._op("R", "decaps")
        if not (ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", m3)]

    def free(self):
        self.dec_r.free()
        self.dec_i.free()


class TLS13PSKKEM(Protocol):
    name = "TLS 1.3 PSK+KEM"
    venue = "RFC 8446"
    year = 2018
    family = "PSK"
    flows = 3
    rtt = 1.0

    def setup(self):
        self.psk = random_bytes(32)
        self.identity = random_bytes(32)

    def session(self, timer):
        timer.start("I")
        ek_e = self.kem.eph_keygen()
        n_c = random_bytes(NONCE)
        body = ek_e + n_c + self.identity
        binder = mac(xof(b"psk-bk", self.psk, outlen=32), b"binder", body, taglen=FIN)
        m1 = body + binder
        timer.stop()
        self._op("I", "keygen")

        timer.start("R")
        okb = ct_eq(binder, mac(xof(b"psk-bk", self.psk, outlen=32), b"binder", body, taglen=FIN))
        ss, ct = self.kem.encaps(ek_e)
        n_s = random_bytes(NONCE)
        th = xof(b"psk-th", m1, ct, n_s, outlen=32)
        ms = xof(b"psk-ms", self.psk, ss, th, outlen=96)
        sf = mac(ms[:32], b"sf", th, taglen=FIN)
        m2 = ct + n_s + sf
        timer.stop()
        self._op("R", "encaps")

        timer.start("I")
        ss_i = self.kem.eph_decaps(ct)
        th_i = xof(b"psk-th", m1, ct, n_s, outlen=32)
        ms_i = xof(b"psk-ms", self.psk, ss_i, th_i, outlen=96)
        ok = ct_eq(sf, mac(ms_i[:32], b"sf", th_i, taglen=FIN))
        cf = mac(ms_i[32:64], b"cf", th_i, taglen=FIN)
        key_i = ms_i[64:]
        timer.stop()
        self._op("I", "decaps")

        timer.start("R")
        ok2 = ct_eq(cf, mac(ms[32:64], b"cf", th, taglen=FIN))
        key_r = ms[64:]
        timer.stop()
        if not (okb and ok and ok2 and key_i == key_r):
            return None
        return [("I", m1), ("R", m2), ("I", cf)]
