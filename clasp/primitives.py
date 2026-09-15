import os
import hashlib
import hmac
import oqs

SHARED_SECRET_LEN = 32
CHAIN_LEN = 32
TAG_LEN = 16
PSEUDONYM_LEN = 16
NONCE_LEN = 16

DOMAIN = b"CLASP-v1"

MLKEM_PARAMS = {
    "ML-KEM-512": {"ek": 800, "dk": 1632, "ct": 768, "level": 1, "k": 2},
    "ML-KEM-768": {"ek": 1184, "dk": 2400, "ct": 1088, "level": 3, "k": 3},
    "ML-KEM-1024": {"ek": 1568, "dk": 3168, "ct": 1568, "level": 5, "k": 4},
}

MLDSA_PARAMS = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420, "level": 2},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309, "level": 3},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627, "level": 5},
    "Falcon-padded-512": {"pk": 897, "sk": 1281, "sig": 666, "level": 1},
    "Falcon-padded-1024": {"pk": 1793, "sk": 2305, "sig": 1280, "level": 5},
}


def xof(label, *chunks, outlen=32):
    parts = [DOMAIN, len(label).to_bytes(4, "big"), label]
    for c in chunks:
        parts.append(len(c).to_bytes(4, "big"))
        parts.append(c)
    return hashlib.shake_256(b"".join(parts)).digest(outlen)


def mac(key, label, *chunks, taglen=TAG_LEN):
    parts = [DOMAIN, b"\x01", len(key).to_bytes(4, "big"), key,
             len(label).to_bytes(4, "big"), label]
    for c in chunks:
        parts.append(len(c).to_bytes(4, "big"))
        parts.append(c)
    return hashlib.shake_256(b"".join(parts)).digest(taglen)


def ct_eq(a, b):
    return hmac.compare_digest(a, b)


class KEM:
    def __init__(self, name):
        self.name = name
        self._enc = oqs.KeyEncapsulation(name)
        self._eph = oqs.KeyEncapsulation(name)
        d = self._enc.details
        self.ek_len = d["length_public_key"]
        self.dk_len = d["length_secret_key"]
        self.ct_len = d["length_ciphertext"]
        self.ss_len = d["length_shared_secret"]

    def keygen(self):
        holder = oqs.KeyEncapsulation(self.name)
        ek = holder.generate_keypair()
        dk = holder.export_secret_key()
        holder.free()
        return ek, dk

    def eph_keygen(self):
        return self._eph.generate_keypair()

    def eph_decaps(self, ct):
        return self._eph.decap_secret(ct)

    def encaps(self, ek):
        ct, ss = self._enc.encap_secret(ek)
        return ss, ct

    def decaps(self, dk, ct):
        holder = oqs.KeyEncapsulation(self.name, secret_key=dk)
        ss = holder.decap_secret(ct)
        holder.free()
        return ss

    def free(self):
        self._enc.free()
        self._eph.free()


class PersistentDecapsulator:
    def __init__(self, name, dk):
        self._h = oqs.KeyEncapsulation(name, secret_key=dk)

    def decaps(self, ct):
        return self._h.decap_secret(ct)

    def free(self):
        self._h.free()


class SIG:
    def __init__(self, name):
        self.name = name
        self._h = oqs.Signature(name)
        d = self._h.details
        self.pk_len = d["length_public_key"]
        self.sig_len = d["length_signature"]

    def keygen(self):
        holder = oqs.Signature(self.name)
        pk = holder.generate_keypair()
        sk = holder.export_secret_key()
        holder.free()
        return pk, sk

    def verify(self, pk, msg, sig):
        return self._h.verify(msg, sig, pk)

    def free(self):
        self._h.free()


class PersistentSigner:
    def __init__(self, name, sk):
        self._h = oqs.Signature(name, secret_key=sk)

    def sign(self, msg):
        return self._h.sign(msg)

    def free(self):
        self._h.free()


def random_bytes(n):
    return os.urandom(n)
