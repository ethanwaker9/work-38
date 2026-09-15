from .primitives import (
    KEM, PersistentDecapsulator, xof, mac, ct_eq, random_bytes,
    CHAIN_LEN, TAG_LEN, PSEUDONYM_LEN,
)
from .lookup import PseudonymTable

L_PID = b"pid"
L_BIND = b"bind"
L_SCHED = b"sched"
L_CTX = b"ctx"
L_TH = b"transcript"
L_G = b"gw-confirm"
L_D = b"dev-confirm"


def context_binder(ek_d, ek_g):
    return xof(L_CTX, ek_d, ek_g, outlen=32)


def pseudonym(chain):
    return xof(L_PID, chain, outlen=PSEUDONYM_LEN)


def bind_key(chain):
    return xof(L_BIND, chain, outlen=32)


def schedule(chain, ss1, ss2, transcript):
    block = xof(L_SCHED, chain, ss1, ss2, transcript, outlen=128)
    return block[0:32], block[32:64], block[64:96], block[96:128]


L_M1 = b"msg"


def message1_hash(msg1):
    return xof(L_M1, msg1, outlen=32)


def transcript_hash(binder, h1, ct2):
    return xof(L_TH, binder, h1, ct2, outlen=32)


class Device:
    def __init__(self, kem, ek_gateway, ek_self, dk_self, chain, device_id=b"\x00" * 8):
        self.kem = kem
        self.ek_gateway = ek_gateway
        self.ek_self = ek_self
        self.decapsulator = PersistentDecapsulator(kem.name, dk_self)
        self.binder = context_binder(ek_self, ek_gateway)
        self.chain = chain
        self.pending = None
        self.device_id = device_id

    def message1(self):
        p = pseudonym(self.chain)
        ss1, ct1 = self.kem.encaps(self.ek_gateway)
        tag1 = mac(bind_key(self.chain), L_BIND, p, ct1)
        msg1 = p + ct1 + tag1
        self.pending = (message1_hash(msg1), ss1, self.chain)
        return msg1

    def process_message2(self, msg2):
        if self.pending is None or len(msg2) != self.kem.ct_len + TAG_LEN:
            return None
        h1, ss1, chain = self.pending
        ct2 = msg2[: self.kem.ct_len]
        tag2 = msg2[self.kem.ct_len:]
        ss2 = self.decapsulator.decaps(ct2)
        th = transcript_hash(self.binder, h1, ct2)
        k_g, k_d, session_key, next_chain = schedule(chain, ss1, ss2, th)
        if not ct_eq(tag2, mac(k_g, L_G, th)):
            self.pending = None
            return None
        tag3 = mac(k_d, L_D, th)
        self.chain = next_chain
        self.pending = None
        return tag3, session_key

    def state_bytes(self):
        return len(self.chain) + len(self.ek_gateway) + self.kem.dk_len

    def free(self):
        self.decapsulator.free()


class Gateway:
    def __init__(self, kem, ek_self, dk_self):
        self.kem = kem
        self.ek_self = ek_self
        self.decapsulator = PersistentDecapsulator(kem.name, dk_self)
        self.table = PseudonymTable()
        self.devices = {}
        self.sessions = {}
        self.cache = {}

    def enroll(self, device_id, ek_device, chain):
        binder = context_binder(ek_device, self.ek_self)
        p = pseudonym(chain)
        self.devices[device_id] = {"ek": ek_device, "binder": binder, "slots": {p: chain}}
        self.table.insert(p, device_id, 0)

    def _set_slots(self, device_id, keep):
        rec = self.devices[device_id]
        for old in list(rec["slots"].keys()):
            if old not in keep:
                self.table.remove(old)
        rec["slots"] = dict(keep)
        for p in keep:
            self.table.insert(p, device_id, 0)

    def process_message1(self, msg1):
        if len(msg1) != PSEUDONYM_LEN + self.kem.ct_len + TAG_LEN:
            return None
        p = msg1[:PSEUDONYM_LEN]
        found = self.table.lookup(p)
        if found is None:
            return None
        device_id = found[0]
        rec = self.devices[device_id]
        chain = rec["slots"].get(p)
        if chain is None:
            return None
        h1 = message1_hash(msg1)
        key = h1
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        ct1 = msg1[PSEUDONYM_LEN:PSEUDONYM_LEN + self.kem.ct_len]
        tag1 = msg1[PSEUDONYM_LEN + self.kem.ct_len:]
        if not ct_eq(tag1, mac(bind_key(chain), L_BIND, p, ct1)):
            return None
        ss1 = self.decapsulator.decaps(ct1)
        ss2, ct2 = self.kem.encaps(rec["ek"])
        th = transcript_hash(rec["binder"], h1, ct2)
        k_g, k_d, session_key, next_chain = schedule(chain, ss1, ss2, th)
        msg2 = ct2 + mac(k_g, L_G, th)
        handle = (device_id, key)
        p_next = pseudonym(next_chain)
        self._set_slots(device_id, {p: chain, p_next: next_chain})
        self.sessions[handle] = (k_d, th, session_key, p_next, next_chain)
        self.cache[key] = (handle, msg2)
        return handle, msg2

    def process_message3(self, handle, tag3):
        st = self.sessions.get(handle)
        if st is None:
            return None
        k_d, th, session_key, p_next, next_chain = st
        if not ct_eq(tag3, mac(k_d, L_D, th)):
            return None
        device_id, key = handle
        self._set_slots(device_id, {p_next: next_chain})
        self.sessions.pop(handle, None)
        self.cache.pop(key, None)
        return session_key

    def state_bytes_per_device(self):
        if not self.devices:
            return 0
        rec = next(iter(self.devices.values()))
        return len(rec["ek"]) + len(rec["binder"]) + sum(
            PSEUDONYM_LEN + len(c) for c in rec["slots"].values()
        )

    def free(self):
        self.decapsulator.free()


class BootstrapContext:
    def __init__(self, kem, ek_device, dk_device, ek_gateway, dk_gateway):
        self.kem = kem
        self.ek_device = ek_device
        self.ek_gateway = ek_gateway
        self.dev = PersistentDecapsulator(kem.name, dk_device)
        self.gw = PersistentDecapsulator(kem.name, dk_gateway)
        self.binder = context_binder(ek_device, ek_gateway)

    def phase1(self):
        kem = self.kem
        ek_e = kem.eph_keygen()
        ss_g, ct_g = kem.encaps(self.ek_gateway)
        self._s = (ek_e, ss_g, ct_g)
        return ek_e + ct_g

    def phase2(self, msg1):
        kem = self.kem
        ct_g = msg1[kem.ek_len:]
        ss_g_r = self.gw.decaps(ct_g)
        ss_e, ct_e = kem.encaps(msg1[: kem.ek_len])
        ss_d, ct_d = kem.encaps(self.ek_device)
        th = xof(b"bootstrap", self.binder, msg1, ct_e, ct_d, outlen=32)
        blk = xof(L_SCHED, ss_g_r, ss_e, ss_d, th, outlen=96)
        k_g, k_d, chain_r = blk[0:32], blk[32:64], blk[64:96]
        tag_g = mac(k_g, L_G, th)
        self._r = (k_d, th, chain_r, tag_g)
        return ct_e + ct_d + tag_g

    def phase3(self, msg1, msg2):
        kem = self.kem
        ek_e, ss_g, ct_g = self._s
        ct_e = msg2[: kem.ct_len]
        ct_d = msg2[kem.ct_len: 2 * kem.ct_len]
        tag_g = msg2[2 * kem.ct_len:]
        ss_e_i = kem.eph_decaps(ct_e)
        ss_d_i = self.dev.decaps(ct_d)
        th_i = xof(b"bootstrap", self.binder, msg1, ct_e, ct_d, outlen=32)
        blk_i = xof(L_SCHED, ss_g, ss_e_i, ss_d_i, th_i, outlen=96)
        ok = ct_eq(tag_g, mac(blk_i[0:32], L_G, th_i))
        tag_d = mac(blk_i[32:64], L_D, th_i)
        chain_i = blk_i[64:96]
        return ok, chain_i, tag_d

    def verify_final(self, tag_d, chain_i):
        k_d, th, chain_r, _ = self._r
        return ct_eq(tag_d, mac(k_d, L_D, th)) and chain_i == chain_r

    def run(self):
        msg1 = self.phase1()
        msg2 = self.phase2(msg1)
        ok, chain_i, tag_d = self.phase3(msg1, msg2)
        ok = ok and self.verify_final(tag_d, chain_i)
        return ok, chain_i, [msg1, msg2, tag_d]

    def free(self):
        self.dev.free()
        self.gw.free()


def bootstrap(kem, ek_device, dk_device, ek_gateway, dk_gateway):
    ctx = BootstrapContext(kem, ek_device, dk_device, ek_gateway, dk_gateway)
    r = ctx.run()
    ctx.free()
    return r
