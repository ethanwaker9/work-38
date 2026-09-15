class PseudonymTable:
    def __init__(self):
        self._map = {}

    def insert(self, pseudonym, device_id, epoch):
        self._map[bytes(pseudonym)] = (device_id, epoch)

    def lookup(self, pseudonym):
        return self._map.get(bytes(pseudonym))

    def remove(self, pseudonym):
        self._map.pop(bytes(pseudonym), None)

    def __len__(self):
        return len(self._map)

    def memory_bytes(self, pseudonym_len):
        return len(self._map) * (pseudonym_len + 12)
