from dataclasses import dataclass

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

import logging


def auth8(client_key_material, server_key_material, derivation_key, handshake_auth_key):
    msg = server_key_material + client_key_material + derivation_key
    assert len(msg) == 32
    cobj = CMAC.new(handshake_auth_key, ciphermod=AES, mac_len=8)
    cobj.update(msg)
    return cobj


@dataclass
class StaticKeys:
    derivation_key: bytes
    handshake_auth_key: bytes
    permit_decrypt_key: bytes
    permit_auth_key: bytes
    handshake_payload: bytes

    @staticmethod
    def from_bytes(data: bytes):
        return StaticKeys(*[data[i : i + 16] for i in range(0, 80, 16)])


@dataclass
class KeyDatabase:
    local_device_type: int
    remote_devices: dict[int, StaticKeys]

    @staticmethod
    def from_bytes(data: bytes):
        n = data[5]
        if len(data) != 6 + 81 * n:
            raise ValueError
        t = data[4]
        m = {}
        for i in range(n):
            p = 6 + 81 * i
            m[data[p]] = StaticKeys.from_bytes(data[p + 1 : p + 81])
        return KeyDatabase(local_device_type=t, remote_devices=m)


@dataclass
class SeqCrypt:
    key: bytes
    nonce: bytes
    seq: int

    def __post_init__(self):
        self.logger = logging.getLogger(type(self).__name__)
        if len(self.nonce) != 8:
            raise ValueError

    def decrypt(self, msg):
        log = self.logger.getChild("decrypt")
        if len(msg) < 3:
            raise ValueError
        d = (msg[-3] - self.seq // 2) & 0xFF
        seq = self.seq + 2 * d
        log.debug(f"{seq = }")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        ciphertext = msg[:-3]
        log.debug(f"{ciphertext.hex() = }")
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        log.debug(f"{msg[-2:].hex() = }, {cobj.digest().hex() = }")
        cobj.verify(msg[-2:] + cobj.digest()[2:4])
        self.seq = seq + 2
        return AES.new(self.key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)


@dataclass
class Session:
    key_database: KeyDatabase
    client_key_material: bytes | None = None
    client_nonce: bytes | None = None
    client_device_type: int | None = None
    server_device_type: int | None = None
    server_key_material: bytes | None = None
    server_nonce: bytes | None = None
    static_keys: StaticKeys | None = None
    client_crypt: SeqCrypt | None = None
    server_crypt: SeqCrypt | None = None

    def __post_init__(self):
        self.logger = logging.getLogger(type(self).__name__)

    def handshake_0_s(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        if msg[1] != 1:
            raise ValueError
        self.server_device_type = msg[0]
        self.static_keys = self.key_database.remote_devices[self.server_device_type]

    def handshake_1_c(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        self.client_key_material = msg[:8]
        self.client_nonce = msg[9:13]
        self.client_device_type = msg[8]

    def handshake_2_s(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        server_key_material = msg[8:16]
        server_nonce = msg[16:20]
        auth = auth8(
            self.client_key_material,
            server_key_material,
            self.static_keys.derivation_key,
            self.static_keys.handshake_auth_key,
        )
        received = msg[0:8]
        auth.verify(received)
        self.server_key_material = server_key_material
        self.server_nonce = server_nonce

    def handshake_3_c(self, msg: bytes):
        log = self.logger.getChild("handshake_3_c")
        if len(msg) != 20:
            raise ValueError
        auth1 = auth8(
            self.client_key_material,
            self.server_key_material,
            self.static_keys.derivation_key,
            self.static_keys.handshake_auth_key,
        )
        inner = (
            auth1.digest() + self.server_key_material + self.static_keys.derivation_key
        )
        auth2 = CMAC.new(self.static_keys.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        received = msg[:8]
        auth2.verify(received)
        log.info("verified")

    def handshake_4_s(self, msg: bytes):
        log = self.logger.getChild("handshake_4_s")
        if len(msg) != 20:
            raise ValueError
        key = AES.new(self.static_keys.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        log.debug(f"{nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        inner = self.server_crypt.decrypt(msg)[:16]
        log.debug(f"{inner.hex() = }")
        plain = AES.new(self.static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
            inner
        )
        auth = CMAC.new(self.static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
        auth.update(plain[:12])
        log.debug(f"{plain[:12].hex() = }")
        log.debug(f"{plain[12:].hex() = }")
        auth.verify(plain[12:])
        if plain[0] == 0 and plain[1] == self.server_device_type:
            log.info("server device type match")

    def handshake_5_c(self, msg: bytes):
        log = self.logger.getChild("handshake_5_c")
        if len(msg) != 20:
            raise ValueError
        plain = self.client_crypt.decrypt(msg)[:-1]
        log.debug(f"{plain.hex() = }")
        log.debug(f"{self.static_keys.handshake_payload.hex() = }")
        if plain == self.static_keys.handshake_payload:
            log.info("handshake payload match")
        experiment = AES.new(self.static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
            plain
        )
        log.debug(f"{experiment.hex() = }")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    kdbdata = bytes.fromhex(
        "5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326"
    )

    sess = Session(key_database=KeyDatabase.from_bytes(kdbdata))
    sess.handshake_0_s(bytes.fromhex("02015f0edcd0c2af98705bed6c8172856d860402"))
    sess.handshake_1_c(bytes.fromhex("a579868377f401ae083405ef88cc0962d6079a04"))
    sess.handshake_2_s(bytes.fromhex("77f3fb85b079310455fd8f47ddaf81ab49defc7b"))
    sess.handshake_3_c(bytes.fromhex("7f57c1ac4e12d21b46cfaf03f9dbd4877d0a7d76"))
    sess.handshake_4_s(bytes.fromhex("ef54ef03ad398363825fd434e69cd829630056fa"))
    sess.handshake_5_c(bytes.fromhex("2f22c383cf264fa4ebc5b10dc8a2c8a4b000619e"))
    c2s = sess.client_crypt.decrypt(bytes.fromhex("5b17ba013a41"))
    print(f"{c2s.hex() = }")
    s2c = sess.server_crypt.decrypt(bytes.fromhex("5d369e51af6072adb66b01f937"))
    print(f"{s2c.hex() = }")
