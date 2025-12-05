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

    @classmethod
    def from_bytes(cls, data: bytes):
        log = logging.getLogger(cls.__name__).getChild("from_bytes")
        n = data[5]
        if len(data) != 6 + 81 * n:
            raise ValueError
        local_device_type = data[4]
        log.debug(f"{local_device_type = }")
        remote_devices = {}
        for i in range(n):
            p = 6 + 81 * i
            remote_devices[data[p]] = StaticKeys.from_bytes(data[p + 1 : p + 81])
        log.debug(f"{remote_devices.keys() = }")
        return cls(local_device_type=local_device_type, remote_devices=remote_devices)


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
    client_key_database: KeyDatabase | None = None
    server_key_database: KeyDatabase | None = None
    client_key_material: bytes | None = None
    client_nonce: bytes | None = None
    client_device_type: int | None = None
    server_device_type: int | None = None
    server_key_material: bytes | None = None
    server_nonce: bytes | None = None
    client_static_keys: StaticKeys | None = None
    server_static_keys: StaticKeys | None = None
    derivation_key: bytes | None = None
    handshake_auth_key: bytes | None = None
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

    def handshake_1_c(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        self.client_key_material = msg[:8]
        self.client_nonce = msg[9:13]
        cdt = self.client_device_type = msg[8]
        sdt = self.server_device_type
        sk = None
        ckd = self.client_key_database
        skd = self.server_key_database
        if ckd is None and skd is None:
            raise ValueError("No key database available.")
        if ckd is not None and ckd.local_device_type == cdt:
            sk = self.client_static_keys = ckd.remote_devices.get(sdt)
        if skd is not None and skd.local_device_type == sdt:
            sk = self.server_static_keys = skd.remote_devices.get(cdt)
        if sk is None:
            raise KeyError(f"No keys available for client device type {cdt} and server device type {sdt}.")
        self.derivation_key = sk.derivation_key
        self.handshake_auth_key = sk.handshake_auth_key


    def handshake_2_s(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        server_key_material = msg[8:16]
        server_nonce = msg[16:20]
        auth = auth8(
            self.client_key_material,
            server_key_material,
            self.derivation_key,
            self.handshake_auth_key,
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
            self.derivation_key,
            self.handshake_auth_key,
        )
        inner = (
            auth1.digest() + self.server_key_material + self.derivation_key
        )
        auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        received = msg[:8]
        auth2.verify(received)
        log.info("verified")

    def handshake_4_s(self, msg: bytes):
        log = self.logger.getChild("handshake_4_s")
        if len(msg) != 20:
            raise ValueError
        key = AES.new(self.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        log.debug(f"{nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        inner = self.server_crypt.decrypt(msg)[:16]
        log.debug(f"{inner.hex() = }")
        self.check_payload(inner, self.client_static_keys, self.server_static_keys, self.server_device_type)

    def handshake_5_c(self, msg: bytes):
        log = self.logger.getChild("handshake_5_c")
        if len(msg) != 20:
            raise ValueError
        inner = self.client_crypt.decrypt(msg)[:-1]
        log.debug(f"{inner.hex() = }")
        self.check_payload(inner, self.server_static_keys, self.client_static_keys, self.client_device_type)

    def check_payload(self, payload, verifier_static_keys, prover_static_keys, prover_device_type):
        log = self.logger.getChild("check_payload")
        if prover_static_keys is not None:
            log.debug(f"{payload.hex() = }")
            log.debug(f"{prover_static_keys.handshake_payload.hex() = }")
            if payload == prover_static_keys.handshake_payload:
                log.info("handshake payload match")
        if verifier_static_keys is not None:
            plain = AES.new(verifier_static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
                payload
            )
            auth = CMAC.new(verifier_static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
            auth.update(plain[:12])
            log.debug(f"{plain[:12].hex() = }")
            log.debug(f"{plain[12:].hex() = }")
            auth.verify(plain[12:])
            if plain[0] == 0 and plain[1] == prover_device_type:
                log.info("prover device type match")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    kdbdata = bytes.fromhex(
        "5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326"
    )
    sess = Session(client_key_database=KeyDatabase.from_bytes(kdbdata))
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

    print("# 780g_pairing_with_mobile.pcapng")
    kdbdata = bytes.fromhex(
        "f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c"
        )
    sess = Session(server_key_database=KeyDatabase.from_bytes(kdbdata))
    sess.handshake_0_s(bytes.fromhex("0401e2f09017a98f9f01cc56492fbacd4576e92b"))
    sess.handshake_1_c(bytes.fromhex("42060e9f344e9312016ee8854d357f659b6b00ba"))
    sess.handshake_2_s(bytes.fromhex("fdeeb13d04c3f18d272630ebeabe7c3a4d4d27b9"))
    sess.handshake_3_c(bytes.fromhex("c02cec4ffb99affcb553a10fa6c55bb13d9fbacf"))
    sess.handshake_4_s(bytes.fromhex("157d8e90214418a0e3d5f0517eebf4a82e00c02e"))
    sess.handshake_5_c(bytes.fromhex("9b36f393b296fa84a757809859fc84a5c300d59b"))
    for d, msg, handle in [
            (0, "391063e5011d25", 0x001b),
            (0, "1f65868265cb921cc8022dea", 0x0022),
            (0, "7857b46603ee4f", 0x001b),
            (1, "39b6b6da6fe8017ba0", 0x0024),
            (0, "dfdaeb83d3042653", 0x0024),
            (0, "a18243a087c7b8753805441a", 0x001e),
            (0, "0e06b490", 0x0020),
            (1, "a16002487a", 0x0024),
            (0, "f501a990adf87fa807bf5a", 0x0024),
            (1, "e93103ae4e", 0x0024),
            (0, "c3db9ac1e12b22080ffe", 0x0024),
            (1, "d8f604efdc", 0x0024),
            (0, "8351b6f9a93d9709345e", 0x0024),
            (1, "440405721b", 0x0024),
            (0, "9912f60afec7", 0x0024),
            (1, "494706e5de", 0x0024),
            (0, "e493870bcb0d", 0x0024),
            (1, "93b0a2070cd6", 0x0027),
            (0, "e79830aabf761cf6016826dda60cf2e4", 0x002a),
            (0, "57086da5a50d452c", 0x0027),
            (1, "deea2508572d", 0x0027),
            (0, "43b2042026863554be0e93cd", 0x002a),
            (0, "9f5b8424e30f093d", 0x0027),
            (1, "896d0a09cc8f", 0x004d),
            (0, "22478bd667e6526970191036fd", 0x004d),
            (1, "e36d4ca4e10a7562", 0x004d),
            (0, "c4ac127a27114b9f", 0x004d),
            (1, "ab3ed3f9760b78ef", 0x004d),
            (0, "a17e9f2b7012fc37", 0x004d),
            (0, "c9783691d06d4ea997dc99af6ae9130c50", 0x0030),
            (0, "4d0e8ac32a09525899c5611dff142679", 0x0030),
            (0, "ca3e5b4cf79104ac6bb2151175", 0x0030),
            (0, "429c5ff1488c62da8c38b0ee46b53f5d6ed9f5d12316839a", 0x0030),
            (0, "53de6a8b3ab3d5c20dc3a2170b44", 0x0030),
            (0, "e6a7e844e5bffef9ba880d6f4126bd8badba60c7f5186873", 0x0030),
            (0, "a1c919eba1758bd8e5443050c48228196c00", 0x0030),
            (0, "90bcdc0820da14a1bdfd18e86254cfc31a42b1", 0x0030),
            (0, "ba0e26de01b0da8cf8286459381b692a", 0x0030),
            (0, "d7e7503871abba92cfc5357ba8fdef721c62a5", 0x0030),
            (0, "37cbe843b37cc9f0b37f558ed41dadaa", 0x0030),
            (0, "3406c9092a7c7d1ca2c3a3c6fe67b26f1eda9c", 0x0030),
            (0, "bd00734b29e55ca34787860c491fc60e", 0x0030),
            (0, "2bc7f72cbe082634490d351a203ee3", 0x0030),
            (0, "3b98207c70f5f6d524fd2d43c363aaee21e40f", 0x0030),
            (0, "564895d9f206431f6c63a4c50f22d437", 0x0030),
            (0, "0193f176fae7d7cc0398ab88351d603123bd9f", 0x0030),
            (0, "4034f888542c866c1c7d1b51e1241f0f", 0x0030),
            (0, "f61b2511a5112aed1e8c253142", 0x0030),
            (0, "92e0650ca1c35611c3f54d8424de36845a1cefd48726cab7", 0x0030),
            (0, "0309b3e4a4d4b36934345927b6b8", 0x0030),
            (0, "f447c7102a63234b0e3cd0c6a0edd2050d89ae6e45283209", 0x0030),
            (0, "751c023e47e27bd710f38f2b4d89292977b1", 0x0030),
            (0, "b8594827c2ca70807b69cf0a4a7ccf582a3f00", 0x0030),
            (0, "713513a88f3c79c5c81a9c72362ba843", 0x0030),
            (0, "8364c07bf71284444522d18927f9b9a72c2de0", 0x0030),
            (0, "afcf5a3639893532d0e1b367752da161", 0x0030),
            (0, "772a67064ea6f945889028067bee45512e6088", 0x0030),
            (0, "3d8ffb0e78d76114244e915c912f3c51", 0x0030),
            (0, "961ab3add8a80a5612c2411c1aad4b553001d3", 0x0030),
            (0, "16818d2d1322162e2b7d60330e3169ad", 0x0030),
            (0, "aa9e9528eea3daf030194ee55d9f6542321360", 0x0030),
            (0, "c7830ef0cf98d4e0757944573733c852", 0x0030),
            (0, "6e864270b9eb6a825e214b6b34472e", 0x0030),
            (0, "ac3b3a966a9ca0e7944835f313", 0x0030),
            (0, "e2aa493e7826bdeb567e08433716d3fb0c9fa3027836853b", 0x0030),
            (0, "20af80e6a3897784fe2c0337f7bc", 0x0030),
            (0, "fba4f174ed9e949f0e94d15f21596cba3c842b527a38460b", 0x0030),
            (0, "46222b5ed2277b52d376e55f9a00aa3909c2", 0x0030),
            (0, "dc11d63c148192423911c9b19671b8243a5443", 0x0030),
            (0, "02d699415337f3285e29a79d013bbea7", 0x0030),
            (0, "6595614bd5ce4860129f18cf0c2077b93cbc3d", 0x0030),
            (0, "62ae98f12b1166b26a94c366bdf33ec93d1ac3", 0x0030),
            (0, "f81a09be8555a2eff5e07d04593e4708", 0x0030),
            (0, "138f75b18b46afc747883fdd4b", 0x0030),
            (0, "eb5c847991c59bce5235a3ff75380a953b0ae02aa040e45c", 0x0030),
            (0, "c36528def6748dc231dfb041f0ad", 0x0030),
            (0, "aa67da7638d5bc34d04d55e379ad06a88b31b9f5ae423c75", 0x0030),
            (0, "226e4afa25a985a681bb9c75f4c83843c528", 0x0030),
            (0, "865aa8df90237ca41c31fa794dce756e448ec6", 0x0030),
            (0, "aa633fa37d41c28569035816e4450498", 0x0030),
            (0, "01165b4dca7cc39c5e83eb6b30b13c1546e854", 0x0030),
            (0, "67356173556a2a2d659a9a37fc47aec6", 0x0030),
            (0, "53bf25250be801434ab3405c55f1d7c3489493", 0x0030),
            (0, "57a4eaed1bae4eed2440e8251a49ea97", 0x0030),
            (0, "4302b4bbbd9d198874a93c07f15049ac5c4ae5a1", 0x0030),
            (0, "f18a4bb47651660695229e68fdad19b64bfa6c", 0x0030),
            (0, "c5971a2aad29008055274c319f29a71e4c337a", 0x0030),
            (0, "2fdaf0a0f5d3578ffccfac8395fa53024d60cf", 0x0030),
            (0, "c4bd9b068c55b754531096ef8b799ee64e21ca", 0x0030),
            (0, "a2af33d40c62073964fa2625494f799b", 0x0030),
            (0, "607c1d5292a7861890f68200b2c6e157509789", 0x0030),
            (0, "4aea7f0756baa5b0c8c87e4e53514af3", 0x0030),
            (0, "3b733940432ac48a9c9277147e24908e526fb8", 0x0030),
            (0, "dd8368119d9881a9444b5d8dd453f1dd", 0x0030),
            (0, "d8b9a328cf3dc6e0c795faa428a72d25545713", 0x0030),
            (0, "dbbec550eb73fab83074810de055b34e", 0x0030),
            (0, "b9304b48a4064d3c1772c50122949cc056d3dd", 0x0030),
            (0, "dc618f001eedf9632b9c9cdcf457ebfb", 0x0030),
            (0, "a37abf0c95207e6a30b8592a19dce0aa58500c", 0x0030),
            (0, "84e40ea55e4b1dc095eef06d7f59a509", 0x0030),
            (0, "1fe4762a752e5692fa56d9a27178f47e5a16b2", 0x0030),
            (0, "40c1e99e1da4edb81c554eba025b44df", 0x0030),
            (0, "9840103cd65a7cdc1a6689f29ea101d75cac53", 0x0030),
            (0, "b1b114b7867ff99b7a468732575d36c5", 0x0030),
            (0, "59ea9b49426bc0b341285ec4e00277b65ec0e2", 0x0030),
            (0, "2492ff92c001095a3b262a829f5f3a0c", 0x0030),
            (0, "3ed29ec379c1fa02e7f34b350cfac5806018a9", 0x0030),
            (0, "a0caa4668f5ecb88d36005f98561659d", 0x0030),
            (0, "1a097ae576f84971f8d74139dd61df3462bff6", 0x0030),
            (0, "ff5f79442dad26fce0b8ee00d663749e", 0x0030),
            (0, "a5141c6b731348880b83a876645111", 0x0030),
            ]:
        print(f"{['client', 'server'][d]} ({handle:04x}): {[sess.client_crypt, sess.server_crypt][d].decrypt(bytes.fromhex(msg)).hex()}")
