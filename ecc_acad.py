from pygost.gost3410 import GOST3410Curve, CURVES
from pygost.gost3410 import public_key
from pygost.utils import bytes2long, long2bytes

# from pygost.gost34112012512 import GOST34112012512
#
curve: GOST3410Curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
#
# hmac: GOST34112012512 = GOST34112012512(data=)
from gostcrypto.utils import utils
import gostcrypto

key = bytearray(
    b'\xf9\xc0\\\t/`\x18\xfd\x89\x84\xad\xd73\xb85\x0e\xf7\xa5\x8cN\x1e\xdaj\x86\xb1\xc9\xdcN\xeb\xb7\x8f\xb8\xf4X\xb50\x97\xe6>\x91T\xe2\xae;\x83\x867[\t\xf4\xb8d\x93\xb7\xd1\x17\x01\xd0\xa1\x86\xf1\x84\xa0h')
data = b'\xadQ/\x81\x01\x95\x9e\xe33\xd4 s\x18@\xe6/r\xc9!`\xf9\xec;p\x17\x91K\x1c\xad,\xe1\x9d\x18w\xb3U\xee\xf86ZK\x87]\x81\xd7\xab\x04\xc4\x07s\xca.N\xd8\x12\xac\xd9\x8a\xfef\xd9\x04\xbb\x05'
hmac512 = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', key, data=data)
mul = 2
half = int(hmac512.digest_size * mul / 2)
priv = hmac512.hexdigest()[:half]
cc = hmac512.hexdigest()[half:]
pub = public_key(curve, bytes2long(bytearray.fromhex(priv)))
print(hmac512.hexdigest(), hmac512.digest_size * mul)
print("priv", len(priv), priv)
print("cc  ", len(cc), cc)
print("pub ", pub)
print("Pub on curve?:", curve.contains(pub))

#
# 3b693a6a57ecf454ce7e2d2fc25dc77c3bb0700555856c93cc10ea66278f3a37cbf17defd7a68d1ea1143d6f3ed7bc1b7bfe0106af8cc4f4210f52cccf88a6fb 128
# priv 3b693a6a57ecf454ce7e2d2fc25dc77c3bb0700555856c93cc10ea66278f3a37
# cc   cbf17defd7a68d1ea1143d6f3ed7bc1b7bfe0106af8cc4f4210f52cccf88a6fb
# pub  (55286432452028624808170923536962444195464475381031703399486157623384108134715, 51293020563602891928577066033811483094794141206721946630471807727682335466208)
# True
#
# print(len(str(pub[0])), pub[0])
# print(len(str(pub[1])), pub[1])
print()
index = utils.int_to_bytearray(1, 4)
print("Child Index", index)
sec = long2bytes(pub[0]) + long2bytes(pub[1]) + index
hmac512_child1_I = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', bytearray.fromhex(cc), data=sec)
print(hmac512_child1_I.hexdigest(), hmac512_child1_I.digest_size * mul)
I1iL = hmac512_child1_I.hexdigest()[:half]
I1iR = hmac512_child1_I.hexdigest()[half:]
# print(hmac512_child1_I.hexdigest()[:half])
# print(priv)
# priv_child1 = hmac512_child1_I.hexdigest()[:half] + priv
priv_child1: int = bytes2long(bytes.fromhex(I1iL)) + bytes2long(bytes.fromhex(priv))
priv_child1: bytes = long2bytes(priv_child1)
print("priv_child1", len(priv_child1.hex()), priv_child1.hex())
print("cc_child1  ", len(I1iR), I1iR)
print("pub_cild1", public_key(curve, bytes2long(priv_child1)))
print("pub_cild1 on curve?:", curve.contains(public_key(curve, bytes2long(priv_child1))))
pubkey_child1 = public_key(curve, bytes2long(priv_child1))
pubkey_child1 = long2bytes(pubkey_child1[0]) + long2bytes(pubkey_child1[1])
print(len(pubkey_child1.hex()), pubkey_child1.hex())
#
# Child Index bytearray(b'\x00\x00\x00\x01')
# abb8d6bb0c0504a7c52ead0b015aa9f125be90a38870c669928784a908003fd21c9f91b507cc43873fcf05093ca4a511f1a72bc7dd4b105b292e1618ef827726 128
# priv_child1 64 e722112563f1f8fc93acda3ac3b8716d616f00a8ddf632fd5e986f0f2f8f7a09
# cc_child1   64 1c9f91b507cc43873fcf05093ca4a511f1a72bc7dd4b105b292e1618ef827726
# pub_cild1 (48729713990574906546126416746516824287795081346883302862413305923952411488069, 97935377744470577726223953897822461011191911548819517122584738467176857492602)
# pub_cild1 on curve?: True
#
print()

r1 = public_key(curve, bytes2long(bytes.fromhex(I1iL)) + bytes2long(bytes.fromhex(priv)))
r2_ch = public_key(curve, bytes2long(bytes.fromhex(I1iL))) + public_key(curve, bytes2long(bytearray.fromhex(priv)))
# r2 = ((r2_ch[0] + r2_ch[2]) % curve.q, (r2_ch[1]+r2_ch[3])% curve.q)
print(r1)
# print(r2)
r2 = curve._add(r1[0], r1[1], r2_ch[0], r2_ch[1])
print(r2)
print("Pub(from priv)on curve?:", curve.contains(r1))
print("Pub(from pub)on curve?:", curve.contains(r2))

import os
from typing import Tuple
from gostcrypto.gosthmac.r_50_1_113_2016 import R5011132016


class KeyPair(object):
    __CURVE = "id-tc26-gost-3410-2012-256-paramSetB"
    __private_key: str = None
    __chain_key: str = None
    __public_key: Tuple[int, int] = None

    def __init__(self, pk: str, cc: str, pub: Tuple[int, int]):
        self.__private_key = pk
        self.__chain_key = cc
        self.__public_key = pub
        self.__curve: GOST3410Curve = CURVES[self.__CURVE]
        assert self.__curve.contains(self.__public_key)

    def get_pk(self):
        return self.__private_key

    def get_pub(self):
        return self.__public_key

    def get_cc(self):
        return self.__chain_key

    def __str__(self):
        return f"\nON CURVE: {self.__CURVE}\nPrivateKey: {self.__private_key}\nChainCode: {self.__chain_key}\nPublicKey: {self.__public_key}\n"

    def __repr__(self):
        return f"\nON CURVE: {self.__CURVE}\nPrivateKey: {self.__private_key}\nChainCode: {self.__chain_key}\nPublicKey: {self.__public_key}\n"


class HDGost(object):
    CURVE = "id-tc26-gost-3410-2012-256-paramSetB"
    HMAC = "HMAC_GOSTR3411_2012_512"
    MUL = 2
    HALF: int = None
    MASTER: KeyPair

    def __init__(self, key: bytearray = os.urandom(64), seed: bytearray = os.urandom(64)):
        self.curve: GOST3410Curve = CURVES[self.CURVE]
        self.MASTER = KeyPair(
            pk=self.__get_pk_m(key, seed), cc=self.__get_cc_m(key, seed), pub=self.__get_pub_m(key, seed)
        )

    def _get_hmac(self, key: bytearray, data: bytes) -> R5011132016:
        hmac = gostcrypto.gosthmac.new(self.HMAC, key, data=data)
        if self.HALF is None:
            self.HALF = int(hmac.digest_size * mul / 2)
        return hmac

    def __get_pk_m(self, key: bytearray, seed: bytes) -> str:
        return self._get_hmac(key, seed).hexdigest()[:self.HALF]

    def __get_cc_m(self, key: bytearray, seed: bytes) -> str:
        return self._get_hmac(key, seed).hexdigest()[self.HALF:]

    def __get_pub_m(self, key: bytearray, seed: bytes) -> Tuple[int, int]:
        return public_key(curve, bytes2long(bytearray.fromhex(self.__get_pk_m(key, seed))))

    def get_master(self) -> KeyPair:
        return self.MASTER

    def check_on_curve(self, point: Tuple[int, int]) -> bool:
        return self.curve.contains(point)

    def get_child(self, index: str = "0/0/0"):
        child_tree = tuple(int(ch) if int(ch) >= 0 else 0 for ch in index.split("/"))
        if sum(child_tree) < 0:
            return None
        assert len(child_tree) == 3
        account_index = child_tree[0]
        account_chain_index = child_tree[1]
        address_index = child_tree[2]
        account_node = self.__get_child(self.MASTER, account_index)
        account_chain = self.__get_child(account_node, account_chain_index)
        address = self.__get_child(account_chain, address_index)
        return address
        # step1: get account node key pair by master
        # step2: get account_chain node key pair by step1
        # get address key pair by step2

    def __get_child(self, parent: KeyPair, index: int) -> KeyPair:
        hmac = self._get_hmac(bytearray.fromhex(parent.get_cc()), self.__get_child_hmac_data(parent.get_pub(), index))
        I1iL = hmac.hexdigest()[:self.HALF]
        I1iR = hmac.hexdigest()[self.HALF:]
        priv: int = bytes2long(bytes.fromhex(I1iL)) + bytes2long(bytes.fromhex(parent.get_pk()))
        priv: bytes = long2bytes(priv)
        return KeyPair(
            pk=priv.hex(),
            cc=I1iR,
            pub=public_key(curve, bytes2long(priv))
        )

    def __get_child_hmac_data(self, public_key_par: Tuple[int, int], index: int) -> bytes:
        index = utils.int_to_bytearray(index, 4)
        return long2bytes(public_key_par[0]) + long2bytes(public_key_par[1]) + index

# I1iL_parse256 = utils.int_to_bytearray(bytes2long(bytes.fromhex(I1iL)), 32)
# print(len(I1iL_parse256.hex()), I1iL_parse256.hex())
# pub_child1_p1 = public_key(curve, bytes2long(I1iL_parse256))
# print(len(str(pub_child1_p1[0])), len(str(pub_child1_p1[1])))
# pub_child1_p1 = long2bytes(pub_child1_p1[0]) + long2bytes(pub_child1_p1[1])
# print(len(pub_child1_p1.hex()))
#
# pub_child1_p2 = long2bytes(pub[0]) + long2bytes(pub[1])
# print(len(pub_child1_p2.hex()))
# pub_child1 = bytes2long(pub_child1_p1) + bytes2long(pub_child1_p2)
#
# point_ser = utils.int_to_bytearray(pub_child1, 64)
# print(len(point_ser.hex()))
# print(len(long2bytes(pub_child1).hex()), long2bytes(pub_child1).hex())
# pub_child1 = bytes2long(point_ser)
# point = (int(str(pub_child1)[:int(len(str(pub_child1))/2)]), int(str(pub_child1)[int(len(str(pub_child1))/2):]))
# print("pub_cild1 on curve?:", curve.contains(point))

key = bytearray(
    b'\xf9\xc0\\\t/`\x18\xfd\x89\x84\xad\xd73\xb85\x0e\xf7\xa5\x8cN\x1e\xdaj\x86\xb1\xc9\xdcN\xeb\xb7\x8f\xb8\xf4X\xb50\x97\xe6>\x91T\xe2\xae;\x83\x867[\t\xf4\xb8d\x93\xb7\xd1\x17\x01\xd0\xa1\x86\xf1\x84\xa0h')
data = b'\xadQ/\x81\x01\x95\x9e\xe33\xd4 s\x18@\xe6/r\xc9!`\xf9\xec;p\x17\x91K\x1c\xad,\xe1\x9d\x18w\xb3U\xee\xf86ZK\x87]\x81\xd7\xab\x04\xc4\x07s\xca.N\xd8\x12\xac\xd9\x8a\xfef\xd9\x04\xbb\x05'

hd = HDGost(key, bytearray(data))
print(hd.get_master())
print(hd.get_child(index="0/0/0"))

