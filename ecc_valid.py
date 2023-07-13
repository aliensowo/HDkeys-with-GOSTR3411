import os
from typing import Tuple
from pygost.gost3410 import GOST3410Curve, CURVES
from pygost.gost3410 import public_key
from pygost.utils import bytes2long, long2bytes
import gostcrypto
from gostcrypto.utils import utils
from gostcrypto.gosthmac.r_50_1_113_2016 import R5011132016


class KeyPair(object):
    __CURVE = "id-tc26-gost-3410-2012-256-paramSetB"
    __private_key: str = None
    __chain_key: str = None
    __public_key: Tuple[int, int] = None
    __index: str = None

    def __init__(self, pk: str, cc: str, pub: Tuple[int, int], index: str = None):
        self.__private_key = pk
        self.__chain_key = cc
        self.__public_key = pub
        self.__curve: GOST3410Curve = CURVES[self.__CURVE]
        self.__index = index
        assert self.__curve.contains(self.__public_key)

    def get_pk(self):
        return self.__private_key

    def get_pub(self):
        return self.__public_key

    def get_cc(self):
        return self.__chain_key

    def __get_description(self):
        description = f"\nCurve: {self.__CURVE}\nPrivateKey: {self.__private_key}\nChainCode: {self.__chain_key}\nPublicKey: {self.__public_key}"
        if self.__index:
            description += f"\nIndex: {self.__index}"
        return description + "\n"

    def __str__(self):
        return self.__get_description()

    def __repr__(self):
        return self.__get_description()


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
            self.HALF = int(hmac.digest_size * self.MUL / 2)
        return hmac

    def __get_pk_m(self, key: bytearray, seed: bytes) -> str:
        return self._get_hmac(key, seed).hexdigest()[:self.HALF]

    def __get_cc_m(self, key: bytearray, seed: bytes) -> str:
        return self._get_hmac(key, seed).hexdigest()[self.HALF:]

    def __get_pub_m(self, key: bytearray, seed: bytes) -> Tuple[int, int]:
        return public_key(self.curve, bytes2long(bytearray.fromhex(self.__get_pk_m(key, seed))))

    def get_master(self) -> KeyPair:
        return self.MASTER

    def check_on_curve(self, point: Tuple[int, int]) -> bool:
        return self.curve.contains(point)

    def get_child(self, index: str = "0/0/0"):
        child_tree = tuple(int(ch) if int(ch) >= 0 else 0 for ch in index.split("/"))
        if sum(child_tree) < 0:
            return None
        assert len(child_tree) in range(3, 5)
        account_index = child_tree[0]
        account_chain_index = child_tree[1]
        address_index = child_tree[2]
        account_node = self.__get_child(self.MASTER, account_index)
        account_chain = self.__get_child(account_node, account_chain_index)
        address = self.__get_child(account_chain, address_index, index)
        return address
        # step1: get account node key pair by master
        # step2: get account_chain node key pair by step1
        # get address key pair by step2

    def __get_child(self, parent: KeyPair, index: int, full_path: str = None) -> KeyPair:
        hmac = self._get_hmac(bytearray.fromhex(parent.get_cc()), self.__get_child_hmac_data(parent.get_pub(), index))
        I1iL = hmac.hexdigest()[:self.HALF]
        I1iR = hmac.hexdigest()[self.HALF:]
        priv: int = bytes2long(bytes.fromhex(I1iL)) + bytes2long(bytes.fromhex(parent.get_pk()))
        priv: bytes = long2bytes(priv)
        return KeyPair(
            pk=priv.hex(),
            cc=I1iR,
            pub=public_key(self.curve, bytes2long(priv)),
            index=full_path
        )

    def __get_child_hmac_data(self, public_key_par: Tuple[int, int], index: int) -> bytes:
        index = utils.int_to_bytearray(index, 4)
        return long2bytes(public_key_par[0]) + long2bytes(public_key_par[1]) + index


key = bytearray(
    b'\xf9\xc0\\\t/`\x18\xfd\x89\x84\xad\xd73\xb85\x0e\xf7\xa5\x8cN\x1e\xdaj\x86\xb1\xc9\xdcN\xeb\xb7\x8f\xb8\xf4X\xb50\x97\xe6>\x91T\xe2\xae;\x83\x867[\t\xf4\xb8d\x93\xb7\xd1\x17\x01\xd0\xa1\x86\xf1\x84\xa0h')
data = b'\xadQ/\x81\x01\x95\x9e\xe33\xd4 s\x18@\xe6/r\xc9!`\xf9\xec;p\x17\x91K\x1c\xad,\xe1\x9d\x18w\xb3U\xee\xf86ZK\x87]\x81\xd7\xab\x04\xc4\x07s\xca.N\xd8\x12\xac\xd9\x8a\xfef\xd9\x04\xbb\x05'

hd = HDGost(key, bytearray(data))
print(hd.get_master())
print(hd.get_child(index="0/0/0"))
print(hd.get_child(index="1/0/0"))
print(hd.get_child(index="1/15/0"))
print(hd.get_child(index="1/15/9"))
print(hd.get_child(index="1/15/9/1"))
print(hd.get_child(index="1/15/9/10"))
