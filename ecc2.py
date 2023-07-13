from os import urandom
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import prv_marshal
from pygost.gost3410 import public_key, GOST3410Curve
from pygost.gost3410 import pub_marshal
from pygost.utils import hexenc, bytes2long, hexdec
import gostcrypto

base_point = bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"))
curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]


def hex_to_int(hex_str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def point(b) -> bytes:
    if isinstance(b, str):
        return pub_marshal(public_key(curve, hex_to_int(b)))
    elif isinstance(b, int):
        return pub_marshal(public_key(curve, b))
    elif isinstance(b, bytes):
        return pub_marshal(public_key(curve, bytes_to_int(b)))


def lANDr(instance: str):
    return instance[:int(len(instance) / 2)], instance[int(len(instance) / 2):]


def hmac(f: bytearray, s: bytes):
    return gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', f, data=s)


def concat(f, s):
    if type(f) != type(s):
        raise TypeError
    else:
        if type(s) in [bytes, bytearray, str]:
            # print(f)
            # print(s)
            res = f
            res += s[:]
            # print(res)
            return res
        else:
            raise TypeError


def mod(number, mod) -> int:
    return number % mod


#
# seed = urandom(32)
seed = b'\x12\xe6\xb9H:\xb7F+\xf2\xe5\xb2\x00\xb1\xa6\x88nZ\xdb|\x95[gl\r\xfa\x13\x19^\x10\x01n\xd1'
hash = hmac(bytearray(seed), seed)  # 128 hex len
k_hex, CC_hex = lANDr(hash.hexdigest())
K_hex = hexenc(point(k_hex))  # public key
print("Master key: ", k_hex, len(k_hex))
print("Master chain code: ", CC_hex, len(CC_hex))
print("Master Public key: ", K_hex, len(K_hex))
print()

k_bytes = bytes.fromhex(k_hex)
CC_bytes = bytes.fromhex(CC_hex)
K_bytes = bytes.fromhex(K_hex)

#
# индекс
index = 1
index_child_32x = index.to_bytes(32, "big")

#
# дочерний личный ключ из родительского личного
I = hmac(bytearray(CC_bytes), concat(point(k_bytes), index_child_32x))
iL, iR = lANDr(I.hexdigest())
CCi = bytes.fromhex(iR)
ki = mod(hex_to_int(iL) + hex_to_int(k_hex), base_point)
Ki = point(ki)
print(f"{index} Child private key   ", hex(ki)[2:], len(hex(ki)[2:]))  # дочерний личный ключ
print(f"{index} Child chain code key", CCi.hex(), len(CCi.hex()))  # дочерний chain code
print(f"{index} Child public key    ", Ki.hex(), len(Ki.hex()))  # открытый ключ $K_i$
print()

#
# из открытого родительского ключа дочерний открытый ключ
I_new = hmac(bytearray(CC_bytes), concat(K_bytes, index_child_32x))
I_newL, I_newR = lANDr(I_new.hexdigest())
Ki_new = bytes_to_int(point(I_newL)) + bytes_to_int(K_bytes)
CCi_new = bytes.fromhex(I_newR)

print("----")
print(f"{index} Child private key   ", hex(ki)[2:], len(hex(ki)[2:]))  # дочерний личный ключ
print(f"{index} Child chain code key", CCi_new.hex(), len(CCi.hex()))  # дочерний chain code
print(f"{index} Child public key    ", hex(Ki_new)[2:], len(hex(Ki_new)[2:]))  # открытый ключ $K_i$


print(curve.contains((
    int(str(hex_to_int(K_hex))[:int(len(str(hex_to_int(K_hex)))/2)]),
    int(str(hex_to_int(K_hex))[int(len(str(hex_to_int(K_hex)))/2):]),
)))

print(curve.contains((
    int(str(bytes_to_int(Ki))[:int(len(str(bytes_to_int(Ki)))/2)]),
    int(str(bytes_to_int(Ki))[int(len(str(bytes_to_int(Ki)))/2):]),
)))

print(curve.contains((
    int(str(Ki_new)[:int(len(str(Ki_new))/2)]),
    int(str(Ki_new)[int(len(str(Ki_new))/2):]),
)))

