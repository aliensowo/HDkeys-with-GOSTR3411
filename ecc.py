from os import urandom
from six import int2byte, b
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import prv_marshal
from pygost.gost3410 import public_key
from pygost.gost3410 import pub_marshal
from pygost.utils import hexenc, bytes2long, hexdec
import gostcrypto

base_point = bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"))
curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
curve

def int_to_string(x):
    """Convert integer x into a string of bytes, as per X9.62."""
    assert x >= 0
    if x == 0:
        return b("\0")
    result = []
    while x:
        ordinal = x & 0xFF
        result.append(int2byte(ordinal))
        x >>= 8

    result.reverse()
    return b("").join(result)


def string_to_int(s):
    """Convert a string of bytes into an integer, as per X9.62."""
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = 256 * result + c
    return result


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
hash = hmac(bytearray(b"Slovo seed"), seed)  # 128 hex len
k_hex, CC_hex = lANDr(hash.hexdigest())
# K_hex = hexenc(point(k_hex))  # public key
K_hex = point(k_hex).hex()  # public key
print("Master key: ", k_hex, len(k_hex))
print("Master chain code: ", CC_hex, len(CC_hex))
print("Master Public key: ", K_hex, len(K_hex))
print()

k_bytes = bytes.fromhex(k_hex)
CC_bytes = bytes.fromhex(CC_hex)
K_bytes = bytes.fromhex(K_hex)

#
# индекс
index = 9150
index_child_32x = index.to_bytes(32, "big")

#
# дочерний личный ключ из родительского личного
I = hmac(bytearray(CC_bytes), concat(point(k_bytes), index_child_32x))
iL, iR = lANDr(I.hexdigest())
CCi = bytes.fromhex(iR)
ki = hex_to_int(iL) + hex_to_int(k_hex)
Ki = point(ki)
# Ki = point(hex_to_int(iL) + hex_to_int(k_hex))
# Ki = bytes_to_int(point(I_newL)) + hex_to_int(K_hex) = bytes_to_int(point(I_newL)) + hex_to_int(hexenc(point(k_hex)))
print(f"path /{index}' Child private key   ", hex(ki)[2:], len(hex(ki)[2:]))  # дочерний личный ключ
print(f"path /{index}' Child chain code key", CCi.hex(), len(CCi.hex()))  # дочерний chain code
print(f"path /{index}' Child public key    ", Ki.hex(), len(Ki.hex()))  # открытый ключ $K_i$
print()
#
# из открытого родительского ключа дочерний открытый ключ
I_new = hmac(bytearray(CC_bytes), concat(K_bytes, index_child_32x))
I_newL, I_newR = lANDr(I_new.hexdigest())
# Ki_new = bytes_to_int(point(I_newL)) + hex_to_int(K_hex)
Ki_new = bytes_to_int(point(I_newL)) + hex_to_int(point(k_hex).hex())
Ki_bytes = Ki_new.to_bytes(64, "big")
CCi_new = bytes.fromhex(I_newR)

print("----")
print(f"{index} Child private key   ", hex(ki)[2:], len(hex(ki)[2:]))  # дочерний личный ключ
print(f"{index} Child chain code key", CCi_new.hex(), len(CCi.hex()))  # дочерний chain code
print(f"{index} Child public key    ", Ki_bytes.hex(), len(Ki_bytes.hex()))  # открытый ключ $K_i$


index2 = 5
index_child_32x2 = index.to_bytes(32, "big")
I2 = hmac(bytearray(CCi), concat(point(ki), index_child_32x2))
iL2, iR2 = lANDr(I2.hexdigest())
CCi2 = bytes.fromhex(iR2)
ki2 = hex_to_int(iL2) + ki
Ki2 = point(ki)
print(f"path /{index}'/{index2}' Child private key   ", hex(ki2)[2:], len(hex(ki2)[2:]))  # дочерний личный ключ
print(f"path /{index}'/{index2}' Child chain code key", CCi2.hex(), len(CCi2.hex()))  # дочерний chain code
print(f"path /{index}'/{index2}' Child public key    ", Ki2.hex(), len(Ki2.hex()))  # открытый ключ $K_i$
print()

index3 = 3
index_child_32x3 = index.to_bytes(32, "big")
I3 = hmac(bytearray(CCi2), concat(point(ki2), index_child_32x3))
iL3, iR3 = lANDr(I3.hexdigest())
CCi3 = bytes.fromhex(iR3)
ki3 = hex_to_int(iL3) + ki2
Ki3 = point(ki2)
print(f"path /{index}'/{index2}'/{index3} Child private key   ", hex(ki3)[2:], len(hex(ki3)[2:]))  # дочерний личный ключ
print(f"path /{index}'/{index2}'/{index3} Child chain code key", CCi3.hex(), len(CCi3.hex()))  # дочерний chain code
print(f"path /{index}'/{index2}'/{index3} Child public key    ", Ki3.hex(), len(Ki3.hex()))  # открытый ключ $K_i$
print()



#
# из открытого родительского ключа дочерний открытый ключ
I_new = hmac(bytearray(CC_bytes), concat(K_bytes, index_child_32x))
I_newL, I_newR = lANDr(I_new.hexdigest())
# Ki_new = bytes_to_int(point(I_newL)) + hex_to_int(K_hex)
Ki_new = bytes_to_int(point(I_newL)) + hex_to_int(point(k_hex).hex())
Ki_bytes = Ki_new.to_bytes(64, "big")
CCi_new = bytes.fromhex(I_newR)

print("----")
print(f"{index} Child private key   ", hex(ki)[2:], len(hex(ki)[2:]))  # дочерний личный ключ
print(f"{index} Child chain code key", CCi_new.hex(), len(CCi.hex()))  # дочерний chain code
print(f"{index} Child public key    ", Ki_bytes.hex(), len(Ki_bytes.hex()))  # открытый ключ $K_i$

