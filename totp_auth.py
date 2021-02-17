import base64
import struct
import hmac
import hashlib
import time


def hotp(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return h


def totp(secret):
    return hotp(secret, intervals_no=int(time.time()) // 30), str(round(30 - time.time() % 30)) + "s"


secret = 'TESTABCDEFGHIJKL'
auth_code, time_left = totp(secret)
print(auth_code, time_left)
