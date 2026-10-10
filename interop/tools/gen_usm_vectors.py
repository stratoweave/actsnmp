#!/usr/bin/env python3
"""Generate extra SNMPv3 USM vectors for test_usm.act and cross-check them with pysnmp.

These are the N_* vectors of src/test_usm.act (SHA-224/384 MACs, AES-192/256
Blumenthal and Reeder with short hashes, 3DES, DES responses, boots and time
at 2^31-1). They are committed for reproducibility; test_usm.act holds the
output and does not run this script.

Generation: own BER encoder + hashlib/hmac + cryptography (no pysnmp code).
Check: pysnmp 7.1.30 localize_key (auth and priv incl. Blumenthal/Reeder),
pyasn1 decoding of the whole message, pysnmp authenticate_incoming_message,
pysnmp decrypt_data, pyasn1 decoding of the ScopedPDU.

Run it in the lab image (interop/build.sh builds actsnmp-interop:1):

    docker run --rm -i actsnmp-interop:1 python3 -W ignore - < interop/tools/gen_usm_vectors.py

For each case it prints the name, the localized keys, the MAC offset and
length, and the message in hex.
"""
import hashlib, hmac, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

HASH = {'MD5': hashlib.md5, 'SHA': hashlib.sha1, 'SHA-224': hashlib.sha224,
        'SHA-256': hashlib.sha256, 'SHA-384': hashlib.sha384, 'SHA-512': hashlib.sha512}
MACLEN = {'MD5': 12, 'SHA': 12, 'SHA-224': 16, 'SHA-256': 24, 'SHA-384': 32, 'SHA-512': 48}
PRIV_KEYLEN = {'DES': 16, 'AES': 16, 'AES192': 24, 'AES256': 32, 'AES192C': 24, 'AES256C': 32, '3DES': 32}

def p2k(auth, pw):
    data = (pw * (1048576 // len(pw) + 1))[:1048576]
    return HASH[auth](data).digest()

def loc(auth, ku, e):
    return HASH[auth](ku + e + ku).digest()

def privkey(auth, priv, pw, e):
    kul = loc(auth, p2k(auth, pw), e)
    need = PRIV_KEYLEN[priv]
    k = kul
    if priv in ('AES192', 'AES256'):
        while len(k) < need:
            k += HASH[auth](k).digest()
    elif priv in ('AES192C', 'AES256C', '3DES'):
        while len(k) < need:
            k += loc(auth, p2k(auth, k), e)
    return k[:need]

def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(t, c):
    return bytes([t]) + blen(len(c)) + c

def bint(v):
    n = 1
    while True:
        try:
            return tlv(2, v.to_bytes(n, 'big', signed=True))
        except OverflowError:
            n += 1

def boid(arcs):
    out = [arcs[0] * 40 + arcs[1]]
    body = b''
    for a in [out[0]] + arcs[2:]:
        chunk = [a & 0x7f]
        a >>= 7
        while a:
            chunk.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        body += bytes(chunk)
    return tlv(6, body)

def scoped(ceid, cname, pdu_tag, rid, varbinds):
    vbl = tlv(0x30, b''.join(tlv(0x30, boid(o) + v) for o, v in varbinds))
    pdu = tlv(pdu_tag, bint(rid) + bint(0) + bint(0) + vbl)
    return tlv(0x30, tlv(4, ceid) + tlv(4, cname) + pdu)

def build(msg_id, flags, eid, boots, time, user, sc, auth=None, akey=None, priv=None, pkey=None, salt=b''):
    pp = b''
    if flags & 2:
        if priv in ('DES', '3DES'):
            k, pre = (pkey[:8], pkey[8:16]) if priv == 'DES' else (pkey[:24], pkey[24:32])
            iv = bytes(a ^ b for a, b in zip(pre, salt))
            pt = sc + bytes((-len(sc)) % 8)
            alg = TripleDES(k * 3 if priv == 'DES' else k)
            ct = Cipher(alg, modes.CBC(iv)).encryptor().update(pt)
        else:
            iv = struct.pack('>II', boots, time) + salt
            ct = Cipher(algorithms.AES(pkey), modes.CFB(iv)).encryptor().update(sc)
        pp = salt
        data = tlv(4, ct)
    else:
        data = sc
    n = MACLEN[auth] if flags & 1 else 0
    before = tlv(4, eid) + bint(boots) + bint(time) + tlv(4, user)
    ah = bytes([4]) + blen(n)
    spc = before + ah + bytes(n) + tlv(4, pp)
    sps = tlv(0x30, spc)
    spos = tlv(4, sps)
    off_in = (len(spos) - len(sps)) + (len(sps) - len(spc)) + len(before) + len(ah)
    ver = bint(3)
    gd = tlv(0x30, bint(msg_id) + bint(65507) + tlv(4, bytes([flags])) + bint(3))
    body = ver + gd + spos + data
    whole = tlv(0x30, body)
    off = (len(whole) - len(body)) + len(ver) + len(gd) + off_in
    assert whole[off:off + n] == bytes(n)
    if flags & 1:
        mac = hmac.new(akey, whole, HASH[auth]).digest()[:n]
        whole = whole[:off] + mac + whole[off + n:]
    return whole, off

E = bytes.fromhex('80001f88800102030405060708')
SYSDESCR = [1, 3, 6, 1, 2, 1, 1, 1, 0]
GET_SC = scoped(E, b'', 0xa0, 0x0a0b0c0d, [(SYSDESCR, b'\x05\x00')])
RESP_SC = scoped(E, b'ctx', 0xa2, 0x0a0b0c0d, [(SYSDESCR, tlv(4, b'actsnmp-v3-spec-test'))])

# name, user, auth, priv, flags, boots, time, salt bytes (as on the wire), scoped
CASES = [
    ('N-MD5-AUTHNOPRIV', b'md5only', 'MD5', None, 0x05, 1, 150, b'', GET_SC),
    ('N-SHA224-AUTHNOPRIV', b'sha224only', 'SHA-224', None, 0x05, 1, 150, b'', GET_SC),
    ('N-SHA384-AUTHNOPRIV', b'sha384only', 'SHA-384', None, 0x05, 1, 150, b'', GET_SC),
    ('N-SHA224-AES192', b'sha224aes192', 'SHA-224', 'AES192', 0x07, 1, 150, bytes.fromhex('deadbeef00000010'), GET_SC),
    ('N-SHA384-AES256C', b'sha384aes256c', 'SHA-384', 'AES256C', 0x07, 1, 150, bytes.fromhex('deadbeef00000011'), GET_SC),
    ('N-MD5-AES192', b'md5aes192', 'MD5', 'AES192', 0x07, 1, 150, bytes.fromhex('deadbeef00000012'), GET_SC),
    ('N-MD5-AES256C', b'md5aes256c', 'MD5', 'AES256C', 0x07, 1, 150, bytes.fromhex('deadbeef00000013'), GET_SC),
    ('N-SHA224-AES256C', b'sha224aes256c', 'SHA-224', 'AES256C', 0x07, 1, 150, bytes.fromhex('deadbeef00000014'), GET_SC),
    ('N-SHA256-AES192', b'sha256aes192', 'SHA-256', 'AES192', 0x07, 1, 150, bytes.fromhex('deadbeef00000006'), GET_SC),
    ('N-SHA-3DES', b'sha3des', 'SHA', '3DES', 0x07, 1, 150, bytes.fromhex('000000010000002c'), GET_SC),
    ('N-MD5-3DES', b'md53des', 'MD5', '3DES', 0x07, 1, 150, bytes.fromhex('000000010000002d'), GET_SC),
    ('N-MD5-DES-RESPONSE', b'md5des', 'MD5', 'DES', 0x03, 7, 100000, bytes.fromhex('0000000712345678'), RESP_SC),
    ('N-SHA512-AES256-RESPONSE', b'sha512aes256', 'SHA-512', 'AES256', 0x03, 2147483647, 2147483647,
     bytes.fromhex('ffffffffffffffff'), RESP_SC),
]

def pysnmp_check(name, wire, off, auth, priv, user, boots, time, salt, sc):
    from pyasn1.codec.ber import decoder
    from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
    from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters
    from pysnmp.proto.secmod.rfc3414 import localkey
    from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
    from pysnmp.proto.secmod.rfc7860.auth import hmacsha2
    from pysnmp.proto.secmod.rfc3414.priv import des
    from pysnmp.proto.secmod.rfc3826.priv import aes
    from pysnmp.proto.secmod.eso.priv import aes192, aes256, des3
    from pysnmp.proto import rfc1905
    from pysnmp.proto.mpmod.rfc3412 import ScopedPDU
    H2 = hmacsha2.HmacSha2
    auth_oid = {'MD5': hmacmd5.HmacMd5.SERVICE_ID, 'SHA': hmacsha.HmacSha.SERVICE_ID,
                'SHA-224': H2.SHA224_SERVICE_ID, 'SHA-256': H2.SHA256_SERVICE_ID,
                'SHA-384': H2.SAH384_SERVICE_ID, 'SHA-512': H2.SHA512_SERVICE_ID}[auth]
    authsvc = {'MD5': hmacmd5.HmacMd5(), 'SHA': hmacsha.HmacSha()}.get(auth) or H2(auth_oid)
    from pyasn1.type import univ
    EO = univ.OctetString(E)
    akey = authsvc.localize_key(authsvc.hash_passphrase(b'authpassword'), EO)
    m, rest = decoder.decode(wire, asn1Spec=SNMPv3Message())
    assert not rest
    sp, rest = decoder.decode(bytes(m['msgSecurityParameters']), asn1Spec=UsmSecurityParameters())
    assert not rest
    assert bytes(sp['msgUserName']) == user and int(sp['msgAuthoritativeEngineBoots']) == boots
    assert int(sp['msgAuthoritativeEngineTime']) == time
    ap = sp['msgAuthenticationParameters']
    assert wire[off:off + len(ap)] == bytes(ap)
    authsvc.authenticate_incoming_message(akey, ap, wire)   # raises on mismatch
    if priv is None:
        assert m['msgData']['plaintext'] is not None
        return akey, b''
    privsvc = {'DES': des.Des(), 'AES': aes.Aes(), 'AES192': aes192.AesBlumenthal192(),
               'AES256': aes256.AesBlumenthal256(), 'AES192C': aes192.Aes192(), 'AES256C': aes256.Aes256(),
               '3DES': des3.Des3()}[priv]
    pkey = privsvc.localize_key(auth_oid, privsvc.hash_passphrase(auth_oid, b'privpassword'), EO)
    assert bytes(sp['msgPrivacyParameters']) == salt
    plain = privsvc.decrypt_data(pkey, (boots, time, sp['msgPrivacyParameters']), m['msgData']['encryptedPDU'])
    plain = bytes(plain)
    assert plain[:len(sc)] == sc, name
    s, rest = decoder.decode(plain, asn1Spec=ScopedPDU())
    return bytes(akey), bytes(pkey)

for name, user, auth, priv, flags, boots, time, salt, sc in CASES:
    akey = loc(auth, p2k(auth, b'authpassword'), E)
    pkey = privkey(auth, priv, b'privpassword', E) if priv else b''
    wire, off = build(0x01020304, flags, E, boots, time, user, sc, auth, akey, priv, pkey, salt)
    pa, pp = pysnmp_check(name, wire, off, auth, priv, user, boots, time, salt, sc)
    assert pa == akey and pp == pkey, name
    print('==', name)
    print('authKey', akey.hex())
    if priv:
        print('privKey', pkey.hex())
    print('offset', off, 'len', MACLEN[auth])
    print('msg', wire.hex())
