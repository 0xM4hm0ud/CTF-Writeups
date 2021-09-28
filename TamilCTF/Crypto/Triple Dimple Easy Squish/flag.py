#!/usr/bin/env python3

from Crypto.Cipher import DES3
from Crypto.Util.number import bytes_to_long
import binascii

ct = bytes.fromhex("59878c3b0190e5161228edb871d44514e761971ab39cd5bfc675050862ea2a0611751867e99ab2d5643b5689e893bf7ca76bc10777030a6a")
key = bytes.fromhex("6b696d696461796f6f6b696d697761616e616e6461796f6f")
iv = bytes.fromhex("a070ae09a4b7627c")

decr = DES3.new(key, DES3.MODE_OFB, iv)
a = decr.decrypt(ct)
print(a)

#TamilCTF{Triplee_DES_iss_quitee_samee_as_DES_isnt_it???}
