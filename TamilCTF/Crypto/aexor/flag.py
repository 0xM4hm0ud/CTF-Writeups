#!/usr/bin/env python3

from Crypto.Cipher import AES
import binascii
from pwn import xor

key = binascii.unhexlify('030e150a0b0415110618111c001b0d1c')
ct = binascii.unhexlify('68e934aa25be2c5f1674e101b31c25672400d69f9cf910a9f64071cea79f2de01d01bcf140105e5f7a3db66fffe64694')
iv = binascii.unhexlify('1cb7942bf4ae14947150f9f196f92b2c')
k = xor(key, b'okay')

decipher = AES.new(k, AES.MODE_CBC, iv)
pt = decipher.decrypt(ct)
print(pt)
#TamilCTF{AESS+XORR_issss_W3irdd_Combinationn???}
