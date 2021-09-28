#!/usr/bin/env python3

import base64
from Crypto.Cipher import AES

key = b'keytamilctf2021!' # To get the key, you needed to encode it to base64, then decode from binary
ct = 'oPgiWmZzdeMhyA80iS9c6la2TlIuIJ1HFRAEvH+8zgo='
base = base64.b64decode(ct)

decipher = AES.new(key, AES.MODE_ECB)
pt = decipher.decrypt(base)
print(pt)

#TamilCTF{bL0ckS_ar3_Br34kabL3!!}
