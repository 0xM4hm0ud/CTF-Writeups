#/usr/bin/env python3

from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
import base64

#To get this, you needed to decode the first public key in megan35
n = 667
e = 3 # changed to 3 instead of 5
c = [408,217,382,380,416,613,408,162,604,9,537,146,280]

p = 23
q = 29

phi = (p-1) * (q-1)
d = inverse(e, phi)
m = []
for i in c:
        m += [pow(i, d, n)]
print(bytes(m))

#To get the modulus and private key, I used this command:
#openssl rsa -in a.pub -pubin -text -noout
n = 359567260516027240236814314071842368703501656647819140843316303878351
e = 65537
ciphertext = base64.b64decode("C1qKLBtrUwLkebPf+JKX6ie1bKEdUGmzkYwBJWQ=")
c = bytes_to_long(ciphertext)

#Factored in factordb
p = 17963604736595708916714953362445519
q = 20016431322579245244930631426505729

phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m)[19:-1])

#TamilCTF{y0u_br34k3d}
