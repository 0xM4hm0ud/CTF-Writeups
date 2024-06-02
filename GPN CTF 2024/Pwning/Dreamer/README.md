# Dreamer

|||
|-|-|
|  **CTF**  |  [GPN CTF](https://play.ctf.kitctf.de/) [(CTFtime)](https://ctftime.org/event/2257)  |
|  **Author** |  s1nn105 |
|  **Category** |  Pwning |
|  **Solves** |  10  |
| **Files** |  [dreamer.tar.gz](<dreamer.tar.gz>)  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/f3dba998-461a-452d-bb00-00c4346a85be)

# Solution

After unzipping, we get the source code of the challenge:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#define ROTL(X, N)  (((X) << (N)) | ((X) >> (8 * sizeof(X) - (N))))
#define ROTR(X, N)  (((X) >> (N)) | ((X) << (8 * sizeof(X) - (N))))
unsigned long STATE; 
unsigned long CURRENT;

char custom_random(){
    STATE = ROTL(STATE,30) ^ ROTR(STATE,12) ^ ROTL(STATE,42) ^ ROTL(STATE,4) ^ ROTR(STATE,5);
    return STATE % 256;

}

void* experience(long origin){
  char* ccol= mmap (0,1024, PROT_READ|PROT_WRITE|PROT_EXEC,
              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    size_t k = 0;
    while(k<106){
        *(ccol+k) = 0x90; //nop just in case;
        k++;
    }
    k=16;
    *((int*)ccol) = origin;
    while(k<100){
        *(ccol+k)=custom_random();
        k++;
    }
    return ccol;

}

void sleepy(void * dream){
    int (*d)(void) = (void*)dream;
    d();
}


void win(){
    execv("/bin/sh",NULL);
}

void setup(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(){
    setup();
    long seed=0;
    printf("the win is yours at %p\n", win);
    scanf("%ld",&seed); 
    STATE = seed;
    printf("what are you thinking about?");
    scanf("%ld",&seed);
    sleepy(experience(seed));
}
```

We can see that we can provide a seed two times. The first one is stored in a global variable STATE, and the other one is given to the experience function. 

In the experience function, a read-write-execute (RWX) memory section is created, and 160 NOPs are inserted. Then, the origin value is placed at the start of the section. The origin value corresponds to the last seed we provide.
Subsequently, the function runs 84 times, calling custom_random() each time. This function performs some encryption based on our STATE. After this, the function sleepy() executes our shellcode.

Initially, I considered brute-forcing all possibilities to obtain a valid shellcode at the end the correct way, but that would be infeasible.

### How can we call the win function?
When the shellcode is called with `call rax`, the return address is pushed onto the stack. Since the return address is in the binary section, it is close to the win function.

Here is the stack before calling our shellcode:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/2834716d-0b3f-41e2-95a8-10cf4eaa5c6d)

Here is the stack after calling our shellcode:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/d61aac97-46a0-428c-8cf5-a2dd9ac7b706)

Thus, we can calculate the offset between the return address and the win function:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/7d5569fd-bdbd-4d68-86c2-4eb962cd1d1f)

The offset is 3. Therefore, we can add 3 to the pointer at rsp(top of the stack, our return address) and then return. We need to put this payload in the origin. This is because the other one gets encrypted.
We only have 4 bytes to do this, because it casts `*((int*)ccol) = origin;`.

We can use the [shell-storm](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=add+byte+ptr+%5Brsp%5D%2C+3&arch=x86-64&as_format=hex#assembly) assembler:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/e2c0c9d5-4562-45ee-b525-8af3805e52f0)

We need to convert this to decimal. We can do this in python. We need to reverse the order because of the endianness:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/daf96679-b365-49c0-be4a-25c2ad010be2)

For the ret instruction to call the win function, we need to find a number that will become ret after encryption. You can easily brute-force this and find that using 108 will become ret.

So if we submit both and check in gdb, we can observe this:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/029603d8-ffa9-4cb2-9fc0-874b88854589)

We can see that we increased the pointer by 3. It is now pointing to the win function.
If we step through to skip the NOPs, we can see our ret:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/d1ea21aa-9222-4c30-9c5c-fe9a5b553390)

So now it will return to the win function and get the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/5955a1f1-c367-4f36-981d-174acd598437)



