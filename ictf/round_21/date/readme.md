# Date

```
Description
What's the date?

Author
Eth007
```


We got a binary, lets check the arch and the protections etc..:

[img](images/checksec.jpg)

So all protections are enabled and its an 64 bit binary. Lets decompile it in ghidra:

[img](images/ghidra.jpg)

We can see there are values stored on the stack in variables and our input starts at `local_d8` pointing to a variable. We can input 0x80 charachters into fgets. We can also see that system is called with the address at `local_98`. Thats pointing to `/usr/bin/date`. So we can overflow it and change it to `/bin/bash`, We cant overflow till the return pointer because of the canary. 

So lets open it in gdb:

[img](images/gdb.jpg)

