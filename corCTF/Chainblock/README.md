# Chainblock

<img src="Images/challenge.png" width="700" >

After downloading the tar file, we untar it and we get some files:

<img src="Images/files.png" width="700" >


The script is:
```c
#include <stdio.h>

char* name = "Techlead";
int balance = 100000000;

void verify() {
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);

	if (strcmp(buf, name) != 0) {
		printf("KYC failed, wrong identity!\n");
		return;
	}

	printf("Hi %s!\n", name);
	printf("Your balance is %d chainblocks!\n", balance);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("      ___           ___           ___                       ___     \n");
	printf("     /\\  \\         /\\__\\         /\\  \\          ___        /\\__\\    \n");
	printf("    /::\\  \\       /:/  /        /::\\  \\        /\\  \\      /::|  |   \n");
	printf("   /:/\\:\\  \\     /:/__/        /:/\\:\\  \\       \\:\\  \\    /:|:|  |   \n");
	printf("  /:/  \\:\\  \\   /::\\  \\ ___   /::\\~\\:\\  \\      /::\\__\\  /:/|:|  |__ \n");
	printf(" /:/__/ \\:\\__\\ /:/\\:\\  /\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/ |:| /\\__\\\n");
	printf(" \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/__\\:\\/:/  / /\\/:/  /    \\/__|:|/:/  /\n");
	printf("  \\:\\  \\            \\::/  /       \\::/  /  \\::/__/         |:/:/  / \n");
	printf("   \\:\\  \\           /:/  /        /:/  /    \\:\\__\\         |::/  /  \n");
	printf("    \\:\\__\\         /:/  /        /:/  /      \\/__/         /:/  /   \n");
	printf("     \\/__/         \\/__/         \\/__/                     \\/__/    \n");
	printf("      ___           ___       ___           ___           ___     \n");
	printf("     /\\  \\         /\\__\\     /\\  \\         /\\  \\         /\\__\\    \n");
	printf("    /::\\  \\       /:/  /    /::\\  \\       /::\\  \\       /:/  /    \n");
	printf("   /:/\\:\\  \\     /:/  /    /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     \n");
	printf("  /::\\~\\:\\__\\   /:/  /    /:/  \\:\\  \\   /:/  \\:\\  \\   /::\\__\\____ \n");
	printf(" /:/\\:\\ \\:|__| /:/__/    /:/__/ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:::::\\__\\\n");
	printf(" \\:\\~\\:\\/:/  / \\:\\  \\    \\:\\  \\ /:/  / \\:\\  \\  \\/__/ \\/_|:|~~|~   \n");
	printf("  \\:\\ \\::/  /   \\:\\  \\    \\:\\  /:/  /   \\:\\  \\          |:|  |    \n");
	printf("   \\:\\/:/  /     \\:\\  \\    \\:\\/:/  /     \\:\\  \\         |:|  |    \n");
	printf("    \\::/__/       \\:\\__\\    \\::/  /       \\:\\__\\        |:|  |    \n");
	printf("     ~~            \\/__/     \\/__/         \\/__/         \\|__|    \n");
	printf("\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("Welcome to Chainblock, the world's most advanced chain of blocks.\n\n");

	printf("Chainblock is a unique company that combines cutting edge cloud\n");
	printf("technologies with high tech AI powered machine learning models\n");
	printf("to create a unique chain of blocks that learns by itself!\n\n");

	printf("Chainblock is also a highly secure platform that is unhackable by design.\n");
	printf("We use advanced technologies like NX bits and anti-hacking machine learning models\n");
	printf("to ensure that your money is safe and will always be safe!\n\n");

	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("For security reasons we require that you verify your identity.\n");

	verify();
}
```
We have a libc file and the binary, so what I thought is ret2libc. We can check it.

First of all we can see its and 64 bit executable.

Secondly we see that we have an buffer overlow because of gets(). 
It takes 255 chars in the buffer and gets() keeps on reading until it sees a newline charachter, so if we put more than the buffer, we will overflowe it:

```c
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);
```

Now with an buffer overflow, we are normally using shellcode to ececute something on the stack but for this challenge as we can read here:
```
"We use advanced technologies like NX bits and anti-hacking machine learning model"
```
We can check it with checksec:

<img src="Images/checksec.png" width="500" >

It have NX enabled: NX is:

```
Nx is short-hand for Non-Executable stack. What this means is that the stack region of memory is not executable. So if there is perfectly valid code there, you can't execute it due to it's permissions.
```
So we can't execute something on the stack. So what we need to do is ret2libc(return to libc) and execute a function from there.

## Exploit

First of all we need to find the offset of the buffer overflow:
I will do this in gdb:

<img src="Images/pattern.png" width="800" >

Run the program an enter you pattern:

<img src="Images/segfault.png" width="800" >

we get an segmentation fault.

Now we check the offset:

<img src="Images/offset.png" width="800" >

We found the offset at 260.


