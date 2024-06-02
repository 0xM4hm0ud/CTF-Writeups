# Future of Pwning 1

|||
|-|-|
|  **CTF**  |  [GPN CTF](https://play.ctf.kitctf.de/) [(CTFtime)](https://ctftime.org/event/2257)  |
|  **Author** |  Ordoviz |
|  **Category** |  Pwning |
|  **Solves** |  63  |
| **Files** |  [future-of-pwning-1.tar.gz](<future-of-pwning-1.tar.gz>)  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/146756d9-f98d-4a6c-bff6-ec281aa0e3da)

# Solution

After unzipping the file, we can see a few files. 

If we check the Dockerfile, we can see that it uses an emulator from Github.

```Dockerfile
# docker build -t future-of-pwning-1 . && docker run -p 5000:5000 --rm -it future-of-pwning-1
FROM python:3.12

RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential curl \
&& apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask

RUN curl -L https://github.com/ForwardCom/bintools/archive/779c06891cba05a97a214a23b7a63aeff25d983a.tar.gz | tar zxf -
WORKDIR bintools-779c06891cba05a97a214a23b7a63aeff25d983a
RUN make -f forw.make && mkdir /app && cp forw instruction_list.csv /app

WORKDIR /app

ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /flag

COPY app.py ./
EXPOSE 5000
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0"]
```

It compiles the emulator and runs `app.py`. Let's check `app.py`:

```py
from flask import Flask, request, redirect, url_for
import subprocess

app = Flask(__name__)


@app.route("/")
def upload_form():
    return """
    <!doctype html>
    <html>
    <body>
        <h2>ForwardCom Emulator</h2>
        Please upload a binary to emulate.
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return redirect(url_for("upload_form"))
    file = request.files["file"]
    file.save("/tmp/binary.ex")
    data = subprocess.check_output(["/app/forw", "-emu", "/tmp/binary.ex"])
    return data[-500:]

if __name__ == "__main__":
    app.run(debug=False)
```

So `app.py` just runs a Flask web server where we can upload a binary, and it will emulate it with `forw`. 
We can also see an `instruction_list.csv` file. This file is just added so that the emulator can work. 

If we run the binary `forw`, we can see a few things we can do in the help menu:

```
Usage: forw command [options] inputfile [outputfile] [options]                                                                                                                      
                                                                                                                                                                                    
Command:                                                                                                                                                                            
-ass       Assemble                                                                                                                                                                 
                                                                                                                                                                                    
-dis       Disassemble object or executable file                                                                                                                                    
                                                                                                                                                                                    
-link      Link object files into executable file                                                                                                                                   
                                                                                                                                                                                    
-relink    Relink and modify executable file                                                                                                                                        

-lib       Build or manage library file                                                   

-emu       Emulate and debug executable file                                              

-dump-XXX  Dump file contents to console.                                                 
           Values of XXX (can be combined):                                               
           f: File header, h: section Headers, s: Symbol table,                           
           m: Relinkable modules, r: Relocation table, n: string table.                   

-help      Print this help screen.

....

Example:                                     
forw -ass test.as test.ob                    
forw -link test.ex test.ob libc.li           
forw -emu test.ex -list=debugout.txt 
```

So our goal is to make a binary that when emulated will give us the flag. 
When I googled for the emulator, I found a nice [documentation](https://www.agner.org/optimize/forwardcom.pdf) about it.

I also used the [Github](https://github.com/ForwardCom/code-examples/tree/master) page with examples.

In chapter 12.4, we can read about the calling convention.
It states that:
`The first 16 parameters to a function that fit into a general purpose register are transferred in register r0 – r15. The first 16 parameters that fit into a vector register are transferred in v0 – v15`

We can also read about the return value:

`
Function return values follow the following rules: A single return value is returned in r0 or v0, using the same rules as for function parameters.
Multiple return values of the same type are treated as a tuple if possible and returned in v0 if the
total size is no more than 16 bytes.
A function with two return values will use two registers for return, using two of the registers r0,
r1, v0, v1 as appropriate, if each of the two values will fit into a single register according to the
above rules. For example, a function can return a result in v0 and an error code in r0. Or a function can return two vectors of variable length.
`

We can also read how to create a section(in the code example part of the documentation):

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/a2cada1f-fd13-430c-951d-835a8cb65e46)

Also for calling external functions. 

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/530c0ec5-bc3f-4ee1-94c7-d208b0f247a6)

I downloaded the `libc.li` from this Github [repository](https://github.com/ForwardCom/libraries).
We can also see all supported functions. 

To make it easier, let's create a script:

```bash
#!/bin/bash

./forw -ass test.as test.ob
./forw -link test.ex test.ob libc.li
./forw -emu test.ex
```

Now we can start with creating our assembly file:

```as
// Here we define a section with 2 strings that I will use later in fopen.
const section read ip                         
file: int8 "/flag", 0   
md: int8 "rb", 0
const end

// Here I create another section that is writable. I also use uninitialized, so the section only coontains zeroes. 
bss section datap uninitialized
int64 buffer[80]
bss end

// Here I start the code section. So this will be executed. 
code section execute align = 4
extern _fread: function // Calling external function from libc.li
extern _fopen: function
extern _puts: function

_main function public   // Defining the main function                                             

int64 r0 = address([file])  // Here I put the address of the file variable I defined above in r0
int64 r1 = address([md])    // Here I put the address of the md variable I defined above in r1               
call _fopen                 // Here I call fopen with the arguments. So it will run fopen("/flag", "rb")
int64 r15 = r0              // The return value of fopen will be the fd. I put it in a random register that I can use later. In this case r15

int64 r0 = address([buffer]) // Here I put the address of the buffer in r0
int64 r1 = 1                 // This is the size in bytes that fread will use to read 
int64 r2 = 80                // This is the number of elements that fread will use to read
int64 r3 = r15               // Here I put the fd from fopen in r3
call _fread                  // Here I call fread like this: fread(buffer, 1, 80, fd)

int64 r0 = address([buffer]) 
call _puts                   // Now after fread the flag will be in buffer, so we can print it out. 

// Here we just clear and exit
int r0 = 0                             
return                                           

_main end
code end
```

So it actually does this:

```c
int main() {
  int fd;
  char buffer[80] = {};

  fd = fopen("/flag", "rb");
  fread(buffer, 1, 80, fd);
  puts(buffer);
  return 0;
}
```

Let's create a fake flag at `/flag`, so we can compile without errors. 
After compiling, we can see that it prints the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/8053cb56-4d73-4cbd-8969-99690be10c2f)

If we upload this binary, we get the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/ae7b5d5b-a39b-4563-b407-5ae6d23d6a08)


