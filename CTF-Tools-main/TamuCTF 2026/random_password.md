# CTF Writeup: random-password

**Competition**: TAMU CTF
**Category**: Crypto / Reverse Engineering
**Flag**: `gigem{h3rd1ng_rand0m_sh3ep_LiNBpqRTk}`

---

## Challenge Description

We're given a `server.py` that accepts a 64-character hex password and "verifies" it. The verification involves sleeping different amounts of time based on each bit, then checking if the next random value equals a specific float.

---

## Source Analysis

```python
from functools import partial
import re
import random

random.seed(121728)

def random_sleep(timeout: float) -> None:
  time_elapsed = 0
  while time_elapsed < timeout:
    time_elapsed += random.random()

handle_zero = partial(random_sleep, 5)
handle_one = partial(random_sleep, 17)

def verify(password: str, correct_value: float) -> bool:
  if len(password) != 64: return False

  bit_str = bin(int(password, 16))[2:].zfill(256)

  for bit in bit_str:
    match bit:
      case '0':
        handle_zero()
      case '1':
        handle_one()

  return random.random() == correct_value

password = input('Enter the password in hex: ')
...
if verify(password, 0.9992610559813815):
  ...print flag...
```

Key observations:

1. **Fixed seed**: `random.seed(121728)` — the entire RNG sequence is deterministic and known in advance.
2. **Bit-level processing**: The 64-hex-char password (256 bits) is iterated bit by bit. Each `'0'` bit calls `random_sleep(5)` and each `'1'` bit calls `random_sleep(17)`.
3. **Simulated sleep via RNG**: `random_sleep` doesn't use real time — it sums `random.random()` values until the sum exceeds the timeout. This means each bit consumes a variable but deterministic number of RNG values.
4. **Final check**: After processing all bits, the server checks `random.random() == 0.9992610559813815`. Since the RNG state is fully determined by the seed and how many values were consumed, this check passes only if the password consumed exactly the right number of RNG values.

---

## Vulnerability

The use of `random` (a PRNG) with a **hardcoded seed** makes the entire output sequence known to the attacker. The "password" is never compared to a secret value — it's just a way to steer the RNG to a target state. Since both the seed and the target float are visible in the source, the correct password can be computed offline.

---

## Solution

### Step 1 — Find the target index

Generate the RNG sequence from seed `121728` and find the index where `0.9992610559813815` appears:

```python
import random

random.seed(121728)
values = [random.random() for _ in range(200000)]

target = 0.9992610559813815
for i, v in enumerate(values):
    if v == target:
        print(f"Target at index {i}")  # → 5719
        break
```

The target value is at index **5719**, meaning the password must cause exactly **5719** RNG values to be consumed before the final check.

### Step 2 — Precompute per-bit RNG cost

For each possible starting index `i`, compute how many RNG values are consumed if the bit is `'0'` (timeout=5) or `'1'` (timeout=17):

```python
def count_consumed(values, start, timeout):
    elapsed = 0
    idx = start
    while elapsed < timeout:
        elapsed += values[idx]
        idx += 1
    return idx - start

zero_cost = [count_consumed(values, i, 5)  for i in range(5720)]  # avg ~10.6
one_cost  = [count_consumed(values, i, 17) for i in range(5720)]  # avg ~34.5
```

### Step 3 — Dynamic programming to find the password

We need a 256-bit string such that processing it consumes exactly 5719 RNG values. This is a path-finding problem: starting at RNG index 0, take 256 steps (one per bit), each step advancing the index by `zero_cost[idx]` or `one_cost[idx]`, and land exactly on index 5719.

```python
# Forward DP
# State: current RNG index after processing `bit_pos` bits
# parent[(bit_pos+1, new_idx)] = (bit_pos, old_idx, bit_choice)

current = {0}
parent = {}

for bit_pos in range(256):
    next_set = set()
    for idx in current:
        for bit, cost in [('0', zero_cost[idx]), ('1', one_cost[idx])]:
            new_idx = idx + cost
            if new_idx <= 5719:
                if (bit_pos + 1, new_idx) not in parent:
                    parent[(bit_pos + 1, new_idx)] = (bit_pos, idx, bit)
                next_set.add(new_idx)
    current = next_set

# Reconstruct the winning path
bits, pos, idx = [], 256, 5719
while pos > 0:
    prev_pos, prev_idx, bit = parent[(pos, idx)]
    bits.append(bit)
    pos, idx = prev_pos, prev_idx
bits.reverse()

password = hex(int(''.join(bits), 2))[2:].zfill(64)
print(password)
# → 00000240480008000000000000019cdf6fdffeffbfd7ff7f7eeeffffdf7ef7c7
```

### Step 4 — Submit

```python
from pwn import *

io = remote("streams.tamuctf.com", 443, ssl=True, sni="random-password")
io.recvuntil(b"hex: ")
io.sendline(b"00000240480008000000000000019cdf6fdffeffbfd7ff7f7eeeffffdf7ef7c7")
print(io.recvall(timeout=15).decode())
# → Here's the flag gigem{h3rd1ng_rand0m_sh3ep_LiNBpqRTk}
```

---

## Full Solver

```python
import random
from pwn import *

random.seed(121728)
values = [random.random() for _ in range(6000)]

# Find target index
target = 0.9992610559813815
TARGET = next(i for i, v in enumerate(values) if v == target)  # 5719

# Precompute per-bit RNG consumption
def count_consumed(start, timeout):
    elapsed, idx = 0, start
    while elapsed < timeout:
        elapsed += values[idx]
        idx += 1
    return idx - start

zero_cost = [count_consumed(i, 5)  for i in range(TARGET + 1)]
one_cost  = [count_consumed(i, 17) for i in range(TARGET + 1)]

# Forward DP
current, parent = {0}, {}
for bit_pos in range(256):
    next_set = set()
    for idx in current:
        for bit, cost in [('0', zero_cost[idx]), ('1', one_cost[idx])]:
            new_idx = idx + cost
            if new_idx <= TARGET:
                if (bit_pos + 1, new_idx) not in parent:
                    parent[(bit_pos + 1, new_idx)] = (bit_pos, idx, bit)
                next_set.add(new_idx)
    current = next_set

# Reconstruct path
bits, pos, idx = [], 256, TARGET
while pos > 0:
    prev_pos, prev_idx, bit = parent[(pos, idx)]
    bits.append(bit)
    pos, idx = prev_pos, prev_idx
bits.reverse()
password = hex(int(''.join(bits), 2))[2:].zfill(64)

# Submit
io = remote("streams.tamuctf.com", 443, ssl=True, sni="random-password")
io.recvuntil(b"hex: ")
io.sendline(password.encode())
print(io.recvall(timeout=15).decode())
```

---

## Key Takeaways

- **Never use `random` for anything security-sensitive** — it is a PRNG, not a CSPRNG. Use `secrets` or `os.urandom` instead.
- A hardcoded seed completely eliminates any security that the randomness was supposed to provide.
- Even when a program doesn't directly compare a password to a stored secret, deterministic state machines can be reverse-engineered. Here the "password" was just a way to seek the RNG to a specific position.
- The DP approach works because the per-bit RNG consumption is bounded (~6–46 values), keeping the reachable state space manageable (≤5720 indices per bit position).
