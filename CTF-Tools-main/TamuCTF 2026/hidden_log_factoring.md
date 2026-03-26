# RSA + DLP Hybrid Encryption

**Category:** Crypto · **Difficulty:** Medium · **Status:** ✓ Solved

> gigem{} CTF — Pohlig-Hellman + RSA Factoring + Rabin Decryption

---

## Overview

The challenge presented a hybrid cryptosystem combining RSA and a Discrete Logarithm Problem (DLP). The RSA private key `d` was masked using an HKDF stream derived from a secret DLP exponent `s`, and the flag was encrypted as `c = flag² mod n` — a Rabin-like scheme, not standard RSA.

The vulnerability chain: the DLP exponent was drawn from `randint(1, 1<<100)` (100-bit space), and `p−1` contains smooth small factors whose product exceeds 100 bits — making Pohlig-Hellman feasible without touching the large prime factor.

---

## Attack Chain

1. **Factor p−1 & Plan Pohlig-Hellman**
   `p−1 = 2¹⁰¹ · 3 · 29 · 317 · 593 · 480661 · <980-bit prime>`. Product of small factors = 144 bits > 100-bit `s` bound. CRT recovery is possible without solving the large subgroup.

2. **Solve DLP via Pohlig-Hellman + BSGS**
   For each small prime-power factor `q^e` of `p−1`, reduce to a subgroup DLP of order `q` and solve with baby-step giant-step. CRT-combine residues to recover `s ≡ 485391067385099231898174017598`.

3. **Unmask RSA Private Key d**
   Derive HKDF mask from `s` (info=`"rsa-d-mask"`), XOR with `D` to recover `d`. Verify: `pow(e, -1, phi)` should match.

4. **Factor n using (e, d)**
   From `d·e ≡ 1 (mod φ)`, write `d·e−1 = 2^s · t`. Repeatedly square a random base; GCD with `n` yields factors `q1`, `q2` with high probability.

5. **Rabin Decryption → Flag**
   `c = flag² mod n` — compute `√c mod q1` and `mod q2` via Tonelli-Shanks, CRT-combine all 4 roots, decode bytes to find the `gigem{}` flag.

---

## Key Observations

> **Weak DLP:** `s` drawn from `randint(1, 1<<100)` is only 100 bits. Combined with a smooth `p−1`, Pohlig-Hellman trivially recovers `s` without touching the large subgroup.

> **Non-standard RSA encryption:** `c = pow(flag, 2, n)` — exponent is `2`, not `e`. Decryption requires computing a modular square root (Rabin), not modular exponentiation with `d`. Four square roots exist; only one decodes to printable text.

**Pohlig-Hellman per subgroup:**
For prime power `q^e | (p−1)`, let `γ = g^((p−1)/q)`. Then for each digit `d_k` in base-q expansion of `s`:

```
h_k = (g^(−x_k) · A)^((p−1)/q^(k+1))  ⟹  d_k = log_γ(h_k)  [BSGS, order q]
```

**RSA factoring from (e, d):**
`k = d·e − 1`, write `k = 2^r · t`. For random `g`: if `gcd(g^(k/2^i) − 1, n)` is non-trivial → factor found.

---

## Solve Script

```python
# Full solve — no external dependencies
import hashlib, hmac, math, random

def hkdf_mask(secret, length):
    prk = hmac.new(b'\x00'*32, secret, hashlib.sha256).digest()
    okm, t = b"", b""
    for i in range(1, -(-length//32)+1):
        t = hmac.new(prk, t+b"rsa-d-mask"+bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def bsgs(g, h, p, order):           # baby-step giant-step
    m = int(order**0.5) + 1
    table = {pow(g, i, p): i for i in range(m)}
    gm_inv = pow(pow(g, m, p), -1, p)
    hj = h
    for j in range(m):
        if hj in table: return j*m + table[hj]
        hj = hj * gm_inv % p

def pohlig(g, h, p, q, e):           # DLP mod q^e
    order = p-1; x = 0
    gamma = pow(g, order//q, p)
    for k in range(e):
        h_k = pow(pow(g, -x, p)*h%p, order//(q**(k+1)), p)
        x += bsgs(gamma, h_k, p, q) * q**k
    return x % (q**e)

# Step 1: Recover s via Pohlig-Hellman
small = [(2,101),(3,1),(29,1),(317,1),(593,1),(480661,1)]
rs, ms = [], []
for q,e in small:
    rs.append(pohlig(g,A,p,q,e)); ms.append(q**e)
s = crt(rs, ms)                       # s = 485391067385099231898174017598

# Step 2: Unmask d
mask = hkdf_mask(s.to_bytes((s.bit_length()+7)//8,'big'), D.bit_length()//8)
d = D ^ int.from_bytes(mask, 'big')

# Step 3: Factor n from (e, d)
q1, q2 = factor_rsa(n, e, d)

# Step 4: Rabin decryption — 4 square roots, find printable
for root in rabin_roots(c, q1, q2, n):
    try: print(root.to_bytes((root.bit_length()+7)//8,'big').decode())
    except: pass
```

---

## Key Values

| Variable | Value / Note |
|----------|-------------|
| `s` | `485391067385099231898174017598` (99 bits, recovered via Pohlig-Hellman) |
| `q1` | `7233682312898124798813999758724...620759` (512-bit RSA factor) |
| `q2` | `9817449389392993178082512184931...017009` (512-bit RSA factor) |
| `d` | `9643012996350657273877726928...796001` (RSA private key, 1023 bits) |

---

## Flag

```
gigem{100lsb_ed_fact0ring_rab1n_attack_1n_th3_log_3oVAjvoCTGmWg847g9zsNBIyPPWqYdP}
```
