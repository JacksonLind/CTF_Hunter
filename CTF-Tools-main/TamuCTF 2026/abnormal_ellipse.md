# abnormal-ellipse — CTF Writeup

**Competition:** TAMU CTF
**Category:** Crypto
**Flag:** `gigem{an0ma1ou5_curv3_ss5a_d41z8GaFF3kZ8}`

---

## Challenge

> Some reason people are using these weird ellipses to do their encryption. But aren't quadratic curves completely broken. Anyways, I caught the data that was being sent along with how they are doing the encryption.

**Files given:**
- `generate.sage` — the encryption script
- `data.txt` — captured public values and ciphertext

---

## Understanding the Setup

`generate.sage` implements textbook ECDH followed by AES-CBC encryption:

```python
p = 57896044618658103051097247842201434560310253892815534401457040244646854264811
a = 57896044618658103051097247842201434560310253892815534336455328262589759096811
b = 6378745995050415640528904257536000
E = EllipticCurve(GF(p), [a, b])

G  = E.random_point()
dA = randint(2, G.order())
dB = randint(2, G.order())

PA = dA * G          # Alice's public key
PB = dB * G          # Bob's public key
s  = (dB * PA).x()  # shared secret (= dA*dB*G)
key = sha256(int(s).to_bytes(...)).digest()
# ... AES-CBC encrypt flag with key
```

`data.txt` gives us `G`, `PA`, `PB`, the AES ciphertext, and the IV — everything except the private keys `dA` and `dB`.

To decrypt, we need to solve the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: given `G` and `PB = dB*G`, find `dB`. Then compute `s = (dB * PA).x()` to recover the AES key.

---

## The Vulnerability: Anomalous Curve

The hint says "quadratic curves completely broken." The challenge name is "abnormal-ellipse." These both point to the same thing: the curve is **anomalous**.

An elliptic curve `E` over `GF(p)` is **anomalous** (or *trace-1*) when:

```
#E(GF(p)) = p
```

i.e., the number of points on the curve equals the field characteristic. This is the defining condition for the **Smart attack** (1999), which solves ECDLP in `O(1)` group operations — trivially broken.

We can verify the curve is anomalous by computing `p * G` in Python and confirming it returns the point at infinity:

```python
pG = scalar_mul(G, p, mod=p)
assert pG is None   # => #E(GF(p)) = p ✓
```

---

## The Smart Attack

The attack works via the **formal group** of the elliptic curve and the **p-adic logarithm**. Here's the intuition:

### Why anomalous curves are broken

For a general curve, the ECDLP is hard because there's no efficient map from the elliptic curve group to a simpler group where logarithms are easy. For anomalous curves, such a map *does* exist: the **formal logarithm** `φ: E₁(ℤ_p) → ℤ_p`, where `E₁` is the kernel of reduction mod `p`.

### Step 1 — Hensel Lift

Lift each point from `GF(p)` to `ℤ/p²ℤ`. Given `P = (x₀, y₀)` on `E(GF(p))`, find `x₁ ≡ x₀ (mod p)` such that `y₀² ≡ x₁³ + ax₁ + b (mod p²)`.

This is one Newton step on `f(x) = x³ + ax + b - y₀²`:

```
f(x₀) ≡ 0 (mod p),  so  f(x₀) = k·p
t = -k · (f'(x₀))⁻¹  (mod p)
x₁ = x₀ + t·p  (mod p²)
```

The y-coordinate lifts trivially (y stays the same; it's a Newton step on x only).

### Step 2 — Multiply by p over ℤ/p²ℤ

Compute `p · Ĝ` and `p · P̂_B` on `E(ℤ/p²ℤ)`. Because `#E(GF(p)) = p`, each `P ∈ E(GF(p))` satisfies `p·P = O` in `E(GF(p))`. The lifted version `p·P̂` is *not* the identity in `E(ℤ/p²ℤ)` — it lands in `E₁`, the formal group kernel, which reduces to `O` mod `p` but has non-trivial structure mod `p²`.

### Step 3 — Apply the Formal Logarithm

For a point `(X:Y:Z)` in `E₁(ℤ/p²ℤ)` (in projective coordinates), the formal logarithm is:

```
φ(P) = -X/Y   (in projective coords; equals -x/y in affine)
```

Because `p·Ĝ` reduces to `O = (0:1:0)` mod `p`, we have `X ≡ 0 (mod p)`. So `φ(p·Ĝ) ≡ 0 (mod p)`. The quantity we want is:

```
l_G = φ(p·Ĝ) / p  =  -(X//p) · Y⁻¹  (mod p)
l_Q = φ(p·P̂_B) / p
```

### Step 4 — Extract the Discrete Log

The formal logarithm is linear, so:

```
l_Q / l_G ≡ dB  (mod p)
```

---

## Implementation

The trickiest part of a pure-Python implementation is the projective arithmetic over `ℤ/p²ℤ`. Using naïve affine arithmetic fails because during the `p`-multiplication, intermediate x-denominators can become divisible by `p`, making modular inversion undefined.

The fix is to use **projective (homogeneous) coordinates** `(X:Y:Z)` throughout, where `(x, y) = (X/Z, Y/Z)`, and apply the correct EFD formulas (`add-1998-cmo-2`, `dbl-1998-cmo-2`) which require no division:

**Doubling** (`dbl-1998-cmo-2`):
```
W  = a·Z₁² + 3·X₁²
S  = Y₁·Z₁
B  = X₁·Y₁·S
H  = W² - 8·B
X₃ = 2·H·S
Y₃ = W·(4·B - H) - 8·Y₁²·S²
Z₃ = 8·S³
```

**Addition** (`add-1998-cmo-2`):
```
u   = Y₂·Z₁ - Y₁·Z₂
v   = X₂·Z₁ - X₁·Z₂
A   = u²·Z₁·Z₂ - v³ - 2·v²·X₁·Z₂
X₃  = v·A
Y₃  = u·(v²·X₁·Z₂ - A) - v³·Y₁·Z₂
Z₃  = v³·Z₁·Z₂
```

Full exploit (`exploit.py`):

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

p  = 57896044618658103051097247842201434560310253892815534401457040244646854264811
a  = 57896044618658103051097247842201434560310253892815534336455328262589759096811
b  = 6378745995050415640528904257536000

Gx  = 46876917648549268272641716936114495226812126512396931121066067980475334056759
Gy  = 29018161638760518123770904309639572979634020954930188106398864033161780615057
PAx = 41794565872898552028378254333448511042514164360566217446125286680794907163222
PAy = 28501067479064047326107608780246105661757692260405498327414296914217192089882
PBx = 832923623940209904267388169663314834051489004894067103155141367420578675552
PBy = 7382962163953851721569729505742450736497607615866914193411926051803583826592

enc_hex = "e31e0e638110d1e5c39764af90ac6194c1f9eaabd396703371dc2e6bb2932a18d824d86175ab071943cba7c093ccc6c6"
iv_hex  = "478876e42be078dceb3aee3a6a8f260f"

INF = (0, 1, 0)

def proj_dbl(P, mod, ac):
    X1, Y1, Z1 = P
    if Z1 % mod == 0: return INF
    W  = (ac * Z1 % mod * Z1 + 3 * X1 % mod * X1) % mod
    S  = Y1 * Z1 % mod
    B  = X1 * Y1 % mod * S % mod
    H  = (W * W - 8 * B) % mod
    X3 = 2 * H * S % mod
    Y3 = (W * (4 * B - H) - 8 * Y1 * Y1 % mod * S * S) % mod
    Z3 = 8 * S * S % mod * S % mod
    return (X3, Y3, Z3)

def proj_add(P, Q, mod, ac):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    if Z1 % mod == 0: return Q
    if Z2 % mod == 0: return P
    Y1Z2 = Y1 * Z2 % mod;  X1Z2 = X1 * Z2 % mod;  Z1Z2 = Z1 * Z2 % mod
    u = (Y2 * Z1 - Y1Z2) % mod;  uu = u * u % mod
    v = (X2 * Z1 - X1Z2) % mod;  vv = v * v % mod;  vvv = v * vv % mod
    R = vv * X1Z2 % mod
    if v == 0:
        return proj_dbl(P, mod, ac) if u == 0 else INF
    A  = (uu * Z1Z2 - vvv - 2 * R) % mod
    X3 = v * A % mod
    Y3 = (u * (R - A) - vvv * Y1Z2) % mod
    Z3 = vvv * Z1Z2 % mod
    return (X3, Y3, Z3)

def proj_mul(P, n, mod, ac):
    R = INF; Q = P
    while n:
        if n & 1: R = proj_add(R, Q, mod, ac)
        Q = proj_dbl(Q, mod, ac); n >>= 1
    return R

def aff_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0: return None
        lam = (3*x1*x1 + a) * pow(2*y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def aff_mul(P, n):
    R = None; Q = P
    while n:
        if n & 1: R = aff_add(R, Q)
        Q = aff_add(Q, Q); n >>= 1
    return R

def hensel_lift(x0, y0):
    pp = p * p
    f_x0    = (pow(x0, 3, pp) + a * x0 + b - y0 * y0) % pp
    f_prime = (3 * x0 * x0 + a) % p
    t  = (-(f_x0 // p) * pow(f_prime, -1, p)) % p
    return (x0 + t * p) % pp, y0 % pp

def smart_attack(Gx_, Gy_, Qx_, Qy_):
    pp = p * p
    Gl = hensel_lift(Gx_, Gy_)
    Ql = hensel_lift(Qx_, Qy_)
    pG = proj_mul((Gl[0], Gl[1], 1), p, pp, a)
    pQ = proj_mul((Ql[0], Ql[1], 1), p, pp, a)
    l_G = (-(pG[0] // p) % p * pow(pG[1] % p, -1, p)) % p
    l_Q = (-(pQ[0] // p) % p * pow(pQ[1] % p, -1, p)) % p
    return (l_Q * pow(l_G, -1, p)) % p

dB = smart_attack(Gx, Gy, PBx, PBy)
s  = aff_mul((PAx, PAy), dB)[0]

key      = hashlib.sha256(int(s).to_bytes((s.bit_length() + 7) // 8, 'big')).digest()
ct       = bytes.fromhex(enc_hex)
iv       = bytes.fromhex(iv_hex)
dec      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
padded   = dec.update(ct) + dec.finalize()
unpadder = sym_padding.PKCS7(128).unpadder()
print(unpadder.update(padded) + unpadder.finalize())
```

---

## Output

```
[*] Running Smart attack to recover dB...
[+] dB = 14351322784803667778298934151869100639090151998944262589608260939971387880030
[+] dB*G == PB? True
[*] Running Smart attack to recover dA...
[+] dA = 5302515257459728333067206555460709176819601641952986275899160992587299740102
[+] dA*G == PA? True
[+] Shared secret s = 46862424626771023060842312162194505004189661568357160582950231202292115713415

FLAG FOUND: gigem{an0ma1ou5_curv3_ss5a_d41z8GaFF3kZ8}
```

---

## Key Takeaways

- **Anomalous curves (#E = p) are completely broken for ECDLP.** The Smart attack recovers any private key with a single scalar multiplication over ℤ/p²ℤ — no baby-step-giant-step, no factoring, nothing.

- **Curve order must be checked.** Safe curve parameters (Curve25519, P-256, etc.) are specifically chosen so that `#E(GF(p)) ≠ p`. When rolling your own curve, always verify the order is neither `p`, `p+1`, nor smooth.

- **Implementation pitfall:** Naïve affine arithmetic over ℤ/p²ℤ breaks down during the `p`-multiplication because intermediate denominators can be divisible by `p` (not invertible mod `p²`). The fix is **projective coordinates with division-free EFD formulas**.

- **Formal group isomorphism:** The underlying math is that for anomalous curves, the formal group `Ê(pℤ_p)` is isomorphic to `(ℤ_p, +)` via the formal logarithm, reducing ECDLP to integer division.
