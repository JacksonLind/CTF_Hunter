# The Architect's Gambit — Cryptographic Combinatorial Warfare

**CTF:** EH4X  
**Category:** Cryptography / Game Theory / Network  
**Connection:** `20.244.7.184:41337`  
**Flag:** `EH4X{4rch173c7s_g4mb17_cryp70_n1m_w4rf4r3}`

---

## Challenge Overview

The Architect's Gambit is a multi-phase network challenge combining **AES cryptography**, **GF(2⁸) field arithmetic**, **combinatorial game theory (Nim)**, and **commit-reveal protocols**. The solver must play 10 rounds against a remote server within a 300-second global timeout, with each round increasing in complexity.

---

## Challenge Mechanics

### 2.1 Proof of Work

Before connecting, the server requires a SHA-256 proof-of-work. The solver brute-forces the nonce by incrementing from 0 until the condition is met. Typical nonces are in the range of 1–60 million iterations, completing in a few seconds.

### 2.2 Game Rules

Each round is a Nim-variant game:

- N piles of stones. Players alternate turns.
- On your turn: pick pile `i`, remove `1..K` stones (`K = take_limit`).
- **Drain links:** removing `k` stones from pile `i` adds `drain(k)` stones to a linked pile `j`.
- **Illegality rule:** moves that do NOT decrease total stones are illegal.
- **Normal play:** last player to move wins. Facing all-zero piles = you lose.

### 2.3 Drain Mechanics by Phase

| Phase | Drain Function |
|---|---|
| Phase 1 | `drain(k) = floor(k / 2)` — simple halving |
| Phase 2 & 3 | `drain(k, w) = GF256_mul(k, w) mod k` — capped GF(2⁸) multiplication |

GF(2⁸) uses the AES irreducible polynomial `x⁸ + x⁴ + x³ + x + 1` (0x11B).

**Critical insight:** drain is *capped* — `GF_mul(k, w) mod k` is always strictly less than `k`, so the drained amount is bounded by the number of stones removed. A move can still decrease the total and be legal even with active drain links.

### 2.4 Answer Binding (Phases 1 & 2)

All Phase 1 and 2 answers require an **HMAC binding token** to prevent replay attacks.

---

## Phase 3 — The Architect's Endgame

Phase 3 (Rounds 8–10) introduces three additional layers of difficulty.

### 3.1 Pile Encryption (AES-128-CTR, No Key)

The pile values are encrypted with AES-128-CTR and the key is not provided. However, the server reveals the true pile state in plaintext in the interactive game header via a `STATE:` line. The solver reads this directly, making oracle queries redundant.

### 3.2 Noisy Oracle (2 Probes)

Before playing, the solver may send 2 `PROBE` queries. With only 2 probes and 3+ unknown parameters, exact deduction is impossible. The solver uses a voting approach across all valid `(p, scalar, offset)` combinations, but the direct `STATE` line takes precedence.

### 3.3 Commit-Reveal Protocol

Every move must be committed before revealing:

1. Generate a random 8-byte nonce (hex-encoded).
2. Commit: `HMAC(nonce, move)`.
3. Reveal: send the nonce and move together.

This prevents the server from knowing the planned move before it's committed.

---

## Game-Theoretic Solution

### Sprague-Grundy via Dynamic Programming

The solver uses a recursive memoised DP to compute whether any game state is a **P-position** (previous player wins = current player loses):

```python
from functools import lru_cache

@lru_cache(maxsize=None)
def is_p_position(state):
    # Try all legal moves
    for i, pile in enumerate(state):
        for k in range(1, min(pile, take_limit) + 1):
            new_state = list(state)
            new_state[i] -= k
            # Apply drain links
            for j, w in drain_links.get(i, []):
                drain_amt = gf256_mul(k, w) % k
                new_state[j] += drain_amt
            new_state = tuple(new_state)
            total_delta = sum(new_state) - sum(state)
            if total_delta >= 0:
                continue  # illegal move
            if is_p_position(new_state):
                return False  # found a move to a P-position, we're N-position
    return True  # all moves lead to N-positions — this is a P-position
```

**State space:** With `MAX_VAL=25` and 5 piles, the theoretical maximum is 26⁵ ≈ 12M states. In practice, drain links constrain reachable states. The solver includes a time-aware early exit that falls back to a greedy heuristic if the deadline approaches.

### Move Application with GF(2⁸) Drain

```python
def gf256_mul(a, b, poly=0x11B):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result & 0xFF
```

---

## Key Bugs Found & Fixed

The solver was developed iteratively. Key issues encountered:

1. **Bidirectional links:** Assumed drain was bidirectional — confirmed via server responses to be **unidirectional** as listed.
2. **STATE line ordering:** The server sends two `STATE` lines per turn (post-our-move, post-AI-move). Always use the **last** one.
3. **Protocol buffer management:** Cleanup `recv` calls after a game ends can consume the next round's prompt on timeout. Remove all unnecessary blocking reads.
4. **Losing gracefully:** When in a genuine P-position, **maximise stone removal** (make the game end fast) rather than taking the minimum, which only prolongs a loss.

---

## Solver Architecture

### High-Level Flow

```
connect → proof-of-work → loop 10 rounds:
    read round header (phase, budget, game params)
    [Phase 3] read STATE line for pile values
    compute Sprague-Grundy DP within time budget
    loop game turns:
        find best move (N-position → P-position)
        [Phase 3] commit → reveal
        [Phase 1/2] send with HMAC binding token
        read server response / new STATE
```

### Timing Management

Each round has a server-enforced budget (20s / 40s / 60s). The solver extracts this from the round header and allocates time accordingly:

```python
time_per_move = round_budget / estimated_moves
if time.time() - round_start > round_budget * 0.8:
    # Fall back to greedy: take from largest pile
    move = greedy_move(state)
```

---

## Lessons Learned

- **Trust the server:** The `STATE: [...]` line is broadcast in plaintext — using it directly is far more reliable than any oracle deduction scheme.
- **Verify assumptions empirically:** "Bidirectional links" had a non-obvious meaning. Trace actual state transitions from server responses to confirm the correct interpretation.
- **Dynamic time budgets beat fixed ones:** Round budgets vary (20s/40s/60s). Hardcoding a per-move time limit breaks on tighter rounds.
- **Losing gracefully:** When in a P-position, maximise stone removal rather than minimising — it ends the game faster.
- **Protocol hygiene:** Clean up all `recv` calls at round boundaries to avoid consuming the next round's data.

---

**Flag:** `EH4X{4rch173c7s_g4mb17_cryp70_n1m_w4rf4r3}`  
*The Architect has been defeated.*
