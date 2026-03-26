# NEURAL-LINK CORE v4.4 — Web / API Exploitation

**CTF:** EH4X  
**Category:** Web / API Exploitation  
**Difficulty:** Medium  
**URL:** `ctf-challenge-1-beige.vercel.app`  
**Flag:** `EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}`

---

## Overview

A browser-based Tic Tac Toe game claiming to have an "unbeatable AI" with a 0% chance of winning. The flag was hidden behind a server-side condition that required discovering an undocumented API mode and exploiting its blind spot.

The game communicated with a single POST endpoint:

```
POST /api
{ mode: "3x3", state: <3x3 board array> }

Response fields: { message, ai_move, gameOver, cheat, flag }
```

---

## Phase 1 — Naive State Manipulation

The obvious first attempt: submit a pre-won board directly to the API.

```javascript
await fetch('/api', {
  method: 'POST',
  body: JSON.stringify({
    mode: "3x3",
    state: [[1,1,1],[0,-1,0],[-1,0,0]]  // X wins top row
  })
});
// Response:
// { message: "AI: I've simulated this 3x3 grid 10^6 times...", ai_move: 3 }
```

The server ignored the winning state and simply made its next AI move. The backend runs its own game logic rather than trusting the client-submitted board.

---

## Phase 2 — Cheat Detection & The Key Clue

Submitting a board with an impossible move count triggered the cheat detector:

```javascript
state: [[1,1,1],[1,-1,-1],[-1,1,0]]

// Response:
{
  message: "AI: Oh, you forced an 'X' into my memory? Cute. But the flag only releases for a valid dimensional shift.",
  cheat: true
}
```

**Key clue:** *"flag only releases for a valid dimensional shift"*

---

## Phase 3 — Discovering 4x4 Mode

Probing alternate mode values:

```javascript
for (const mode of ["4x4", "5x5", "2x2", "1x1", ...]) {
  const r = await fetch('/api', {
    method: 'POST',
    body: JSON.stringify({ mode, state: [[1,1,1],[0,-1,0],[-1,0,0]] })
  });
  console.log(mode, await r.json());
}
// Result:
// 4x4 → { message: "4x4_MODE_ACTIVE: AI sensors blind in ghost sectors." }
// All other modes → 400 error
```

4x4 mode was real — and the AI described itself as **"blind in ghost sectors"**, suggesting it couldn't properly defend in this dimension.

---

## Phase 4 — Dead Ends

- Hidden endpoints (`/api/flag`, `/admin`, `/.env`) — all 404
- HTTP method variations (GET, PUT, PATCH) — all `405 POST_ONLY`
- Custom request headers (`X-Admin`, `X-Dimensional-Shift`, `Authorization`) — no effect
- Alternative field names (`board`, `grid` instead of `state`) — `400 PACKET_LOSS`
- Session/cookie based state — server is fully stateless
- Playing 3x3 legitimately — AI plays perfectly and always draws

---

## Phase 5 — The Solve

**Hypothesis:** 4x4 mode disables the AI's defense ("blind"), but still evaluates the board for a valid win. It requires 4-in-a-row with a legal move count (X = O + 1).

Programmatically generate every possible 4x4 winning configuration:

```javascript
const winLines4x4 = [
  // 4 rows
  [[0,0],[0,1],[0,2],[0,3]], [[1,0],[1,1],[1,2],[1,3]],
  [[2,0],[2,1],[2,2],[2,3]], [[3,0],[3,1],[3,2],[3,3]],
  // 4 columns
  [[0,0],[1,0],[2,0],[3,0]], [[0,1],[1,1],[2,1],[3,1]],
  [[0,2],[1,2],[2,2],[3,2]], [[0,3],[1,3],[2,3],[3,3]],
  // 2 diagonals
  [[0,0],[1,1],[2,2],[3,3]], [[0,3],[1,2],[2,1],[3,0]],
];

for (const line of winLines4x4) {
  const state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
  for (const [r,c] of line) state[r][c] = 1;  // Place X on win line

  // Fill 3 O pieces in remaining cells (X:4, O:3 = valid count)
  let oCount = 0;
  for (let r = 0; r < 4 && oCount < 3; r++)
    for (let c = 0; c < 4 && oCount < 3; c++)
      if (state[r][c] === 0) { state[r][c] = -1; oCount++; }

  const resp = await fetch('/api', {
    method: 'POST',
    body: JSON.stringify({ mode: "4x4", state })
  });
  const d = await resp.json();
  if (!d.message.includes('blind')) console.log('DIFFERENT RESPONSE!', d);
}
```

One of the generated boards satisfied the server's 4x4 win validation and returned the flag.

---

## Vulnerability Summary

| Security Check | Bypass Method |
|---|---|
| 3x3 cheat detection | Switch to undocumented 4x4 mode |
| 4x4 blind AI defense | Submit a valid winning board state |
| Move count validation | Ensure X count = O count + 1 |

The core vulnerability was **security through obscurity**: the 4x4 mode existed but was undocumented, and its "blind AI" was intended to make winning trivial — but only if the attacker discovered the mode and submitted a geometrically valid winning board with correct move counts.

---

## Key Lessons

- Always probe for alternate API modes and parameters beyond what the frontend uses.
- Error messages and taunts often contain the most valuable hints — parse them carefully.
- When a server detects cheating, it reveals what it *is* checking — invert that to find what it *doesn't* check.
- Brute-forcing all possible valid board states is viable when the state space is small.
- Security through obscurity fails when the API is directly accessible.

---

**Flag:** `EH4X{D1M3NS1ONAL_GHOST_1N_TH3_SH3LL}`
