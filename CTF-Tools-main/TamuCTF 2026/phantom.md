# phantom — TAMUctf 2026 Writeup

**Category**: OSINT / Git Forensics  
**Flag**: `gigem{917hu8_f02k5_423_v32y_1n7323571n9_1d60b3}`  
**Solves**: ~200

---

## Challenge Description

The only thing provided is a link to a GitHub repository: `https://github.com/tamuctf/phantom`

The repo contains a single file — `README.md` — with the contents:

```
# phantom
```

That's it.

---

## Recon

### Step 1: Clone and enumerate

```bash
git clone https://github.com/tamuctf/phantom
cd phantom
git ls-remote origin
```

Output:
```
35ecf7068d2aa0bc295f69cfc622c7904dab42cf    HEAD
35ecf7068d2aa0bc295f69cfc622c7904dab42cf    refs/heads/main
5579d8d89ec47e7446312199ac3c307d1ff3a474    refs/pull/3/head
0862ea7f92f15bcf4290f3a046f0f3cfca053a84    refs/pull/3/merge
```

There's a pull request ref — `refs/pull/3/head` — pointing to a commit not on `main`.

### Step 2: Investigate the PR

```bash
git fetch origin refs/pull/3/head:pr3
git fetch origin refs/pull/3/merge:pr3merge
git checkout pr3
git show 5579d8d
```

The PR commit is authored by `Kahunser <kahunser@proton.me>` and titled *"Fix header formatting in README.md"*. The diff adds a single trailing space to `# phantom`. Nothing suspicious.

The merge commit (`pr3merge`) also reveals nothing useful.

### Step 3: Check all git objects

```bash
git cat-file --batch-all-objects --batch-check
```

Only 7 objects total. All accounted for. No dangling blobs, no hidden trees.

### Step 4: Check blob contents for steganography

```powershell
git cat-file blob aa7a5b4 | Format-Hex
git cat-file blob 3664c63 | Format-Hex
```

The old README is exactly `23 20 70 68 61 6E 74 6F 6D` (`# phantom`, no newline).  
The new README adds a single trailing space (`20`). No hidden unicode. Dead end.

### Step 5: Inspect the PGP signing key

All three commits (initial, PR, merge) share the same GPG key ID: `B5690EEEBB952194` — meaning the "external contributor" Kahunser is actually the challenge author in disguise.

Fetching the public key from `keys.openpgp.org` showed a key with no UID and no embedded data. Dead end.

---

## The Break: GitHub Events API

Having exhausted all git-level avenues, we turned to the **GitHub Events API**:

```powershell
Invoke-WebRequest -Uri "https://api.github.com/repos/tamuctf/phantom/events" -OutFile "events.json"
cat events.json
```

Buried in the events list was a `CommitCommentEvent`:

```json
{
  "type": "CommitCommentEvent",
  "actor": { "login": "T-Of-Me" },
  "payload": {
    "comment": {
      "commit_id": "b365313472870cbf887a42a7be75df741b60c8d3",
      "body": "MAKE MSEC GREAT AGAIN\r\n"
    }
  }
}
```

The commit SHA `b365313472870cbf887a42a7be75df741b60c8d3` **does not exist in any local ref**. It was never pushed to any branch or tag — it's a fully orphaned / dangling commit that lives only on GitHub's backend.

But someone had left a comment on it, leaking the SHA through the public Events API.

---

## The Solve

GitHub's object store allows fetching any object by SHA directly, even if it's unreachable from any ref:

```bash
git fetch origin b365313472870cbf887a42a7be75df741b60c8d3
git show b365313472870cbf887a42a7be75df741b60c8d3
```

The commit contained the flag in its message or diff.

```
gigem{917hu8_f02k5_423_v32y_1n7323571n9_1d60b3}
```

Decoded from leet speak: **"github forks are very interesting"** — a nod to the intended rabbit hole.

---

## Key Takeaways

- **`git ls-remote`** and **`git fetch origin refs/pull/*`** are essential first steps on any GitHub CTF repo.
- **GitHub's Events API** (`/repos/:owner/:repo/events`) records `CommitCommentEvent`, `PushEvent`, and other activity that can leak commit SHAs of otherwise-invisible objects.
- **Orphaned commits** on GitHub can be fetched directly by SHA even when unreachable from any branch or tag — GitHub doesn't garbage-collect them immediately.
- The flag itself hints at the solution: forks also preserve orphaned commit SHAs, making them another potential leak vector.

---

## TL;DR Solve Steps

1. `git ls-remote origin` → find PR refs
2. Fetch PR refs → rabbit hole (intentional distraction)
3. `curl https://api.github.com/repos/tamuctf/phantom/events` → find `CommitCommentEvent` leaking SHA `b3653134...`
4. `git fetch origin b365313472870cbf887a42a7be75df741b60c8d3` → profit
