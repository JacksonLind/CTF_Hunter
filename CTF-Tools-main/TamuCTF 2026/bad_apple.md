# bad-apple — TamuCTF Web Challenge Writeup

**Category:** Web
**Flag:** `gigem{3z_t0h0u_fl4g_r1t3}`
**Hint:** "funny touhou reference"

---

## Overview

A Flask web app lets users upload video files and converts them to GIF frame sequences using `ffmpeg`. The app displays the iconic Bad Apple!! Touhou fan video by default. The flag is hidden inside a protected GIF stored in an admin upload directory.

---

## Recon

### Application Structure

The source files provided:

| File | Purpose |
|------|---------|
| `wsgi_app.py` | Flask app served via Apache mod_wsgi |
| `Dockerfile` | Container setup |
| `httpd-append.conf` | Apache vhost config |

### Dockerfile — How the Flag Is Hidden

```dockerfile
CMD ["sh", "-c", "HEX=$(openssl rand -hex 16) && \
  mv /srv/http/uploads/admin/flag.gif /srv/http/uploads/admin/$HEX-flag.gif && \
  echo $HEX > /srv/http/.flag_secret && \
  httpd -DFOREGROUND"]
```

At startup, `flag.gif` is renamed to `<random-16-byte-hex>-flag.gif`. The hex is written to `.flag_secret` but that file isn't directly reachable from the web.

### Apache Config — Directory Listing + Auth Guard

```apache
Alias /browse /srv/http/uploads
<Directory /srv/http/uploads>
    Options +Indexes
    DirectoryIndex disabled
    Require all granted

    <FilesMatch "\.gif$">
        AuthType Basic
        AuthName "Admin Area"
        AuthUserFile /srv/http/.htpasswd
        Require valid-user
    </FilesMatch>
</Directory>
```

Key observations:
- `/browse/` has **directory listing enabled** with no auth required
- Only **downloading `.gif` files** triggers Basic Auth
- Listing directory contents (including filenames) is freely accessible

---

## Vulnerability

### Information Disclosure via Unauthenticated Directory Listing

The Apache `Options +Indexes` directive exposes the admin upload directory at `/browse/admin/` without authentication. While downloading the `.gif` requires credentials, **reading the directory index does not**.

Visiting `https://bad-apple.tamuctf.com/browse/admin/` reveals:

```
Index of /browse/admin
f7912549f2b8bc3487e8081c2c9fa629-flag.gif   1.7M
```

The randomized filename is fully exposed — defeating the security-by-obscurity rename.

---

## Exploitation

### Step 1 — Leak the Randomized Filename

```bash
curl -s "https://bad-apple.tamuctf.com/browse/admin/"
```

Output reveals: **`f7912549f2b8bc3487e8081c2c9fa629-flag.gif`**

### Step 2 — Find Pre-Extracted Frames

Other players had already used the Flask `/convert` endpoint (which accepts an unsanitized `user_id` parameter, allowing path traversal into the static frames directory) to extract frames from the flag GIF and write them into a world-readable location under `/browse/`:

```
/browse/leak/f7912549f2b8bc3487e8081c2c9fa629-flag/
  frame_0001.png
  frame_0002.png
  ...
  frame_0155.png
```

These PNG frames are served without any authentication.

### Step 3 — Download and Scan Frames for the Flag

```bash
mkdir -p /tmp/bad-apple-frames
for i in $(seq -f "%04g" 1 155); do
    curl -s "https://bad-apple.tamuctf.com/browse/leak/f7912549f2b8bc3487e8081c2c9fa629-flag/frame_${i}.png" \
         -o "/tmp/bad-apple-frames/frame_${i}.png"
done
```

### Step 4 — Read the Flag

The flag is rendered as white text scrolling right-to-left across the black-and-white Bad Apple!! video frames. Viewing frames sequentially:

| Frame | Visible text |
|-------|-------------|
| 0030 | `gigem{` |
| 0040 | `gem{3z` |
| 0060 | `{3z_t0h` |
| 0075 | `_t0h0u_` |
| 0095 | `0u_fl4g` |
| 0110 | `fl4g_r1` |
| 0120 | `4g_r1t3` |
| 0125 | `g_r1t3}` |

Assembled: **`gigem{3z_t0h0u_fl4g_r1t3}`**

---

## Flag

```
gigem{3z_t0h0u_fl4g_r1t3}
```

Decoded from leet: **"ez touhou flag rite"** — a nod to the Bad Apple!! music video, one of the most iconic pieces of Touhou Project fan media, famous for being rendered in absurd and creative mediums.

---

## Root Cause Summary

| Issue | Detail |
|-------|--------|
| Unauthenticated directory listing | `Options +Indexes` + `Require all granted` on `/browse/` exposes admin filenames |
| Auth only on file download, not listing | `FilesMatch "\.gif$"` blocks download but not `GET /browse/admin/` |
| Path traversal in `/convert` | `user_id` not sanitized → frames written to attacker-controlled path under `/browse/` |

### Fix

- Disable directory listing (`Options -Indexes`) or require auth on the entire `/browse/admin/` directory, not just `.gif` files
- Sanitize `user_id` with `secure_filename()` in the `/convert` route, consistent with `/upload`
