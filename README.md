# VulnLab v2 – mapped to CSM5011C Web Application Security

**WARNING:** deliberately insecure. Run on localhost, a host-only VM network, or a server firewalled to your IP only.

## Run
    docker build -t vulnlab . && docker run -d -p 127.0.0.1:5000:5000 vulnlab
    # or: pip install -r requirements.txt && python app.py      (reset data: /reset-data)
Server access: keep port closed and use `ssh -L 5000:localhost:5000 user@server`.

## Syllabus map
| Unit | Topic | Where / hint |
|---|---|---|
| 1 | Banner grabbing, fingerprinting | `curl -I /` → Server / X-Powered-By; nmap -sV |
| 1 | Hidden resources, default pages, OSINT | /robots.txt, /server-status, /backup.sql.bak, gobuster/dirb |
| 1 | Error messages | break any parameter (e.g. /view?page=zzz) |
| 2 | Error/UNION SQLi | /search?q=' ; UNION needs 2 columns; SQLMap (Practicals 8, 9, 11) |
| 2 | Boolean/time-based blind | /item?id=1 AND 1=1 ; time: randomblob(500000000) |
| 2 | Stacked queries | /feedback?msg=x'); UPDATE users SET role='admin' WHERE id=2;-- |
| 2 | Reflected / stored / DOM XSS | /search, /guestbook, /dom#... ; hook with BeEF (Practicals 13, 14); steal `sid` cookie |
| 3 | Brute force, no rate limit | /login with Burp Intruder / hydra |
| 3 | User enumeration, weak reset | different messages; /reset token = md5(username) |
| 3 | Insecure remember-me, session flaws | cookie `remember`=base64(user); sequential `sid`; fixation via /login?sid=...; logout flaw |
| 3 | IDOR, function-level, priv-esc | /profile?id=, /admin, /api/users, /promote |
| 3 | Insecure redirect | /go?url=https://example.com |
| 4 | LFI / path traversal | /view?page=../../../../etc/passwd |
| 4 | Arbitrary file upload | /upload (try .html with JS) |
| 4 | CSRF, clickjacking | /transfer (GET works, no token, no X-Frame-Options) |
| 4 | CORS misconfig | /api/me with Origin header from another site |
| 4 | Web storage | login page saves credentials to localStorage |
| 4 | Business logic, DoS | /shop negative qty; /fib?n=40 |
| 4 | Secure headers | note missing CSP, HSTS, X-Frame-Options → write the fix |

**Not included:** RFI (needs outbound fetching, risky on a server), HTTP response splitting (modern Flask blocks CR/LF), XPath injection, WebSockets.
For Practicals 12 & 15 use bWAPP via Docker and Nessus on this lab.

## Remediation exercise (Term Work 4 report)
Fix each issue: parameterized queries, output escaping, ownership/role checks, random HttpOnly+Secure+SameSite sessions,
CSRF tokens, upload allow-lists, path canonicalisation, strict CORS, rate limiting, security headers, generic errors.
