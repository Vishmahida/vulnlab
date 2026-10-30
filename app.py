"""VulnLab v2
Run ONLY in an isolated lab (localhost / VM / firewalled host). Never expose to the internet."""
import sqlite3, os, base64, hashlib, itertools
from flask import (Flask, request, make_response, redirect, render_template_string,
                   jsonify, send_from_directory)

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
DB, UP, PG = "/tmp/vulnlab.db", os.path.join(BASE, "uploads"), os.path.join(BASE, "pages")
SESS, ids = {}, itertools.count(1000)          # VULN: sequential, predictable session IDs

def db(): return sqlite3.connect(DB)

def init():
    if os.path.exists(DB): os.remove(DB)
    os.makedirs(UP, exist_ok=True); os.makedirs(PG, exist_ok=True)
    for n, t in (("about", "VulnLab is a practice app."), ("contact", "lab@example.local")):
        open(os.path.join(PG, n + ".txt"), "w").write(t)
    c = db()
    c.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret TEXT, balance INTEGER);
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE comments(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
    INSERT INTO users VALUES (1,'admin','admin123','admin','FLAG{idor_or_sqli_admin}',5000);
    INSERT INTO users VALUES (2,'alice','password1','user','Alice private note',500);
    INSERT INTO users VALUES (3,'bob','qwerty','user','Bob private note',500);
    INSERT INTO products VALUES (1,'Laptop',799),(2,'Phone',499),(3,'Headphones',99),(4,'Smartwatch',199),(5,'Camera',649),(6,'Speaker',129);
    """); c.commit(); c.close()

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>ShopSphere – Gadgets & More</title><style>
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#f3f4f8;color:#1f2937}
a{color:#4f46e5;text-decoration:none}
.top{background:#111827;color:#fde68a;text-align:center;font-size:.8rem;padding:.4rem}
header{background:#fff;box-shadow:0 2px 12px rgba(0,0,0,.08);position:sticky;top:0;z-index:5}
.bar{max-width:1100px;margin:auto;display:flex;align-items:center;gap:1.2rem;padding:.8rem 1rem;flex-wrap:wrap}
.logo{font-size:1.6rem;font-weight:800;color:#4f46e5;letter-spacing:-.5px}.logo span{color:#f59e0b}
.sbox{flex:1;min-width:200px;display:flex}.sbox input{flex:1;border:2px solid #e5e7eb;border-right:0;border-radius:10px 0 0 10px;padding:.6rem .9rem;font:inherit}
.sbox button{border-radius:0 10px 10px 0}
.icons a{margin-left:1rem;color:#374151;font-size:.9rem;font-weight:600}
nav{background:linear-gradient(90deg,#4f46e5,#7c3aed)}nav div{max-width:1100px;margin:auto;padding:.55rem 1rem;display:flex;gap:1.4rem;overflow:auto}
nav a{color:#fff;font-size:.9rem;white-space:nowrap;opacity:.92}nav a:hover{opacity:1;text-decoration:underline}
main{max-width:1100px;margin:1.3rem auto;padding:0 1rem}
.card{background:#fff;border-radius:14px;padding:1.3rem 1.6rem;box-shadow:0 2px 12px rgba(0,0,0,.06);margin-bottom:1.2rem}
.hero{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:1rem;color:#fff;border-radius:20px;padding:2.2rem 2.5rem;margin-bottom:1.5rem;background:linear-gradient(120deg,#4f46e5,#7c3aed 55%,#db2777)}
.hero h1{font-size:2.3rem;margin:.2rem 0}.hero p{opacity:.92;max-width:430px}.hero .btn{background:#fff;color:#4f46e5;font-weight:700}
h2.sec{margin:1.8rem 0 .8rem;font-size:1.3rem}
.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem}
.cat{background:#fff;border-radius:14px;padding:1rem;text-align:center;font-weight:600;box-shadow:0 2px 10px rgba(0,0,0,.05);color:#374151}
.cat i{display:block;font-size:2rem;font-style:normal;margin-bottom:.3rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:1.1rem}
.prod{background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.07);transition:.2s;position:relative}
.prod:hover{transform:translateY(-4px);box-shadow:0 8px 22px rgba(79,70,229,.18)}
.prod svg{width:100%;height:150px;display:block}.pb{padding:.9rem 1rem 1.1rem}.pb h3{margin:0 0 .2rem;font-size:1.02rem}
.stars{color:#f59e0b;font-size:.85rem}.price{font-size:1.2rem;font-weight:800;color:#4f46e5;margin:.3rem 0}
.tag{position:absolute;top:10px;left:10px;background:#ef4444;color:#fff;font-size:.7rem;padding:.2rem .5rem;border-radius:20px;z-index:2}
.deal{display:flex;flex-wrap:wrap;gap:1rem;align-items:center;justify-content:space-between;background:linear-gradient(100deg,#f59e0b,#ef4444);color:#fff;border-radius:18px;padding:1.5rem 2rem;margin-top:1.8rem}
.deal h2{margin:0}.deal .btn{background:#fff;color:#ef4444;font-weight:700}
.rev{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}
.rev div{background:#fff;border-radius:14px;padding:1.1rem;box-shadow:0 2px 10px rgba(0,0,0,.05);font-size:.92rem}
.news{background:#111827;color:#fff;border-radius:18px;padding:1.6rem 2rem;margin-top:1.8rem;text-align:center}
.news form{display:flex;justify-content:center;gap:.5rem;flex-wrap:wrap}.news input{max-width:300px}
input,textarea,select{width:100%;max-width:440px;padding:.65rem .8rem;border:2px solid #e5e7eb;border-radius:10px;margin:.25rem 0;font:inherit}
input:focus,textarea:focus{outline:0;border-color:#7c3aed}
button,.btn{background:#4f46e5;color:#fff;border:0;border-radius:10px;padding:.65rem 1.2rem;cursor:pointer;display:inline-block;font:inherit;font-weight:600}
button:hover,.btn:hover{background:#4338ca}
pre{background:#111827;color:#e5e7eb;padding:1rem;border-radius:10px;overflow:auto}
footer{background:#111827;color:#9ca3af;margin-top:2rem;padding:2rem 1rem 1rem;font-size:.88rem}
.fc{max-width:1100px;margin:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1.5rem}
footer h4{color:#fff;margin:0 0 .6rem}footer a{color:#9ca3af;display:block;margin:.3rem 0}footer a:hover{color:#fff}
.cp{text-align:center;border-top:1px solid #1f2937;margin-top:1.5rem;padding-top:1rem;font-size:.78rem}
</style></head><body>
<div class=top>🚚 Free shipping on orders above $50 &nbsp;•&nbsp; Use code WELCOME10 for 10% off</div>
<header><div class=bar><a class=logo href="/">Shop<span>Sphere</span></a>
<form class=sbox action="/search"><input name=q placeholder="Search for laptops, phones, headphones…"><button>🔍</button></form>
<div class=icons><a href="/login">👤 Account</a><a href="/shop">🛒 Cart</a></div></div>
<nav><div><a href="/">Home</a><a href="/search">All Products</a><a href="/guestbook">Reviews</a><a href="/transfer">Wallet</a>
<a href="/upload">Support</a><a href="/login">Login</a><a href="/register">Register</a><a href="/labs">🧪 Labs</a></div></nav></header>
<main>{{ body|safe }}</main>
<footer><div class=fc>
<div><h4>ShopSphere</h4><p>A fictional demo store built for security training.</p></div>
<div><h4>Shop</h4><a href="/search?q=Laptop">Laptops</a><a href="/search?q=Phone">Phones</a><a href="/search?q=Headphones">Audio</a></div>
<div><h4>Help</h4><a href="/upload">Support</a><a href="/reset">Forgot password</a><a href="/view?page=contact">Contact</a></div>
<div><h4>Company</h4><a href="/view?page=about">About us</a><a href="/labs">Security labs</a></div></div>
<div class=cp>© ShopSphere – fictional store. Training lab: intentionally vulnerable, authorised practice only.</div></footer>
</body></html>"""
def page(b): return render_template_string(PAGE, body=b)

def cur():
    u = SESS.get(request.cookies.get("sid", ""))
    if u: return u
    r = request.cookies.get("remember")           # VULN: forgeable remember-me (base64 username)
    if r:
        try: return base64.b64decode(r).decode()
        except Exception: pass

@app.after_request
def hdr(r):
    r.headers["Server"] = "Apache/2.2.8 (Ubuntu) DAV/2"          # banner grabbing target
    r.headers["X-Powered-By"] = "PHP/5.2.4-2ubuntu5.10"
    # VULN: no CSP, HSTS, X-Frame-Options (clickjacking), X-Content-Type-Options
    if request.path.startswith("/api/") and request.headers.get("Origin"):
        r.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]   # VULN: CORS reflect
        r.headers["Access-Control-Allow-Credentials"] = "true"
    return r

@app.errorhandler(Exception)
def err(e):                                       # VULN: verbose error messages
    return page(f"<h3>Server error</h3><pre>{type(e).__name__}: {e}\nPath: {request.full_path}</pre>"), 500

# ---------- UNIT 1: recon & misconfiguration ----------
ART = {
 1: '<rect x=32 y=30 width=56 height=36 rx=4 fill="#1f2937"/><rect x=36 y=34 width=48 height=28 fill="#60a5fa"/><path d="M20 70h80l-6 9H26z" fill="#9ca3af"/>',
 2: '<rect x=46 y=14 width=28 height=66 rx=7 fill="#111827"/><rect x=49 y=20 width=22 height=52 rx=2 fill="#a78bfa"/><circle cx=60 cy=76 r=2 fill="#fff"/>',
 3: '<path d="M36 58a24 24 0 0 1 48 0" stroke="#111827" stroke-width=6 fill="none"/><rect x=29 y=54 width=13 height=24 rx=6 fill="#ef4444"/><rect x=78 y=54 width=13 height=24 rx=6 fill="#ef4444"/>',
 4: '<rect x=52 y=10 width=16 height=18 fill="#6b7280"/><rect x=52 y=62 width=16 height=18 fill="#6b7280"/><rect x=46 y=26 width=28 height=38 rx=9 fill="#111827"/><rect x=50 y=31 width=20 height=28 rx=5 fill="#34d399"/>',
 5: '<rect x=40 y=24 width=18 height=9 rx=2 fill="#6b7280"/><rect x=26 y=31 width=68 height=42 rx=7 fill="#374151"/><circle cx=60 cy=52 r=15 fill="#111827"/><circle cx=60 cy=52 r=9 fill="#38bdf8"/>',
 6: '<rect x=42 y=12 width=36 height=68 rx=10 fill="#1f2937"/><circle cx=60 cy=33 r=8 fill="#f59e0b"/><circle cx=60 cy=58 r=13 fill="#374151"/><circle cx=60 cy=58 r=6 fill="#9ca3af"/>'}
BG = {1: "#dbeafe,#e0e7ff", 2: "#ede9fe,#fce7f3", 3: "#fee2e2,#ffedd5", 4: "#d1fae5,#cffafe", 5: "#e0f2fe,#e0e7ff", 6: "#fef3c7,#ffe4e6"}

def art(i):
    a, b = BG.get(i, "#e5e7eb,#f3f4f6").split(",")
    return (f'<svg viewBox="0 0 120 90" preserveAspectRatio="xMidYMid slice"><defs><linearGradient id="g{i}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient></defs>'
            f'<rect width="120" height="90" fill="url(#g{i})"/>{ART.get(i, "")}</svg>')

@app.route("/")
def home():
    ps = db().execute("SELECT id, name, price FROM products").fetchall()
    cards = "".join(
        f"<div class=prod>{'<span class=tag>HOT</span>' if i in (1, 3) else ''}{art(i)}<div class=pb><h3>{n}</h3>"
        f"<div class=stars>★★★★☆ <span style='color:#9ca3af'>({40 + i * 13})</span></div><div class=price>${p:.0f}</div>"
        f"<a class=btn href='/search?q={n}'>View product</a></div></div>" for i, n, p in ps)
    return page(f"""<div class=hero><div><small>NEW SEASON SALE</small><h1>Upgrade your tech.<br>Up to 30% off.</h1>
<p>Laptops, phones, audio and more – delivered fast with easy returns.</p><a class=btn href="/search">Shop now →</a></div>
<svg width=230 height=170 viewBox="0 0 120 90"><circle cx=60 cy=45 r=42 fill="rgba(255,255,255,.15)"/>{ART[1]}<g transform="translate(34 6) scale(.55)">{ART[2]}</g></svg></div>
<div class=cats><a class=cat href="/search?q=Laptop"><i>💻</i>Laptops</a><a class=cat href="/search?q=Phone"><i>📱</i>Phones</a>
<a class=cat href="/search?q=Headphones"><i>🎧</i>Audio</a><a class=cat href="/search?q=Smartwatch"><i>⌚</i>Wearables</a>
<a class=cat href="/search?q=Camera"><i>📷</i>Cameras</a><a class=cat href="/search?q=Speaker"><i>🔊</i>Speakers</a></div>
<h2 class=sec>🔥 Trending products</h2><div class=grid>{cards}</div>
<div class=deal><div><h2>Deal of the day</h2><p>Smartwatch now just $199 – today only!</p></div><a class=btn href="/search?q=Smartwatch">Grab the deal</a></div>
<h2 class=sec>⭐ What customers say</h2><div class=rev>
<div>“Super fast delivery and the laptop is amazing!”<br><b>– Riya S.</b></div>
<div>“Great prices, easy checkout and good support.”<br><b>– Aman P.</b></div>
<div>“The headphones sound fantastic for the price.”<br><b>– Neha K.</b></div></div>
<div class=news><h2 style="margin:0 0 .4rem">Join our newsletter</h2><p>Get offers straight to your inbox.</p>
<form action="/feedback"><input name=msg placeholder="you@email.com"><button>Subscribe</button></form></div>""")

@app.route("/labs")
def labs():
    return page("""<h2>🧪 Lab challenges </h2>
<b>Unit 1 Recon:</b> check response headers, <a href="/robots.txt">robots.txt</a>, <a href="/server-status">default pages</a>, hidden files, error messages<br>
<b>Unit 2:</b> <a href="/search">SQLi + reflected XSS</a>, <a href="/item?id=1">blind SQLi</a>, <a href="/feedback?msg=hi">stacked SQLi</a>, <a href="/guestbook">stored XSS</a>, <a href="/dom">DOM XSS</a><br>
<b>Unit 3:</b> <a href="/login">login</a> (brute force, enumeration, fixation, remember-me), <a href="/reset">reset</a>, <a href="/profile?id=2">IDOR</a>, function-level checks, <a href="/go?url=/">open redirect</a><br>
<b>Unit 4:</b> <a href="/view?page=about">LFI/traversal</a>, <a href="/upload">file upload</a>, <a href="/transfer">CSRF/clickjacking</a>, <a href="/shop">logic flaw</a>, CORS (/api/me), <a href="/fib?n=10">DoS</a>""")

@app.route("/robots.txt")
def robots(): return "User-agent: *\nDisallow: /admin\nDisallow: /admin-backup/\nDisallow: /backup.sql.bak\n", 200, {"Content-Type": "text/plain"}
@app.route("/server-status")
def status(): return page("<h2>It works!</h2><p>Apache/2.2.8 default page. Server uptime: 12 days. PHP 5.2.4. DB: SQLite 3</p>")
@app.route("/admin-backup/")
def abk(): return page("<h2>Hidden dir</h2>FLAG{hidden_resource_discovery}")
@app.route("/backup.sql.bak")
def bak(): return "INSERT INTO users VALUES ('admin','admin123');", 200, {"Content-Type": "text/plain"}

# ---------- UNIT 2: injection & XSS ----------
@app.route("/search")
def search():
    q, out = request.args.get("q", ""), ""
    if q:
        try:  # VULN: error-based / UNION SQLi (2 columns)
            rows = db().execute(f"SELECT name, price FROM products WHERE name LIKE '%{q}%'").fetchall()
        except Exception as e: rows, out = [], f"<pre>SQL error: {e}</pre>"
        out += f"<p>Results for: {q}</p><ul>" + "".join(f"<li>{n} - ${p}</li>" for n, p in rows) + "</ul>"  # VULN: reflected XSS
    return page(f"<h2>Search</h2><form><input name=q><button>Go</button></form>{out}")

@app.route("/item")
def item():  # VULN: boolean/time-based blind SQLi (errors hidden). Time: randomblob() heavy compute
    try: r = db().execute(f"SELECT name FROM products WHERE id={request.args.get('id','1')}").fetchone()
    except Exception: r = None
    return page("In stock" if r else "Not found")

@app.route("/feedback")
def feedback():  # VULN: stacked queries (executescript)
    m = request.args.get("msg", "")
    c = db(); c.executescript(f"INSERT INTO comments(author,body) VALUES ('anon','{m}')"); c.commit()
    return page("Thanks for your feedback")

@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():  # VULN: stored XSS (hook a BeEF script here)
    c = db()
    if request.method == "POST":
        c.execute("INSERT INTO comments(author,body) VALUES (?,?)", (request.form.get("author", "anon"), request.form.get("body", ""))); c.commit()
    items = "".join(f"<p><b>{a}</b>: {b}</p>" for a, b in c.execute("SELECT author, body FROM comments"))
    return page(f"<h2>Guestbook</h2><form method=post><input name=author placeholder=name><br><textarea name=body></textarea><br><button>Post</button></form>{items}")

@app.route("/dom")
def dom():  # VULN: DOM XSS via location.hash -> innerHTML
    return page("<h2>DOM XSS</h2><div id=o></div><script>document.getElementById('o').innerHTML=decodeURIComponent(location.hash.slice(1))</script><p>Try /dom#hello</p>")

# ---------- UNIT 3: authentication & access control ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":  # VULN: no rate limiting / lockout / CAPTCHA
        u, p = request.form.get("username", ""), request.form.get("password", "")
        q = f"SELECT id, username FROM users WHERE username='{u}' AND password='{p}'"   # VULN: SQLi
        try: row = db().execute(q).fetchone()
        except Exception as e: return page(f"<pre>SQL error: {e}\nQuery: {q}</pre>")
        if row:
            sid = request.args.get("sid") or request.cookies.get("sid") or str(next(ids))  # VULN: session fixation
            SESS[sid] = row[1]
            r = make_response(redirect(f"/profile?id={row[0]}")); r.set_cookie("sid", sid)  # no HttpOnly/Secure
            if request.form.get("remember"): r.set_cookie("remember", base64.b64encode(row[1].encode()).decode())
            return r
        ex = db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
        msg = "<p style=color:red>" + ("Wrong password" if ex else "Unknown user") + "</p>"   # VULN: user enumeration
    return page(f"""<h2>Login</h2>{msg}<form method=post onsubmit="localStorage.setItem('last_login',this.username.value+':'+this.password.value)">
<input name=username placeholder=username><br><input name=password type=password placeholder=password><br>
<label><input type=checkbox name=remember> remember me</label><br><button>Login</button></form><p>New here? <a href="/register">Create an account</a></p>""")

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if not u or not p:
            msg = "<p style=color:red>Username and password required</p>"
        else:
            c = db()
            # VULN: no password strength check, no uniqueness race protection, plaintext storage
            exists = c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
            if exists:
                msg = "<p style=color:red>Username already taken</p>"
            else:
                c.execute("INSERT INTO users(username,password,role,secret,balance) VALUES (?,?,?,?,?)",
                          (u, p, "user", f"{u}'s private note", 500))
                c.commit()
                return page(f"<h2>Account created</h2><p>Welcome, {u}! You can now <a href='/login'>log in</a>.</p>")
    return page(f"""<h2>Create account</h2>{msg}<form method=post>
<input name=username placeholder="Choose a username"><br>
<input name=password type=password placeholder="Choose a password"><br>
<button>Register</button></form><p>Already have an account? <a href="/login">Login</a></p>""")

@app.route("/logout")
def logout():  # VULN: only clears cookie; server session & remember cookie stay valid
    r = make_response(redirect("/")); r.delete_cookie("sid"); return r

@app.route("/reset")
def reset():  # VULN: predictable token = md5(username), no expiry
    u, t, n = request.args.get("user"), request.args.get("token"), request.args.get("new")
    if u and t and n and t == hashlib.md5(u.encode()).hexdigest():
        c = db(); c.execute("UPDATE users SET password=? WHERE username=?", (n, u)); c.commit(); return page("Password changed")
    if u: return page("If the account exists, a reset link was emailed.")
    return page("<h2>Reset</h2><form><input name=user placeholder=username><button>Send link</button></form>")

@app.route("/profile")
def profile():  # VULN: IDOR
    r = db().execute("SELECT username, role, secret, balance FROM users WHERE id=?", (request.args.get("id", "1"),)).fetchone()
    return page(f"<h2>Profile</h2>User: {r[0]}<br>Role: {r[1]}<br>Secret: {r[2]}<br>Balance: {r[3]}" if r else "Not found")

@app.route("/admin")
def admin():  # VULN: missing function-level access check
    rows = db().execute("SELECT id, username, password, role FROM users").fetchall()
    return page("<h2>Admin panel</h2><pre>" + "\n".join(map(str, rows)) + "</pre>")

@app.route("/promote")
def promote():  # VULN: privilege escalation, no auth/role check
    c = db(); c.execute("UPDATE users SET role=? WHERE username=?", (request.args.get("role", "admin"), request.args.get("user", ""))); c.commit()
    return page("Role updated")

@app.route("/api/users")
def api_users(): return jsonify(db().execute("SELECT id, username, role FROM users").fetchall())  # no auth

@app.route("/api/me")
def api_me():  # VULN: CORS reflects any Origin with credentials
    u = cur()
    r = db().execute("SELECT username, secret FROM users WHERE username=?", (u,)).fetchone() if u else None
    return jsonify(user=r[0], secret=r[1]) if r else (jsonify(error="login required"), 401)

@app.route("/go")
def go(): return redirect(request.args.get("url", "/"))  # VULN: open redirect

# ---------- UNIT 4: advanced ----------
@app.route("/view")
def view():  # VULN: LFI / path traversal (try ?page=../../../../etc/passwd)
    return page("<pre>" + open(os.path.join(PG, request.args.get("page", "about") + ("" if "/" in request.args.get("page", "") else ".txt"))).read() + "</pre>")

@app.route("/upload", methods=["GET", "POST"])
def upload():  # VULN: arbitrary file upload (no type/name checks), served same-origin
    msg = ""
    if request.method == "POST":
        f = request.files["f"]; f.save(os.path.join(UP, f.filename)); msg = f"Saved: <a href='/uploads/{f.filename}'>{f.filename}</a>"
    return page(f"<h2>Upload</h2>{msg}<form method=post enctype=multipart/form-data><input type=file name=f><button>Upload</button></form>")
@app.route("/uploads/<path:n>")
def uploaded(n): return send_from_directory(UP, n)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():  # VULN: CSRF (no token, accepts GET) + frameable (clickjacking)
    u = cur()
    if not u: return redirect("/login")
    to, amt, msg = request.values.get("to"), request.values.get("amount"), ""
    if to and amt:
        c = db(); c.execute("UPDATE users SET balance=balance-? WHERE username=?", (int(amt), u))
        c.execute("UPDATE users SET balance=balance+? WHERE username=?", (int(amt), to)); c.commit(); msg = "Transfer done"
    return page(f"<h2>Transfer ({u})</h2>{msg}<form method=post><input name=to placeholder=to><input name=amount placeholder=amount><button>Send</button></form>")

@app.route("/shop", methods=["GET", "POST"])
def shop():  # VULN: business logic - negative quantity, no balance check
    u = cur()
    if not u: return redirect("/login")
    c = db()
    if request.method == "POST":
        c.execute("UPDATE users SET balance=balance-? WHERE username=?", (int(request.form.get("qty", "1")) * 100, u)); c.commit()
    b = c.execute("SELECT balance FROM users WHERE username=?", (u,)).fetchone()[0]
    return page(f"<h2>Shop</h2>Balance: {b}<form method=post>Gadget ($100) qty <input name=qty value=1><button>Buy</button></form>")

@app.route("/fib")
def fib():  # VULN: unbounded CPU work (DoS) - try large n
    def f(n): return n if n < 2 else f(n - 1) + f(n - 2)
    return page(str(f(int(request.args.get("n", "10")))))

@app.route("/reset-data")
def reset_data(): init(); SESS.clear(); return redirect("/")

if __name__ == "__main__":
    init(); app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), threaded=True)
