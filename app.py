"""VulnLab v2 - INTENTIONALLY VULNERABLE app mapped to CSM5011C (Web Application Security).
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
    INSERT INTO products VALUES (1,'Laptop',799),(2,'Phone',499),(3,'Headphones',99);
    """); c.commit(); c.close()

PAGE = """<!doctype html><title>VulnLab</title>
<style>body{font-family:sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem}
nav a{margin-right:.8rem}.w{background:#fee;border:1px solid #c00;padding:.5rem}
input,textarea{padding:.4rem;margin:.2rem 0}</style>
<div class="w">⚠ Intentionally vulnerable – lab use only.</div>
<nav><a href="/">Home</a><a href="/login">Login</a><a href="/search">Search</a>
<a href="/guestbook">Guestbook</a><a href="/shop">Shop</a><a href="/upload">Upload</a></nav><hr>{{ body|safe }}"""
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
@app.route("/")
def home():
    return page("""<h2>VulnLab – syllabus-mapped challenges</h2>
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
<label><input type=checkbox name=remember> remember me</label><br><button>Login</button></form>""")

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
