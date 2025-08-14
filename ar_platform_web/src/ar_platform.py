# file: ar_platform.py
from __future__ import annotations

import csv
import io
import os
import secrets
import sqlite3
import hashlib
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Iterable, Tuple, Union, Dict, List

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import (
    HTMLResponse, RedirectResponse, StreamingResponse, PlainTextResponse
)
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

# --------------------------- Config --------------------------------------------

DB_FILE = "ar_platform.db"
SECRET_KEY = os.environ.get("AR_SECRET_KEY", "dev-secret-change-me")
app = FastAPI(title="A/R Payment Tracker (Multi-AR + Auth)")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax")

# --------------------------- DB Utils & Init -----------------------------------

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(r["name"] == column for r in conn.execute(f"PRAGMA table_info({table})"))

def init_db() -> None:
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ar_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                pwd_salt BLOB NOT NULL,
                pwd_hash BLOB NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS user_ar_access (
                user_id INTEGER NOT NULL,
                ar_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, ar_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (ar_id) REFERENCES ar_entities(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ar_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                company TEXT,
                UNIQUE(ar_id, name),
                FOREIGN KEY (ar_id) REFERENCES ar_entities(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ar_id INTEGER NOT NULL,
                client_id INTEGER NOT NULL,
                issue_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                amount REAL NOT NULL CHECK(amount >= 0),
                invoice_number TEXT,
                status TEXT,
                check_in TEXT,
                check_out TEXT,
                nights INTEGER,
                rate_per_night REAL,
                case_number TEXT,
                FOREIGN KEY (ar_id) REFERENCES ar_entities(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                payment_date TEXT NOT NULL,
                method TEXT,
                check_number TEXT,
                check_date TEXT,
                FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
            );
            """
        )
        # Migrations / indexes
        if not column_exists(conn, "invoices", "invoice_number"):
            conn.execute("ALTER TABLE invoices ADD COLUMN invoice_number TEXT")
        if not column_exists(conn, "invoices", "status"):
            conn.execute("ALTER TABLE invoices ADD COLUMN status TEXT")
            conn.execute("UPDATE invoices SET status = 'OPEN' WHERE status IS NULL")
        if not column_exists(conn, "invoices", "check_in"):
            conn.execute("ALTER TABLE invoices ADD COLUMN check_in TEXT")
        if not column_exists(conn, "invoices", "check_out"):
            conn.execute("ALTER TABLE invoices ADD COLUMN check_out TEXT")
        if not column_exists(conn, "invoices", "nights"):
            conn.execute("ALTER TABLE invoices ADD COLUMN nights INTEGER")
        if not column_exists(conn, "invoices", "rate_per_night"):
            conn.execute("ALTER TABLE invoices ADD COLUMN rate_per_night REAL")
        if not column_exists(conn, "invoices", "case_number"):
            conn.execute("ALTER TABLE invoices ADD COLUMN case_number TEXT")

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_invoice_ar_number
            ON invoices(ar_id, invoice_number) WHERE invoice_number IS NOT NULL
        """)
        conn.execute("INSERT OR IGNORE INTO ar_entities(name) VALUES ('Red Roof Inn')")
        conn.execute("INSERT OR IGNORE INTO ar_entities(name) VALUES ('Motel 6')")
        conn.commit()
    finally:
        conn.close()

# --------------------------- Passwords & Auth Helpers --------------------------

def _hash_password(password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt, pwd_hash

def _verify_password(password: str, salt: bytes, pwd_hash: bytes) -> bool:
    test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return secrets.compare_digest(test, pwd_hash)

@dataclass
class User:
    id: int
    name: str
    email: str
    is_admin: bool

def current_user(request: Request) -> Optional[User]:
    uid = request.session.get("uid")
    if not uid:
        return None
    conn = connect()
    try:
        row = conn.execute("SELECT id, name, email, is_admin FROM users WHERE id = ?", (uid,)).fetchone()
        if not row:
            return None
        return User(id=row["id"], name=row["name"], email=row["email"], is_admin=bool(row["is_admin"]))
    finally:
        conn.close()

def set_current_ar(request: Request, ar_id: int) -> None:
    request.session["ar_id"] = ar_id

def get_current_ar(request: Request) -> Optional[int]:
    return request.session.get("ar_id")

def user_allowed_ar_ids(user_id: int) -> list[sqlite3.Row]:
    conn = connect()
    try:
        rows = conn.execute("""
            SELECT ar.id, ar.name
            FROM ar_entities ar
            JOIN user_ar_access ua ON ua.ar_id = ar.id
            WHERE ua.user_id = ?
            ORDER BY ar.name
        """, (user_id,)).fetchall()
        return rows
    finally:
        conn.close()

EnsureScopeResult = Union[RedirectResponse, Tuple[User, int]]

def ensure_scope(request: Request) -> EnsureScopeResult:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    ar_id = get_current_ar(request)
    if not ar_id:
        return RedirectResponse("/switch-ar", status_code=303)
    allowed = [r["id"] for r in user_allowed_ar_ids(user.id)]
    if ar_id not in allowed:
        return RedirectResponse("/switch-ar", status_code=303)
    return (user, ar_id)

# --------------------------- Shared HTML shell ----------------------------------

BASE_CSS = """
:root { --muted:#888; --b:#ddd; --bg:#fafafa; --call:#2684ff; --danger:#d33; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height:1.45; }
header a { text-decoration:none; color:#333 }
nav a { margin-right: 12px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid var(--b); padding: 8px; text-align:left; }
th { background: #f5f5f5; }
.row { margin: 12px 0; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.btn { display:inline-block; padding:6px 10px; border:1px solid #ccc; border-radius:6px; background:var(--bg); cursor:pointer; text-decoration:none; color:#111; }
.btn.danger { border-color:var(--danger); color:var(--danger); }
.btn.primary { border-color:var(--call); color:var(--call); }
form.inline { display:inline; }
input, select { padding:6px; }
.muted { color:var(--muted); }
.brand { display:flex; gap:10px; align-items:center; justify-content:space-between; }
.search input[type=text]{ min-width:260px; }
@media (max-width:680px) { .search input[type=text] { min-width:160px; } }
.kpi { display:flex; gap:14px; flex-wrap:wrap; }
.kpi .card { border:1px solid var(--b); padding:10px 14px; border-radius:8px; background:#fff; min-width:160px; }
.right { text-align:right; }
.small { font-size: 12px; color: var(--muted); }
.badge { padding:2px 6px; border:1px solid var(--b); border-radius: 999px; font-size: 12px; background:#fff; }
.topbar { display:flex; gap:10px; align-items:center; }
.ar-switch { margin-left: 12px; }
.kebab { position: relative; display:inline-block; }
.kebab > button { border: none; background: transparent; font-size: 20px; line-height: 1; cursor: pointer; padding: 2px 6px; }
.menu { display:none; position:absolute; right:0; z-index:5; min-width: 180px; background:#fff; border:1px solid var(--b); border-radius:8px; box-shadow: 0 6px 18px rgba(0,0,0,.08); }
.menu a, .menu button { display:block; width:100%; text-align:left; background:#fff; border:0; padding:8px 10px; cursor:pointer; text-decoration:none; color:#111; }
.menu a:hover, .menu button:hover { background:#f5f5f5; }
"""

JS_PREVIEW = """
<script>
function _parseDate(str){ if(!str) return null; const d = new Date(str); return isNaN(d) ? null : d; }
function _diffNights(ci, co){
  if(!ci || !co) return 0;
  const MS=24*3600*1000;
  const n = Math.round((co - ci)/MS);
  return Math.max(n, 0);
}
function previewInvoice(calcIdPrefix){
  const ci = _parseDate(document.querySelector(`[name="${calcIdPrefix}check_in"]`)?.value);
  const co = _parseDate(document.querySelector(`[name="${calcIdPrefix}check_out"]`)?.value);
  const rate = parseFloat(document.querySelector(`[name="${calcIdPrefix}rate_per_night"]`)?.value || "0");
  const nights = _diffNights(ci, co);
  const amount = (nights * rate).toFixed(2);
  const el = document.getElementById(calcIdPrefix + "preview");
  if(el){ el.textContent = (nights>0 && rate>=0) ? `Preview: ${nights} night(s) × ${rate.toFixed(2)} = ${amount}` : "Preview: —"; }
}
document.addEventListener("input", (e)=>{
  if(["check_in","check_out","rate_per_night"].some(n => e.target.name?.endsWith(n))){
    const pref = e.target.name.includes("client_") ? "client_" : "global_";
    previewInvoice(pref);
  }
});
document.addEventListener('click', (e) => {
  if (e.target.closest('.kebab')) {
    const kb = e.target.closest('.kebab');
    const open = kb.querySelector('.menu');
    const visible = open.style.display === 'block';
    document.querySelectorAll('.kebab .menu').forEach(m => m.style.display='none');
    open.style.display = visible ? 'none' : 'block';
  } else {
    document.querySelectorAll('.kebab .menu').forEach(m => m.style.display='none');
  }
});
function confirmPost(formId, msg) { if (confirm(msg)) document.getElementById(formId).submit(); }
</script>
"""

def shell(request: Request, title: str, body: str, back: str | None = "/") -> HTMLResponse:
    user = current_user(request)
    ar_id = get_current_ar(request)
    ar_label = ""
    if user and ar_id:
        conn = connect()
        try:
            row = conn.execute("SELECT name FROM ar_entities WHERE id = ?", (ar_id,)).fetchone()
            if row:
                ar_label = f"<span class='badge'>{row['name']}</span>"
        finally:
            conn.close()
    auth_links = (
        f"<span class='muted'>Hello, {user.name}</span> {ar_label} "
        "<a class='btn ar-switch' href='/switch-ar'>Switch A/R</a> "
        f"{'<a class=\"btn\" href=\"/admin/users\">Admin</a>' if (user and user.is_admin) else ''} "
        "<a class='btn' href='/logout'>Logout</a>"
        if user else
        "<a class='btn' href='/login'>Login</a> <a class='btn' href='/register'>Register</a>"
    )
    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{BASE_CSS}</style>
{JS_PREVIEW}
</head><body>
<header>
  <div class="brand">
    <div class="topbar">
      <h2 style="margin:0"><a href="/">A/R Payment Tracker</a></h2>
      <nav style="margin-top:6px;">
        <a href="/clients">Clients</a>
        <a href="/invoices">Invoices</a>
        <a href="/search">Search</a>
      </nav>
    </div>
    <div>{auth_links}</div>
  </div>
</header>
{body}
{'' if back is None else f'<div class="row"><a class="btn" href="{back}">← Back</a></div>'}
</body></html>"""
    return HTMLResponse(html)

# --------------------------- Auth Routes ---------------------------------------

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    init_db()
    body = """
    <h3>Register</h3>
    <form method="post" action="/register">
      <div class="row">
        <input name="name" placeholder="Full name" required>
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
      </div>
      <button class="btn primary" type="submit">Create Account</button>
      <div class="small">First account becomes admin and can assign A/R access to others.</div>
    </form>
    """
    return shell(request, "Register", body, back=None)

@app.post("/register")
def register(request: Request, name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    init_db()
    conn = connect()
    try:
        exists = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        salt, pwd_hash = _hash_password(password)
        conn.execute(
            "INSERT INTO users(name, email, pwd_salt, pwd_hash, is_admin) VALUES (?, ?, ?, ?, ?)",
            (name.strip(), email.strip().lower(), salt, pwd_hash, 1 if exists == 0 else 0)
        )
        user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()["id"]
        if exists == 0:
            for ar in conn.execute("SELECT id FROM ar_entities").fetchall():
                conn.execute("INSERT OR IGNORE INTO user_ar_access(user_id, ar_id) VALUES (?, ?)", (user_id, ar["id"]))
        conn.commit()
    except sqlite3.IntegrityError:
        return PlainTextResponse("Email already registered.", status_code=400)
    finally:
        conn.close()
    return RedirectResponse("/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    init_db()
    body = """
    <h3>Login</h3>
    <form method="post" action="/login">
      <div class="row">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
      </div>
      <button class="btn primary" type="submit">Login</button>
    </form>
    """
    return shell(request, "Login", body, back=None)

@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    init_db()
    conn = connect()
    try:
        row = conn.execute("SELECT id, name, email, pwd_salt, pwd_hash, is_admin FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if not row or not _verify_password(password, row["pwd_salt"], row["pwd_hash"]):
            return PlainTextResponse("Invalid credentials.", status_code=401)
        request.session["uid"] = row["id"]
        ars = conn.execute("""
            SELECT ar.id FROM ar_entities ar
            JOIN user_ar_access ua ON ua.ar_id = ar.id
            WHERE ua.user_id = ?
            ORDER BY ar.name
        """, (row["id"],)).fetchall()
        if ars:
            set_current_ar(request, ars[0]["id"])
        else:
            request.session.pop("ar_id", None)
    finally:
        conn.close()
    return RedirectResponse("/", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

# --------------------------- Dashboard -----------------------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    init_db()
    if not current_user(request):
        return RedirectResponse("/register", status_code=303)
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    body = """
    <h3>Dashboard</h3>
    <div class="row">
      <a class="btn primary" href="/invoices">View Invoices</a>
      <a class="btn" href="/clients">Manage Clients</a>
      <a class="btn" href="/payments">Manage Payments</a>
    </div>
    <div class="row" style="margin-top:24px">
      <a class="btn" href="/export/invoices.csv">Export Invoices (CSV)</a>
      <a class="btn" href="/export/payments.csv">Export Payments (CSV)</a>
    </div>
    """
    return shell(request, "Dashboard", body, back=None)

@app.get("/switch-ar", response_class=HTMLResponse)
def switch_ar(request: Request):
    init_db()
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    ars = user_allowed_ar_ids(user.id)
    options = "".join(f"<option value='{r['id']}'>{r['name']}</option>" for r in ars) or "<option>(no access)</option>"
    body = f"""
    <h3>Switch A/R</h3>
    <form method="post" action="/switch-ar">
      <select name="ar_id" required>{options}</select>
      <button class="btn primary" type="submit">Switch</button>
    </form>
    """
    return shell(request, "Switch A/R", body)

@app.post("/switch-ar")
def do_switch_ar(request: Request, ar_id: int = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    allowed = [r["id"] for r in user_allowed_ar_ids(user.id)]
    if ar_id not in allowed:
        return PlainTextResponse("You do not have access to this A/R.", status_code=403)
    set_current_ar(request, ar_id)
    return RedirectResponse("/", status_code=303)

# --------------------------- Admin: Users & Access ------------------------------

@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request):
    init_db()
    user = current_user(request)
    if not user or not user.is_admin:
        return PlainTextResponse("Admin only.", status_code=403)
    conn = connect()
    try:
        users = conn.execute("SELECT id, name, email, is_admin FROM users ORDER BY id").fetchall()
        ars = conn.execute("SELECT id, name FROM ar_entities ORDER BY name").fetchall()
        rows = []
        for u in users:
            access = set(r["ar_id"] for r in conn.execute("SELECT ar_id FROM user_ar_access WHERE user_id = ?", (u["id"],)).fetchall())
            checks = " ".join(
                f"<label><input type='checkbox' name='ar_{u['id']}_{ar['id']}' {'checked' if ar['id'] in access else ''}> {ar['name']}</label>"
                for ar in ars
            )
            rows.append(
                f"<tr><td>{u['id']}</td><td>{u['name']}</td><td>{u['email']}</td>"
                f"<td>{'yes' if u['is_admin'] else 'no'}</td><td>{checks}</td></tr>"
            )
        table = "".join(rows) or "<tr><td colspan='5'>(no users)</td></tr>"
        body = f"""
        <h3>Admin: Users & Access</h3>
        <form method="post" action="/admin/users/save">
          <table>
            <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Admin</th><th>Access (check to allow)</th></tr></thead>
            <tbody>{table}</tbody>
          </table>
          <button class="btn primary" type="submit">Save Access</button>
        </form>
        """
        return shell(request, "Admin Users", body)
    finally:
        conn.close()

@app.post("/admin/users/save")
async def admin_users_save(request: Request):
    user = current_user(request)
    if not user or not user.is_admin:
        return PlainTextResponse("Admin only.", status_code=403)
    conn = connect()
    try:
        form = await request.form()
        users = conn.execute("SELECT id FROM users").fetchall()
        ars = conn.execute("SELECT id FROM ar_entities").fetchall()
        for u in users:
            for ar in ars:
                key = f"ar_{u['id']}_{ar['id']}"
                has = key in form
                exists = conn.execute(
                    "SELECT 1 FROM user_ar_access WHERE user_id = ? AND ar_id = ?",
                    (u["id"], ar["id"])
                ).fetchone()
                if has and not exists:
                    conn.execute("INSERT INTO user_ar_access(user_id, ar_id) VALUES (?, ?)", (u["id"], ar["id"]))
                if not has and exists:
                    conn.execute("DELETE FROM user_ar_access WHERE user_id = ? AND ar_id = ?", (u["id"], ar["id"]))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin/users", status_code=303)

# --------------------------- Helpers -------------------------------------------

def paid_and_balance(conn: sqlite3.Connection, inv_id: int) -> tuple[float, float, float]:
    row = conn.execute("SELECT amount FROM invoices WHERE id = ?", (inv_id,)).fetchone()
    if not row:
        raise ValueError("Invoice not found")
    amt = float(row["amount"])
    paid = float(conn.execute("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE invoice_id = ?", (inv_id,)).fetchone()["s"])
    return amt, paid, round(amt - paid, 2)

def get_clients(conn: sqlite3.Connection, ar_id: int) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM clients WHERE ar_id = ? ORDER BY name", (ar_id,)))

def get_companies(conn: sqlite3.Connection, ar_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT company FROM clients WHERE ar_id = ? AND company IS NOT NULL AND TRIM(company) != '' ORDER BY company",
        (ar_id,)
    ).fetchall()
    return [r["company"] for r in rows]

def parse_date(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def compute_nights(check_in: str, check_out: str) -> int:
    d1 = parse_date(check_in)
    d2 = parse_date(check_out)
    nights = (d2 - d1).days
    if nights <= 0:
        return 0
    return nights

def month_range(year: int, month: int) -> tuple[str, str]:
    if month < 1 or month > 12:
        raise ValueError("month must be 1..12")
    start = date(year, month, 1)
    if month == 12:
        nextm = date(year + 1, 1, 1)
    else:
        nextm = date(year, month + 1, 1)
    return (start.isoformat(), nextm.isoformat())

def year_range(year: int) -> tuple[str, str]:
    start = date(year, 1, 1).isoformat()
    nexty = date(year + 1, 1, 1).isoformat()
    return (start, nexty)

def overlap_sql() -> str:
    return "(i.check_in < ? AND i.check_out > ?)"

def parse_opt_int(s: Optional[str]) -> Optional[int]:
    if s is None: return None
    s2 = s.strip()
    if not s2: return None
    try:
        return int(s2)
    except ValueError:
        return None

# --------------------------- Clients -------------------------------------------

@app.get("/clients", response_class=HTMLResponse)
def clients_list(request: Request):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        rows = get_clients(conn, ar_id)
        items = "".join(
            f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['company'] or ''}</td><td>{r['email'] or ''}</td>"
            f"<td><a class='btn' href='/client/{r['id']}'>View</a></td></tr>"
            for r in rows
        ) or '<tr><td colspan="5" class="muted">(no clients)</td></tr>'
        body = f"""
        <h3>Clients</h3>
        <table><thead><tr><th>ID</th><th>Name</th><th>Company</th><th>Email</th><th>Actions</th></tr></thead><tbody>{items}</tbody></table>
        <h4>Add Client</h4>
        <form method="post" action="/clients/add">
          <div class="row">
            <input name="name" placeholder="Client name" required>
            <input name="company" placeholder="Company (optional)">
            <input name="email" placeholder="Email">
          </div>
          <button class="btn primary" type="submit">Add Client</button>
        </form>
        """
        return shell(request, "Clients", body)
    finally:
        conn.close()

@app.post("/clients/add")
def clients_add(request: Request, name: str = Form(...), email: Optional[str] = Form(None), company: Optional[str] = Form(None)):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO clients (ar_id, name, email, company) VALUES (?, ?, ?, ?)",
            (ar_id, name.strip(), email, (company or "").strip() or None)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return PlainTextResponse("Client name must be unique within this A/R.", status_code=400)
    finally:
        conn.close()
    return RedirectResponse(url="/clients", status_code=303)

# --------------------------- Invoices: list/create/void/update -----------------

@app.get("/invoices", response_class=HTMLResponse)
def invoices_list(
    request: Request,
    outstanding: bool = Query(False),
    client_like: Optional[str] = Query(None),
    company: Optional[str] = Query(None),
    year: Optional[str] = Query(None),
    month: Optional[str] = Query(None),
    include_void: bool = Query(False),
):
    """Filters by company and stay overlap with year/month."""
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    year_i = parse_opt_int(year)
    month_i = parse_opt_int(month)
    conn = connect()
    try:
        where = ["i.ar_id = ?"]
        params: list = [ar_id]

        if client_like:
            where.append("c.name LIKE ?")
            params.append(f"%{client_like.strip()}%")
        if company:
            where.append("c.company = ?")
            params.append(company.strip())
        if year_i and month_i:
            start, end = month_range(year_i, month_i)
            where.append(overlap_sql())
            params.extend([end, start])
        elif year_i:
            start, end = year_range(year_i)
            where.append(overlap_sql())
            params.extend([end, start])

        if not include_void:
            where.append("i.status != 'VOID'")

        where_sql = " WHERE " + " AND ".join(where)

        rows = conn.execute(
            f"""
            SELECT
                i.id, i.invoice_number, i.amount, i.status, i.check_in, i.check_out,
                c.name AS client, c.company AS company,
                COALESCE(SUM(p.amount),0) AS paid,
                (i.amount - COALESCE(SUM(p.amount),0)) AS balance
            FROM invoices i
            JOIN clients c ON c.id = i.client_id
            LEFT JOIN payments p ON p.invoice_id = i.id
            {where_sql}
            GROUP BY i.id
            ORDER BY i.id
            """,
            params,
        ).fetchall()

        if outstanding:
            rows = [r for r in rows if r["balance"] > 0]

        trs = []
        for r in rows:
            inv_no = r["invoice_number"] or "(none)"
            kebab = (
                "<div class='kebab'>"
                "<button title='Options'>⋮</button>"
                "<div class='menu'>"
                f"<a href='/invoice/{r['id']}'>Open</a>"
                f"<a href='/invoice/{r['id']}/print' target='_blank'>Print</a>"
                f"<a href='/invoice/{r['id']}/audit'>Audit Log</a>"
                f"<a href='/invoices/{r['id']}/payments'>Payments</a>"
                f"<form id='void{r['id']}' class='inline' method='post' action='/invoices/{r['id']}/void'></form>"
                f"<button onclick=\"confirmPost('void{r['id']}', 'Void this invoice?')\">Void</button>"
                "</div></div>"
            )
            upd = (
                f"<form class='inline' method='post' action='/invoices/{r['id']}/update_amount' "
                "onsubmit=\"return confirm('Update amount?');\">"
                "<input type='number' step='0.01' min='0' name='amount' placeholder='New amount' required>"
                "<button class='btn' type='submit'>Update</button>"
                "</form>"
            )
            trs.append(
                "<tr>"
                f"<td>{inv_no}</td>"
                f"<td>{r['client']}</td>"
                f"<td class='right'>{r['amount']:.2f}</td>"
                f"<td class='right'>{r['paid']:.2f}</td>"
                f"<td class='right'>{r['balance']:.2f}</td>"
                f"<td>{kebab} {upd}</td>"
                "</tr>"
            )
        table = "".join(trs) or '<tr><td colspan="6" class="muted">(no invoices)</td></tr>'

        companies = get_companies(conn, ar_id)
        company_options = "".join(
            f'<option value="{co}" {"selected" if company==co else ""}>{co}</option>' for co in companies
        )
        years_rows = conn.execute(
            "SELECT DISTINCT substr(COALESCE(check_in, issue_date),1,4) AS yr "
            "FROM invoices WHERE ar_id = ? AND substr(COALESCE(check_in, issue_date),1,4) IS NOT NULL "
            "ORDER BY yr DESC",
            (ar_id,)
        ).fetchall()
        years: List[int] = []
        for r in years_rows:
            yr = str(r["yr"]) if r["yr"] is not None else ""
            if yr.isdigit():
                years.append(int(yr))
        year_options = "".join(f'<option value="{y}" {"selected" if year_i==y else ""}>{y}</option>' for y in years)
        month_options = "".join(f'<option value="{m}" {"selected" if month_i==m else ""}>{m:02d}</option>' for m in range(1,13))

        create_client_options = "".join(
            f'<option value="{c["id"]}">{c["name"]} ({c["company"] or "—"})</option>'
            for c in get_clients(conn, ar_id)
        ) or '<option value="">(add a client first)</option>'

        body = f"""
        <h3>Invoices</h3>
        <form method="get" action="/invoices">
          <div class="row">
            <label><input type="checkbox" name="outstanding" {"checked" if outstanding else ""}> Outstanding only</label>
            <input name="client_like" placeholder="Client contains..." value="{client_like or ''}">
            <label> Company:
              <select name="company"><option value="">(all)</option>{company_options}</select>
            </label>
            <label> Year:
              <select name="year"><option value="">(any)</option>{year_options}</select>
            </label>
            <label> Month:
              <select name="month"><option value="">(any)</option>{month_options}</select>
            </label>
            <label><input type="checkbox" name="include_void" {"checked" if include_void else ""}> Include VOID</label>
            <button class="btn" type="submit">Apply</button>
          </div>
          <div class="small">Year/Month filters use stay dates (check-in/check-out). Spanning stays appear in each overlapping month.</div>
        </form>

        <table>
          <thead><tr>
            <th>Invoice #</th><th>Client</th><th class="right">Amount</th>
            <th class="right">Paid</th><th class="right">Balance</th><th>Actions</th>
          </tr></thead>
          <tbody>{table}</tbody>
        </table>

        <h4>Create Invoice</h4>
        <form method="post" action="/invoices/create" oninput="previewInvoice('global_')">
          <div class="row">
            <label>Client
              <select name="client_id" required>{create_client_options}</select>
            </label>
            <label>Invoice # <input name="invoice_number" required></label>
            <label>Case # <input name="case_number" placeholder="Case #"></label>
          </div>
          <div class="row">
            <label>Issue Date <input type="date" name="issue_date" required></label>
            <label>Due Date <input type="date" name="due_date" required></label>
          </div>
          <div class="row">
            <label>Check-in <input type="date" name="global_check_in" required></label>
            <label>Check-out <input type="date" name="global_check_out" required></label>
            <label>Rate/night <input type="number" step="0.01" min="0" name="global_rate_per_night" required></label>
          </div>
          <div id="global_preview" class="small">Preview: —</div>
          <div class="small">Amount is auto-calculated: nights × rate/night.</div>
          <button class="btn primary" type="submit">Create</button>
        </form>

        <div class="row">
          <a class="btn" href="/export/invoices.csv">Export Invoices (CSV)</a>
        </div>
        """
        return shell(request, "Invoices", body)
    finally:
        conn.close()

@app.post("/invoices/create")
def invoices_create(
    request: Request,
    client_id: int = Form(...),
    invoice_number: str = Form(...),
    case_number: Optional[str] = Form(None),
    issue_date: str = Form(...),
    due_date: str = Form(...),
    global_check_in: str = Form(...),
    global_check_out: str = Form(...),
    global_rate_per_night: float = Form(...),
):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        exists = conn.execute("SELECT 1 FROM clients WHERE id = ? AND ar_id = ?", (client_id, ar_id)).fetchone()
        if not exists:
            return PlainTextResponse("Client not found in this A/R.", status_code=400)
        if not invoice_number.strip():
            return PlainTextResponse("invoice_number required.", status_code=400)
        if conn.execute("SELECT 1 FROM invoices WHERE ar_id = ? AND invoice_number = ?", (ar_id, invoice_number.strip())).fetchone():
            return PlainTextResponse("invoice_number already exists in this A/R.", status_code=400)
        nights = compute_nights(global_check_in, global_check_out)
        if nights <= 0:
            return PlainTextResponse("Check-out must be after check-in (at least 1 night).", status_code=400)
        amount = round(float(global_rate_per_night) * nights, 2)
        conn.execute(
            """INSERT INTO invoices
               (ar_id, client_id, invoice_number, issue_date, due_date, amount, status,
                check_in, check_out, nights, rate_per_night, case_number)
               VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)""",
            (ar_id, client_id, invoice_number.strip(), issue_date, due_date, amount,
             global_check_in, global_check_out, nights, float(global_rate_per_night), (case_number or None)),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url="/invoices", status_code=303)

@app.post("/invoices/{invoice_id}/void")
def invoices_void(request: Request, invoice_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        row = conn.execute("SELECT ar_id FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if not row or row["ar_id"] != ar_id:
            return PlainTextResponse("Not found.", status_code=404)
        conn.execute("UPDATE invoices SET status = 'VOID' WHERE id = ?", (invoice_id,))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url="/invoices", status_code=303)

@app.post("/invoices/{invoice_id}/update_amount")
def invoices_update_amount(request: Request, invoice_id: int, amount: float = Form(...)):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        row = conn.execute("SELECT status, ar_id FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if not row or row["ar_id"] != ar_id:
            return PlainTextResponse("Invoice not found.", status_code=404)
        if (row["status"] or "OPEN").upper() == "VOID":
            return PlainTextResponse("Cannot update a VOID invoice.", status_code=400)
        inv_amt, paid, _ = paid_and_balance(conn, invoice_id)
        if float(amount) + 1e-9 < paid:
            return PlainTextResponse(f"New amount is less than total paid ({paid:.2f}).", status_code=400)
        conn.execute("UPDATE invoices SET amount = ? WHERE id = ?", (float(amount), invoice_id))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url="/invoices", status_code=303)

# --------------------------- Invoice Detail / Audit / Print --------------------

@app.get("/invoice/{invoice_id}", response_class=HTMLResponse)
def invoice_detail(request: Request, invoice_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        inv = conn.execute(
            """SELECT i.*, c.name AS client_name, c.email AS client_email, c.company AS client_company
               FROM invoices i JOIN clients c ON c.id = i.client_id
               WHERE i.id = ? AND i.ar_id = ?""",
            (invoice_id, ar_id)
        ).fetchone()
        if not inv:
            return PlainTextResponse("Not found.", status_code=404)
        amt, paid, bal = paid_and_balance(conn, invoice_id)
        payments = conn.execute(
            "SELECT id, amount, payment_date, method, check_number, check_date FROM payments WHERE invoice_id = ? ORDER BY payment_date, id",
            (invoice_id,),
        ).fetchall()
        pay_rows = "".join(
            f"<tr><td>{p['id']}</td><td>{p['payment_date']}</td><td class='right'>{p['amount']:.2f}</td>"
            f"<td>{(p['method'] or '').upper()}</td><td>{p['check_number'] or '-'}</td><td>{p['check_date'] or '-'}</td></tr>"
            for p in payments
        ) or '<tr><td colspan="6" class="muted">(no payments)</td></tr>'

        kebab = (
            "<div class='kebab'>"
            "<button title='Options'>⋮</button>"
            "<div class='menu'>"
            f"<a href='/invoice/{invoice_id}/audit'>Audit Log</a>"
            f"<a href='/invoice/{invoice_id}/print' target='_blank'>Print</a>"
            f"<a href='/invoices/{invoice_id}/payments'>Payments</a>"
            f"<form id='void{invoice_id}' class='inline' method='post' action='/invoices/{invoice_id}/void'></form>"
            f"<button onclick=\"confirmPost('void{invoice_id}', 'Void this invoice?')\">Void</button>"
            "</div></div>"
        )

        meta = f"""
        <div class="kpi">
          <div class="card"><div class="muted">Client</div><div><b>{inv['client_name']}</b> <span class="badge">{inv['client_company'] or '—'}</span></div></div>
          <div class="card"><div class="muted">Invoice #</div><div><b>{inv['invoice_number']}</b></div></div>
          <div class="card"><div class="muted">Case #</div><div><b>{inv['case_number'] or '—'}</b></div></div>
          <div class="card"><div class="muted">Stay</div><div><b>{inv['check_in'] or '—'}</b> → <b>{inv['check_out'] or '—'}</b> ({inv['nights'] or 0} nights)</div></div>
          <div class="card"><div class="muted">Rate/night</div><div><b>{(inv['rate_per_night'] or 0):.2f}</b></div></div>
        </div>
        """

        body = f"""
        <h3>Invoice {inv['invoice_number']}</h3>
        {kebab}
        {meta}

        <table>
          <thead><tr><th>Amount</th><th>Paid</th><th>Balance</th></tr></thead>
          <tbody><tr><td class='right'>{amt:.2f}</td><td class='right'>{paid:.2f}</td><td class='right'>{bal:.2f}</td></tr></tbody>
        </table>

        <div class="row">
          <form class="inline" method="post" action="/invoices/{inv['id']}/update_amount" onsubmit="return confirm('Update amount?');">
            <input type="number" step="0.01" min="0" name="amount" placeholder="New amount" required>
            <button class="btn" type="submit">Update Amount</button>
          </form>
        </div>

        <h4>Payments</h4>
        <table>
          <thead><tr><th>ID</th><th>Date</th><th class="right">Amount</th><th>Method</th><th>Check #</th><th>Check date</th></tr></thead>
          <tbody>{pay_rows}</tbody>
        </table>
        """
        return shell(request, f"Invoice {inv['invoice_number']}", body, back="/invoices")
    finally:
        conn.close()

@app.get("/invoice/{invoice_id}/audit", response_class=HTMLResponse)
def invoice_audit(request: Request, invoice_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        inv = conn.execute(
            "SELECT invoice_number, issue_date, due_date, status FROM invoices WHERE id = ? AND ar_id = ?",
            (invoice_id, ar_id)
        ).fetchone()
        if not inv:
            return PlainTextResponse("Not found.", status_code=404)
        rows = f"""
        <table>
          <thead><tr><th>Field</th><th>Value</th></tr></thead>
          <tbody>
            <tr><td>Invoice #</td><td>{inv['invoice_number']}</td></tr>
            <tr><td>Issue date</td><td>{inv['issue_date']}</td></tr>
            <tr><td>Due date</td><td>{inv['due_date']}</td></tr>
            <tr><td>Status</td><td>{inv['status']}</td></tr>
          </tbody>
        </table>
        """
        body = f"<h3>Audit Log</h3><p>Invoice <b>{inv['invoice_number']}</b></p>{rows}"
        return shell(request, "Audit Log", body, back=f"/invoice/{invoice_id}")
    finally:
        conn.close()

@app.get("/invoice/{invoice_id}/print", response_class=HTMLResponse)
def invoice_print(request: Request, invoice_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        inv = conn.execute(
            """SELECT i.*, c.name AS client_name, c.email AS client_email, c.company AS client_company
               FROM invoices i JOIN clients c ON c.id = i.client_id WHERE i.id = ? AND i.ar_id = ?""",
            (invoice_id, ar_id)
        ).fetchone()
        if not inv: return PlainTextResponse("Not found.", status_code=404)
        amt, paid, bal = paid_and_balance(conn, invoice_id)
        payments = conn.execute(
            "SELECT payment_date, amount, method, check_number, check_date FROM payments WHERE invoice_id = ? ORDER BY payment_date, id",
            (invoice_id,),
        ).fetchall()
        payments_html = "".join(
            f"<tr><td>{p['payment_date']}</td><td style='text-align:right'>{p['amount']:.2f}</td>"
            f"<td>{(p['method'] or '').upper()}</td><td>{p['check_number'] or '-'}</td><td>{p['check_date'] or '-'}</td></tr>"
            for p in payments
        ) or "<tr><td colspan='5'>(no payments)</td></tr>"
        # Escape braces in CSS within f-string
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Invoice {inv['invoice_number']}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 32px; color:#111; }}
  h2,h3 {{ margin: 0 0 6px 0; }}
  .muted {{ color:#666; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; }}
  .totals td {{ text-align:right; }}
  .header {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px; }}
  .print {{ margin: 16px 0; }}
  @media print {{ .print {{ display:none; }} @page {{ margin: 18mm; }} }}
</style></head>
<body>
<div class="header">
  <div>
    <h2>Invoice</h2>
    <div class="muted">Invoice # {inv['invoice_number']}<br>ID {inv['id']}</div>
  </div>
  <div>
    <div><b>Client</b>: {inv['client_name']} <span>({inv['client_company'] or '—'})</span></div>
    <div class="muted">{inv['client_email'] or ''}</div>
    <div><b>Issue</b>: {inv['issue_date']} &nbsp; <b>Due</b>: {inv['due_date']}</div>
    <div><b>Status</b>: {inv['status']}</div>
    <div><b>Stay</b>: {inv['check_in'] or '—'} → {inv['check_out'] or '—'} ({inv['nights'] or 0} nights @ {(inv['rate_per_night'] or 0):.2f})</div>
    <div><b>Case #</b>: {inv['case_number'] or '—'}</div>
  </div>
</div>

<table>
  <thead><tr><th>Description</th><th style="width:180px">Amount</th></tr></thead>
  <tbody><tr><td>Lodging ({inv['nights'] or 0} × {(inv['rate_per_night'] or 0):.2f})</td><td style="text-align:right">{amt:.2f}</td></tr></tbody>
</table>

<table class="totals">
  <tbody>
    <tr><td><b>Paid</b></td><td style="width:180px">{paid:.2f}</td></tr>
    <tr><td><b>Balance</b></td><td>{bal:.2f}</td></tr>
  </tbody>
</table>

<h3>Payments</h3>
<table>
  <thead><tr><th>Date</th><th style="width:180px">Amount</th><th>Method</th><th>Check #</th><th>Check date</th></tr></thead>
  <tbody>{payments_html}</tbody>
</table>

<div class="print">
  <button onclick="window.print()" style="padding:8px 12px;">Print / Save as PDF</button>
</div>
</body></html>"""
        return HTMLResponse(html)
    finally:
        conn.close()

# --------------------------- Payments ------------------------------------------

@app.get("/payments", response_class=HTMLResponse)
def payments_root(request: Request):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    body = """
      <h3>Manage Payments</h3>
      <p>Open any invoice, then click <b>Payments</b> in the ⋮ menu, or use <a class="btn" href="/search">Search</a>.</p>
      <div class="row">
        <a class="btn primary" href="/invoices">Go to Invoices</a>
        <a class="btn" href="/search">Search</a>
      </div>
    """
    return shell(request, "Manage Payments", body, back="/")

@app.get("/invoices/{invoice_id}/payments", response_class=HTMLResponse)
def payments_for_invoice(request: Request, invoice_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        inv = conn.execute(
            """SELECT i.*, c.name AS client_name FROM invoices i JOIN clients c ON c.id = i.client_id
               WHERE i.id = ? AND i.ar_id = ?""",
            (invoice_id, ar_id)
        ).fetchone()
        if not inv: return PlainTextResponse("Not found.", status_code=404)
        payments = conn.execute(
            "SELECT id, amount, payment_date, method, check_number, check_date FROM payments WHERE invoice_id = ? ORDER BY payment_date, id",
            (invoice_id,),
        ).fetchall()
        pay_rows = "".join(
            f"""
            <tr>
              <td>{p['id']}</td>
              <td class="right">{p['amount']:.2f}</td>
              <td>{p['payment_date']}</td>
              <td>{(p['method'] or '').upper()}</td>
              <td>{p['check_number'] or '-'}</td>
              <td>{p['check_date'] or '-'}</td>
              <td>
                <div class="kebab">
                  <button title="Options">⋮</button>
                  <div class="menu">
                    <form class="inline" method="post" action="/payments/{p['id']}/update">
                      <div style="padding:8px">
                        <select name="method" required>
                          <option value="cash" {"selected" if (p['method'] or "cash")=="cash" else ""}>cash</option>
                          <option value="check" {"selected" if (p['method'] or "")=="check" else ""}>check</option>
                        </select>
                        <input type="number" step="0.01" min="0.01" name="amount" value="{p['amount']:.2f}" required>
                        <input type="date" name="payment_date" value="{p['payment_date']}" required>
                        <input name="check_number" placeholder="Check #" value="{p['check_number'] or ''}">
                        <input type="date" name="check_date" value="{p['check_date'] or ''}">
                        <button class="btn" type="submit">Save</button>
                      </div>
                    </form>
                    <form id="del{p['id']}" class="inline" method="post" action="/payments/{p['id']}/delete"></form>
                    <button onclick="confirmPost('del{p['id']}', 'Delete payment?')">Delete</button>
                  </div>
                </div>
              </td>
            </tr>
            """
            for p in payments
        ) or '<tr><td colspan="7" class="muted">(no payments)</td></tr>'

        amt, paid, bal = paid_and_balance(conn, invoice_id)
        disabled = "disabled" if (inv["status"] or "OPEN").upper() == "VOID" else ""
        info = f"""
        <p><b>Invoice:</b> {inv['invoice_number']} (ID {inv['id']}) | <b>Client:</b> {inv['client_name']} |
           <b>Status:</b> {inv['status']} | <b>Amount:</b> {amt:.2f} | <b>Paid:</b> {paid:.2f} | <b>Balance:</b> {bal:.2f}</p>
        """
        form = f"""
        <h4>Add Payment</h4>
        <form method="post" action="/payments/add">
          <input type="hidden" name="invoice_id" value="{invoice_id}">
          <div class="row">
            <label>Method
              <select name="method" required {"disabled" if disabled else ""}>
                <option value="cash">cash</option>
                <option value="check">check</option>
              </select>
            </label>
            <label>Amount <input type="number" step="0.01" min="0.01" name="amount" required {disabled}></label>
            <label>Date <input type="date" name="payment_date" required {disabled}></label>
            <label>Check # <input name="check_number" placeholder="Check #" {disabled}></label>
            <label>Check date <input type="date" name="check_date" {disabled}></label>
          </div>
          <div class="small">If method = <b>check</b>, fill Check # and Check date.</div>
          <button class="btn primary" type="submit" {disabled}>Add Payment</button>
          {"<p class='muted'>Payments disabled for VOID invoices.</p>" if disabled else ""}
        </form>
        """
        body = f"""
        <h3>Payments</h3>
        {info}
        <table>
          <thead><tr><th>ID</th><th class="right">Amount</th><th>Date</th><th>Method</th><th>Check #</th><th>Check date</th><th>Actions</th></tr></thead>
          <tbody>{pay_rows}</tbody>
        </table>
        {form}
        <div class="row"><a class="btn" href="/export/payments.csv">Export Payments (CSV)</a></div>
        """
        return shell(request, "Payments", body, back="/invoices")
    finally:
        conn.close()

@app.post("/payments/add")
def payments_add(
    request: Request,
    invoice_id: int = Form(...),
    method: str = Form(...),
    amount: float = Form(...),
    payment_date: str = Form(...),
    check_number: Optional[str] = Form(None),
    check_date: Optional[str] = Form(None),
):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    method = (method or "").strip().lower()
    if method not in ("cash", "check"):
        return PlainTextResponse("Method must be 'cash' or 'check'.", status_code=400)
    if method == "check" and (not check_number or not check_date):
        return PlainTextResponse("Check number and check date are required for method 'check'.", status_code=400)
    conn = connect()
    try:
        inv = conn.execute("SELECT ar_id, status FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if not inv or inv["ar_id"] != ar_id:
            return PlainTextResponse("Invoice not found.", status_code=404)
        if (inv["status"] or "OPEN").upper() == "VOID":
            return PlainTextResponse("Cannot record payment on a VOID invoice.", status_code=400)
        _, paid, bal = paid_and_balance(conn, invoice_id)
        if float(amount) <= 0:
            return PlainTextResponse("Payment amount must be > 0.", status_code=400)
        if bal <= 0:
            return PlainTextResponse("Invoice already fully paid.", status_code=400)
        if float(amount) > bal + 1e-9:
            return PlainTextResponse(f"Payment exceeds remaining balance ({bal:.2f}).", status_code=400)
        conn.execute(
            "INSERT INTO payments (invoice_id, amount, payment_date, method, check_number, check_date) VALUES (?, ?, ?, ?, ?, ?)",
            (invoice_id, float(amount), payment_date, method, check_number, check_date),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url=f"/invoices/{invoice_id}/payments", status_code=303)

@app.post("/payments/{payment_id}/delete")
def payments_delete(request: Request, payment_id: int):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        row = conn.execute("""
            SELECT p.invoice_id, i.ar_id, i.status
            FROM payments p JOIN invoices i ON i.id = p.invoice_id
            WHERE p.id = ?
        """, (payment_id,)).fetchone()
        if not row or row["ar_id"] != ar_id:
            return PlainTextResponse("Payment not found.", status_code=404)
        if (row["status"] or "OPEN").upper() == "VOID":
            return PlainTextResponse("Cannot delete payment from a VOID invoice.", status_code=400)
        conn.execute("DELETE FROM payments WHERE id = ?", (payment_id,))
        conn.commit()
        invoice_id = int(row["invoice_id"])
    finally:
        conn.close()
    return RedirectResponse(url=f"/invoices/{invoice_id}/payments", status_code=303)

@app.post("/payments/{payment_id}/update")
def payments_update(
    request: Request,
    payment_id: int,
    method: str = Form(...),
    amount: float = Form(...),
    payment_date: str = Form(...),
    check_number: Optional[str] = Form(None),
    check_date: Optional[str] = Form(None),
):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    method = (method or "").strip().lower()
    if method not in ("cash", "check"):
        return PlainTextResponse("Method must be 'cash' or 'check'.", status_code=400)
    if method == "check" and (not check_number or not check_date):
        return PlainTextResponse("Check number and check date are required for method 'check'.", status_code=400)
    conn = connect()
    try:
        row = conn.execute("""
            SELECT p.invoice_id, i.ar_id, i.amount AS inv_amount, i.status
            FROM payments p JOIN invoices i ON i.id = p.invoice_id
            WHERE p.id = ?
        """, (payment_id,)).fetchone()
        if not row or row["ar_id"] != ar_id:
            return PlainTextResponse("Payment not found.", status_code=404)
        if amount <= 0:
            return PlainTextResponse("Amount must be > 0.", status_code=400)
        if (row["status"] or "OPEN").upper() == "VOID":
            return PlainTextResponse("Cannot update payment on a VOID invoice.", status_code=400)
        invoice_id = int(row["invoice_id"])
        inv_amt = float(row["inv_amount"])
        others_sum = float(
            conn.execute("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE invoice_id = ? AND id != ?", (invoice_id, payment_id)
        ).fetchone()["s"])
        if others_sum + float(amount) > inv_amt + 1e-9:
            return PlainTextResponse(f"New payment would exceed invoice amount. Max allowed is {(inv_amt - others_sum):.2f}.", status_code=400)
        conn.execute(
            "UPDATE payments SET amount = ?, payment_date = ?, method = ?, check_number = ?, check_date = ? WHERE id = ?",
            (float(amount), payment_date, method, check_number, check_date, payment_id),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url=f"/invoices/{invoice_id}/payments", status_code=303)

# --------------------------- Client Page (per-client list) ---------------------

@app.get("/client/{client_id}", response_class=HTMLResponse)
def client_page(request: Request, client_id: int, outstanding: bool = Query(False)):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        client = conn.execute("SELECT * FROM clients WHERE id = ? AND ar_id = ?", (client_id, ar_id)).fetchone()
        if not client:
            return PlainTextResponse("Client not found in this A/R.", status_code=404)
        rows = conn.execute(
            """
            SELECT
                i.id, i.invoice_number, i.amount, i.status,
                COALESCE(SUM(p.amount),0) AS paid,
                (i.amount - COALESCE(SUM(p.amount),0)) AS balance
            FROM invoices i
            LEFT JOIN payments p ON p.invoice_id = i.id
            WHERE i.client_id = ?
            GROUP BY i.id
            ORDER BY i.id
            """,
            (client_id,),
        ).fetchall()
        if outstanding:
            rows = [r for r in rows if r["balance"] > 0]
        total_amount = sum(float(r["amount"]) for r in rows) if rows else 0.0
        total_paid = sum(float(r["paid"]) for r in rows) if rows else 0.0
        total_balance = sum(float(r["balance"]) for r in rows) if rows else 0.0

        trs = []
        for r in rows:
            inv_no = r["invoice_number"] or "(none)"
            kebab = (
                "<div class='kebab'>"
                "<button title='Options'>⋮</button>"
                "<div class='menu'>"
                f"<a href='/invoice/{r['id']}'>Open</a>"
                f"<a href='/invoice/{r['id']}/print' target='_blank'>Print</a>"
                f"<a href='/invoice/{r['id']}/audit'>Audit Log</a>"
                f"<a href='/invoices/{r['id']}/payments'>Payments</a>"
                f"<form id='void{r['id']}' class='inline' method='post' action='/invoices/{r['id']}/void'></form>"
                f"<button onclick=\"confirmPost('void{r['id']}', 'Void this invoice?')\">Void</button>"
                "</div></div>"
            )
            upd = (
                f"<form class='inline' method='post' action='/invoices/{r['id']}/update_amount' "
                "onsubmit=\"return confirm('Update amount?');\">"
                "<input type='number' step='0.01' min='0' name='amount' placeholder='New amount' required>"
                "<button class='btn' type='submit'>Update</button>"
                "</form>"
            )
            trs.append(
                f"<tr><td>{inv_no}</td><td class='right'>{r['amount']:.2f}</td><td class='right'>{r['paid']:.2f}</td><td class='right'>{r['balance']:.2f}</td><td>{kebab} {upd}</td></tr>"
            )
        table = "".join(trs) or '<tr><td colspan="5" class="muted">(no invoices)</td></tr>'

        body = f"""
        <h3>Client: {client['name']} <span class="badge">{client['company'] or '—'}</span></h3>
        <div class="muted">{client['email'] or ''}</div>

        <div class="kpi">
          <div class="card"><div class="muted">Total Amount</div><div><b>{total_amount:.2f}</b></div></div>
          <div class="card"><div class="muted">Total Paid</div><div><b>{total_paid:.2f}</b></div></div>
          <div class="card"><div class="muted">Total Balance</div><div><b>{total_balance:.2f}</b></div></div>
        </div>

        <form method="get" action="/client/{client_id}">
          <label><input type="checkbox" name="outstanding" {"checked" if outstanding else ""}> Outstanding only</label>
          <button class="btn" type="submit">Apply</button>
        </form>

        <table>
          <thead><tr>
            <th>Invoice #</th><th class="right">Amount</th><th class="right">Paid</th><th class="right">Balance</th><th>Actions</th>
          </tr></thead>
          <tbody>{table}</tbody>
        </table>

        <h4>New Invoice for {client['name']}</h4>
        <form method="post" action="/client/{client_id}/invoices/create" oninput="previewInvoice('client_')">
          <div class="row">
            <label>Invoice # <input name="invoice_number" required></label>
            <label>Case # <input name="case_number" placeholder="Case #"></label>
            <label>Issue Date <input type="date" name="issue_date" required></label>
            <label>Due Date <input type="date" name="due_date" required></label>
          </div>
          <div class="row">
            <label>Check-in <input type="date" name="client_check_in" required></label>
            <label>Check-out <input type="date" name="client_check_out" required></label>
            <label>Rate/night <input type="number" step="0.01" min="0" name="client_rate_per_night" required></label>
          </div>
          <div id="client_preview" class="small">Preview: —</div>
          <div class="small">Amount will be auto-calculated (nights × rate/night).</div>
          <button class="btn primary" type="submit">Create Invoice</button>
        </form>
        """
        return shell(request, f"Client {client['name']}", body, back="/clients")
    finally:
        conn.close()

@app.post("/client/{client_id}/invoices/create")
def client_create_invoice(
    request: Request,
    client_id: int,
    invoice_number: str = Form(...),
    case_number: Optional[str] = Form(None),
    issue_date: str = Form(...),
    due_date: str = Form(...),
    client_check_in: str = Form(...),
    client_check_out: str = Form(...),
    client_rate_per_night: float = Form(...),
):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        row = conn.execute("SELECT 1 FROM clients WHERE id = ? AND ar_id = ?", (client_id, ar_id)).fetchone()
        if not row:
            return PlainTextResponse("Client not found in this A/R.", status_code=404)
        if not invoice_number.strip():
            return PlainTextResponse("invoice_number required.", status_code=400)
        if conn.execute("SELECT 1 FROM invoices WHERE ar_id = ? AND invoice_number = ?", (ar_id, invoice_number.strip())).fetchone():
            return PlainTextResponse("invoice_number already exists in this A/R.", status_code=400)
        nights = compute_nights(client_check_in, client_check_out)
        if nights <= 0:
            return PlainTextResponse("Check-out must be after check-in (at least 1 night).", status_code=400)
        amount = round(float(client_rate_per_night) * nights, 2)
        conn.execute(
            "INSERT INTO invoices (ar_id, client_id, invoice_number, issue_date, due_date, amount, status, check_in, check_out, nights, rate_per_night, case_number) VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)",
            (ar_id, client_id, invoice_number.strip(), issue_date, due_date, amount, client_check_in, client_check_out, nights, float(client_rate_per_night), (case_number or None)),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url=f"/client/{client_id}", status_code=303)

# --------------------------- Search (no group-by) -------------------------------

@app.get("/search", response_class=HTMLResponse)
def search(
    request: Request,
    q: Optional[str] = Query(None),
    company: Optional[str] = Query(None),
    year: Optional[str] = Query(None),
    month: Optional[str] = Query(None),
):
    """q matches invoice_number or client; filters by company and stay overlap with year/month."""
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    year_i = parse_opt_int(year)
    month_i = parse_opt_int(month)
    conn = connect()
    try:
        q_clean = (q or "").strip()

        # Fast path: exact invoice number
        if q_clean:
            inv = conn.execute("SELECT id FROM invoices WHERE ar_id = ? AND invoice_number = ?", (ar_id, q_clean)).fetchone()
            if inv:
                return RedirectResponse(url=f"/invoice/{inv['id']}", status_code=303)

        where = ["i.ar_id = ?"]
        params: list = [ar_id]

        if q_clean:
            where.append("(i.invoice_number LIKE ? OR c.name LIKE ?)")
            like = f"%{q_clean}%"
            params.extend([like, like])

        if company:
            where.append("c.company = ?")
            params.append(company.strip())

        if year_i and month_i:
            start, end = month_range(year_i, month_i)
            where.append(overlap_sql())
            params.extend([end, start])
        elif year_i:
            start, end = year_range(year_i)
            where.append(overlap_sql())
            params.extend([end, start])

        where_sql = " WHERE " + " AND ".join(where)

        rows = conn.execute(
            f"""
            SELECT i.id, i.invoice_number, i.amount, i.issue_date, i.due_date, i.status,
                   i.check_in, i.check_out, i.nights, i.rate_per_night, i.case_number,
                   c.name AS client, c.company AS company,
                   COALESCE(SUM(p.amount),0) AS paid, (i.amount-COALESCE(SUM(p.amount),0)) AS balance
            FROM invoices i
            JOIN clients c ON c.id = i.client_id
            LEFT JOIN payments p ON p.invoice_id = i.id
            {where_sql}
            GROUP BY i.id
            ORDER BY i.id
            """,
            params,
        ).fetchall()

        trs = []
        for r in rows:
            trs.append(
                f"<tr><td>{r['invoice_number']}</td><td>{r['client']}</td><td>{r['company'] or '—'}</td>"
                f"<td class='right'>{r['amount']:.2f}</td><td class='right'>{r['paid']:.2f}</td><td class='right'>{r['balance']:.2f}</td>"
                f"<td><a class='btn' href='/invoice/{r['id']}'>Open</a></td></tr>"
            )
        table = (
            f"<table><thead><tr><th>Invoice #</th><th>Client</th><th>Company</th><th class='right'>Amount</th><th class='right'>Paid</th><th class='right'>Balance</th><th>Actions</th></tr></thead><tbody>"
            f"{''.join(trs) or '<tr><td colspan=\"7\" class=\"muted\">(no results)</td></tr>'}</tbody></table>"
        )

        companies = get_companies(conn, ar_id)
        company_opts = "".join(f'<option value="{co}" {"selected" if company==co else ""}>{co}</option>' for co in companies)
        years_rows = conn.execute(
            "SELECT DISTINCT substr(COALESCE(check_in, issue_date),1,4) y FROM invoices WHERE ar_id = ? AND substr(COALESCE(check_in, issue_date),1,4) IS NOT NULL ORDER BY y DESC",
            (ar_id,)
        ).fetchall()
        year_vals = [int(str(r["y"])) for r in years_rows if r["y"] and str(r["y"]).isdigit()]
        year_opts = "".join(f'<option value="{y}" {"selected" if year_i==y else ""}>{y}</option>' for y in year_vals)
        month_opts = "".join(f'<option value="{m}" {"selected" if month_i==m else ""}>{m:02d}</option>' for m in range(1,13))

        body = f"""
        <h3>Search</h3>
        <form method="get" action="/search">
          <div class="row">
            <input type="text" name="q" class="search" placeholder="Invoice # or Client name" value="{q_clean}">
            <label> Company:
              <select name="company"><option value="">(all)</option>{company_opts}</select>
            </label>
            <label> Year:
              <select name="year"><option value="">(any)</option>{year_opts}</select>
            </label>
            <label> Month:
              <select name="month"><option value="">(any)</option>{month_opts}</select>
            </label>
            <button class="btn" type="submit">Search</button>
          </div>
          <div class="small">Filters use stay overlap (check-in/check-out) with the selected month/year.</div>
        </form>
        {table}
        """
        return shell(request, "Search", body, back="/")
    finally:
        conn.close()

# --------------------------- CSV Export (scoped) --------------------------------

def _csv_stream(headers: list[str], rows: Iterable[Iterable]):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for r in rows:
        writer.writerow(r)
    buffer.seek(0)
    return buffer

@app.get("/export/invoices.csv")
def export_invoices_csv(request: Request):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT i.id, i.invoice_number, c.name AS client, c.company, i.issue_date, i.due_date, i.status,
                   i.check_in, i.check_out, i.nights, i.rate_per_night, i.case_number, i.amount,
                   COALESCE(SUM(p.amount),0) AS paid, (i.amount - COALESCE(SUM(p.amount),0)) AS balance
            FROM invoices i
            JOIN clients c ON c.id = i.client_id
            LEFT JOIN payments p ON p.invoice_id = i.id
            WHERE i.ar_id = ?
            GROUP BY i.id
            ORDER BY i.id
            """, (ar_id,)
        ).fetchall()
        buf = _csv_stream(
            ["id", "invoice_number", "client", "company", "issue_date", "due_date", "status", "check_in", "check_out", "nights", "rate_per_night", "case_number", "amount", "paid", "balance"],
            ([r["id"], r["invoice_number"], r["client"], r["company"] or "", r["issue_date"], r["due_date"], r["status"],
              r["check_in"] or "", r["check_out"] or "", r["nights"] or 0, f"{(r['rate_per_night'] or 0):.2f}", r["case_number"] or "",
              f"{r['amount']:.2f}", f"{r['paid']:.2f}", f"{r['balance']:.2f}"] for r in rows),
        )
    finally:
        conn.close()
    return StreamingResponse(buf, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=invoices.csv"})

@app.get("/export/payments.csv")
def export_payments_csv(request: Request):
    init_db()
    res = ensure_scope(request)
    if isinstance(res, RedirectResponse):
        return res
    _, ar_id = res
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT p.id, i.invoice_number, c.name AS client, c.company, p.amount, p.payment_date, p.method, p.check_number, p.check_date
            FROM payments p
            JOIN invoices i ON i.id = p.invoice_id
            JOIN clients c ON c.id = i.client_id
            WHERE i.ar_id = ?
            ORDER BY p.payment_date, p.id
            """, (ar_id,)
        ).fetchall()
        buf = _csv_stream(
            ["payment_id", "invoice_number", "client", "company", "amount", "payment_date", "method", "check_number", "check_date"],
            ([r["id"], r["invoice_number"], r["client"], r["company"] or "", f"{r['amount']:.2f}", r["payment_date"], r["method"] or "", r["check_number"] or "", r["check_date"] or ""] for r in rows),
        )
    finally:
        conn.close()
    return StreamingResponse(buf, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=payments.csv"})

# --------------------------- Run ------------------------------------------------

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8000)
