"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import logging
import os
import sqlite3
import subprocess
import secrets
import ast
import operator
import html

import requests
import uvicorn
import yaml
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Secret used to sign session cookies: read from the environment, never hardcoded.
# No default value on purpose: the app refuses to start rather than run with a known key.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("The SECRET_KEY environment variable must be set")
# "production" by default (fail secure): dev-only features must be explicitly enabled
APP_ENV = os.environ.get("APP_ENV", "production")
IS_DEV = APP_ENV == "development"
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
# SSRF protection: the server may only fetch these hosts (allowlist, not denylist)
ALLOWED_FETCH_HOSTS = {"example.com", "www.python.org"}

# INFO in production: DEBUG logs are verbose and may expose internal details
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("minishop")

# debug=False: no stack traces sent to clients.
# Swagger UI and the OpenAPI schema map the whole API: only exposed in development.
app = FastAPI(
    title="MiniShop",
    debug=False,
    docs_url="/docs" if IS_DEV else None,
    redoc_url="/redoc" if IS_DEV else None,
    openapi_url="/openapi.json" if IS_DEV else None,
)

# Session cookie: signed with SECRET_KEY, sent over HTTPS only (Secure), not readable by
# JavaScript (HttpOnly, default), not sent on cross-site POST requests (SameSite=Lax),
# and expiring after 1 hour instead of 14 days
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax",
    max_age=3600,
)

# Security headers sent with every response (defense in depth on the browser side)
SECURITY_HEADERS = {
    # The API only returns JSON and plain HTML: no script, style or frame is ever allowed
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    # Do not guess the content type: trust the Content-Type header
    "X-Content-Type-Options": "nosniff",
    # HTTPS only for one year (ignored by browsers over plain HTTP)
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Never display the site inside a frame (clickjacking)
    "X-Frame-Options": "DENY",
    # Do not leak our URLs to other sites
    "Referrer-Policy": "no-referrer",
}

# Swagger UI loads scripts from a CDN: the strict CSP would break it.
# These pages are disabled in production anyway.
_DOCS_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        if name == "Content-Security-Policy" and request.url.path in _DOCS_PATHS:
            continue
        response.headers[name] = value
    return response

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def current_user(request: Request) -> dict:
    """Return the logged-in user, or stop the request with a 401.

    Used as Depends(current_user): authentication is checked in one single place
    instead of being copy-pasted (and possibly forgotten) in every endpoint.
    """
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="login required")
    # Reload the user from the database: a deleted account must lose access immediately
    row = db().execute(
        "SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        request.session.clear()
        raise HTTPException(status_code=401, detail="login required")
    return dict(row)

# Role-based access control: every permission of every role is defined here, and only here.
# Deny by default: any permission that is not explicitly listed is refused.
ROLE_PERMISSIONS = {
    "admin": {"user:list", "user:delete"},
    "user": set(),
}


def require(permission: str):
    """Build a dependency that only lets through users whose role grants `permission`."""

    def checker(user: dict = Depends(current_user)) -> dict:
        role = "admin" if user["is_admin"] else "user"
        # .get(role, set()): an unknown role gets no permission at all
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    return checker

# Argon2id (the library default): slow, memory-hard and salted, designed for password storage
ph = PasswordHasher()

# Hash of a random value, used to spend the same time when the username does not exist
_DUMMY_HASH = ph.hash("dummy-password-for-timing")

def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    # Full details (stack trace) go to the server logs only, never to the client.
    # The random error_id lets a user report the error and a developer find it in the logs.
    error_id = secrets.token_hex(8)
    log.error(
        "unhandled error id=%s on %s %s",
        error_id, request.method, request.url.path,
        exc_info=exc,
    )
    return JSONResponse(
        {"error": "internal server error", "error_id": error_id},
        status_code=500,
    )

@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic v2 echoes the rejected value ("input") in its error details:
    # never reflect user input back. Only the field location and the reason are returned.
    errors = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", "")} for e in exc.errors()]
    return JSONResponse({"error": "invalid request", "details": errors}, status_code=422)

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]

    # Never log secrets. %r escapes newlines, so a crafted username cannot forge fake log lines.
    log.info("login attempt user=%r", username)

    # Fetch the user by name only: an argon2 hash is salted, so it cannot be compared in SQL
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    try:
        # Verify against a dummy hash when the user does not exist, so the response time
        # does not reveal which usernames exist
        ph.verify(row["password"] if row else _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    if not row:
        return JSONResponse({"error": "bad credentials"}, status_code=401)

    # Start a fresh session at login (prevents session fixation)
    request.session.clear()
    request.session["user_id"] = row["id"]
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    # Parameterized query: the % wildcards are added to the value, not to the SQL string
    rows = db().execute(
        "SELECT id, name, price FROM products WHERE name LIKE ?",
        (f"%{q}%",),
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/ping")
def ping(host: IPvAnyAddress = "127.0.0.1"):
    # host is validated by pydantic: anything that is not an IPv4/IPv6 address gets a 422
    try:
        # No shell: arguments are passed as a list, so ; | & $() are never interpreted
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", str(host)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "ping timed out"}, status_code=504)
    return PlainTextResponse(out.stdout + out.stderr)

@app.get("/hello")
def hello(name: str = ""):
    # Escape HTML special characters (< > & " ') so the input is displayed as text, never run as code
    return HTMLResponse(f"<h1>Bonjour {html.escape(name)}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    base = Path(UPLOAD_DIR).resolve()
    # resolve() computes the real absolute path: "..", absolute paths and symlinks are all resolved
    target = (base / name).resolve()
    # The real path must stay inside uploads/, and must be an existing regular file
    if not target.is_relative_to(base) or not target.is_file():
        return JSONResponse({"error": "file not found"}, status_code=404)
    return FileResponse(target)

# Whitelist of allowed arithmetic operators. ** is excluded on purpose (9**9**9 = DoS).
_CALC_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(expr: str):
    """Evaluate a pure arithmetic expression. Anything else raises ValueError."""

    def _eval(node):
        # Numbers only (bool is excluded: True is an int subclass)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        # Binary operation: 2 + 3
        if isinstance(node, ast.BinOp) and type(node.op) in _CALC_OPERATORS:
            return _CALC_OPERATORS[type(node.op)](_eval(node.left), _eval(node.right))
        # Unary operation: -5
        if isinstance(node, ast.UnaryOp) and type(node.op) in _CALC_OPERATORS:
            return _CALC_OPERATORS[type(node.op)](_eval(node.operand))
        # Function calls, names, attributes, strings... are all rejected
        raise ValueError("forbidden expression")

    # Parse only (nothing is executed), then walk the tree ourselves
    return _eval(ast.parse(expr, mode="eval").body)

@app.post("/calc")
def calc(data: dict = Body(...)):
    expr = data.get("expr")
    # Reject non-string or overly long input before parsing it
    if not isinstance(expr, str) or len(expr) > 100:
        return JSONResponse({"error": "invalid expression"}, status_code=400)
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError):
        return JSONResponse({"error": "invalid expression"}, status_code=400)
    return {"result": str(result)}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        # safe_load only builds plain data (dict, list, str, int...): no Python objects
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        return JSONResponse({"error": "invalid YAML"}, status_code=400)
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


class Profile(BaseModel):
    """Expected shape of an imported profile: plain data only, strictly validated."""

    username: str = Field(..., min_length=1, max_length=50)
    email: str | None = Field(None, max_length=254)
    bio: str = Field("", max_length=500)

    model_config = ConfigDict(extra="forbid")  # unknown fields are rejected


@app.post("/import-profile")
def import_profile(profile: Profile):
    # The body is parsed as JSON and validated by pydantic: invalid input gets a 422.
    # Unlike pickle, JSON can only describe data, it can never trigger code execution.
    return {"profile": profile}


@app.get("/fetch")
def fetch(url: str):
    parsed = urlparse(url)
    # HTTPS only, default port only, and the host must be explicitly allowed.
    # parsed.hostname is the real host: "https://example.com@127.0.0.1" gives "127.0.0.1"
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_FETCH_HOSTS
        or parsed.port not in (None, 443)
    ):
        return JSONResponse({"error": "URL not allowed"}, status_code=400)
    try:
        r = requests.get(
            url,
            timeout=5,              # never hang the server
            verify=True,            # check the TLS certificate (prevents MITM)
            allow_redirects=False,  # a redirect could point to an internal address
        )
    except requests.RequestException:
        return JSONResponse({"error": "upstream request failed"}, status_code=502)
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    # Ownership is checked in the query itself: another user's invoice is simply not found.
    # 404 (not 403) so an attacker cannot tell "exists but not yours" from "does not exist".
    row = db().execute(
        "SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, user["id"]),
    ).fetchone()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return dict(row)

@app.get("/admin/users")
def admin_users(user: dict = Depends(require("user:list"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(require("user:delete"))):
    # An admin cannot delete their own account: avoids locking everyone out of the admin area
    if user_id == user["id"]:
        return JSONResponse({"error": "cannot delete your own account"}, status_code=400)
    conn = db()
    cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    if cursor.rowcount == 0:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    # Local run only: listen on localhost, no auto-reload.
    # In the container, the Dockerfile starts uvicorn on 0.0.0.0 itself.
    uvicorn.run("app:app", host="127.0.0.1", port=5000)