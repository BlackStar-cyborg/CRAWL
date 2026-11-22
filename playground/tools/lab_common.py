"""Shared helpers for the playground tools: token salting, the token registry, time stamps.

Standard library only, so every tool also runs inside the lab containers, which have no
internet access and therefore cannot pip-install anything.
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone

STATE_DIR = os.environ.get("CRAWL_STATE_DIR", "/state")
TOKEN_LEN = 10
TOKEN_RE = re.compile(r"[0-9a-f]{%d}" % TOKEN_LEN)

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token        TEXT PRIMARY KEY,   -- salted, unguessable ID that appears in the URL
    node         TEXT NOT NULL,      -- which (simulated) node the token was planted on
    deployment   TEXT NOT NULL,      -- deployment window, e.g. pg-2026-11-22
    placement    TEXT NOT NULL,      -- hidden_link, visible_link, robots_disallow, pdf_body_text, ...
    depth        INTEGER NOT NULL,   -- clicks from the start page needed to find the token
    doc_type     TEXT NOT NULL,      -- html, robots, pdf
    location     TEXT NOT NULL,      -- path of the page/file that carries the token (where it can be harvested)
    url_path     TEXT NOT NULL,      -- path a client requests when it resolves the token
    created_utc  TEXT NOT NULL,
    retired_utc  TEXT                -- set when a newer deployment replaces this one
);
"""


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(s):
    """Parse '2026-11-22T10:00:00.123Z' or '+00:00' forms into an aware datetime (UTC)."""
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_secret(state_dir=STATE_DIR):
    """The salt for all tokens. Created once, kept in state/ (git-ignored), never printed."""
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, "token_secret.key")
    env = os.environ.get("CRAWL_TOKEN_SECRET")
    if env:
        return env.encode()
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path) as f:
        return f.read().strip().encode()


def make_token(secret, *fields):
    """HMAC over the placement details: unique per placement, unguessable without the secret."""
    msg = "|".join(str(f) for f in fields).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:TOKEN_LEN]


def open_registry(state_dir=STATE_DIR):
    os.makedirs(state_dir, exist_ok=True)
    con = sqlite3.connect(os.path.join(state_dir, "registry.sqlite"))
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con
