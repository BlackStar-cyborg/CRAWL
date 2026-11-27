"""Shared helpers for the CRAWL node tools: token salting, the token registry, time stamps.

Based on playground/tools/lab_common.py. Differences for the real deployment:
  * tokens are 16 hex characters (64 bits) instead of 10 (40 bits)
  * the registry records when a token went live (exposed_utc), so time-to-first-resolution
    is measured from deployment, not from when the site was built
  * control tokens: "negative" (registered, never published) and "positive" (resolved by us)
  * a deployments table and a pre-registration hash

Standard library only (Python 3.8+).
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone

TOKEN_LEN = 16
# A token is a run of exactly TOKEN_LEN hex characters that is not part of a longer hex run.
TOKEN_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{%d}(?![0-9a-fA-F])" % TOKEN_LEN)
# Any hex run of 8+ characters: candidates for near-misses (truncated / extended tokens).
HEX_RUN_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{8,}(?![0-9a-fA-F])")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token        TEXT PRIMARY KEY,   -- salted, unguessable ID that appears in the URL
    node         TEXT NOT NULL,      -- node the token belongs to
    deployment   TEXT NOT NULL,      -- deployment window, e.g. n01-2026-12
    placement    TEXT NOT NULL,      -- hidden_link, visible_link, robots_disallow, pdf_body_text, ...
    depth        INTEGER NOT NULL,   -- clicks from the start page needed to find the token
    doc_type     TEXT NOT NULL,      -- html, robots, pdf, none (controls)
    location     TEXT NOT NULL,      -- carrier: path of the page/file that contains the token
    url_path     TEXT NOT NULL,      -- path a client requests when it resolves the token
    control      TEXT,               -- NULL, 'negative' or 'positive'
    created_utc  TEXT NOT NULL,      -- when the token was generated (site build)
    exposed_utc  TEXT,               -- when the site with this token was deployed (go-live)
    retired_utc  TEXT                -- when a newer deployment replaced this one
);
CREATE TABLE IF NOT EXISTS preregistrations (
    node         TEXT NOT NULL,
    deployment   TEXT NOT NULL,
    sha256       TEXT NOT NULL,      -- hash over the deployment's token list (see registry_hash)
    n_tokens     INTEGER NOT NULL,
    recorded_utc TEXT NOT NULL
);
"""


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(s):
    """Parse '2026-11-22T10:00:00.123Z' or '+00:00' forms into an aware datetime (UTC)."""
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_secret(state_dir):
    """The salt for all tokens. Created once, kept in the state folder (git-ignored), never printed."""
    os.makedirs(state_dir, exist_ok=True)
    env = os.environ.get("CRAWL_TOKEN_SECRET")
    if env:
        return env.encode()
    path = os.path.join(state_dir, "token_secret.key")
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


def open_registry(state_dir):
    os.makedirs(state_dir, exist_ok=True)
    con = sqlite3.connect(os.path.join(state_dir, "registry.sqlite"))
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def registry_hash(con, node, deployment):
    """SHA-256 over all tokens of one deployment (including controls), in a canonical order.

    The hash reveals nothing about the tokens, so it can be shared (e.g. in a commit or an email)
    before go-live as proof that tokens were not assigned to placements after the fact.
    """
    rows = con.execute(
        "SELECT token, placement, depth, doc_type, location, url_path, IFNULL(control, '') AS control "
        "FROM tokens WHERE node=? AND deployment=? ORDER BY token", (node, deployment)).fetchall()
    h = hashlib.sha256()
    for r in rows:
        h.update(("|".join(str(r[k]) for k in r.keys()) + "\n").encode())
    return h.hexdigest(), len(rows)
