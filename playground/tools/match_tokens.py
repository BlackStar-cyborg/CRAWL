#!/usr/bin/env python3
"""Matcher / mini analysis for the playground (standard library only).

Reads the nginx JSON log and the token registry and answers:
  * which tokens were resolved, by whom, how fast after planting      (time-to-first-resolution)
  * who fetched the page/PDF carrying a token (harvest) vs. who resolved it
  * what a client did right after resolving a token                     (session after token access)
  * which tokens were never resolved
  * per client: volume, 404s, robots.txt behaviour, header payloads that the classic log formats miss

Writes CSVs to logs/analysis/ and prints a short report.
    python3 match_tokens.py --log ../logs/nginx/access.json --state ../state --site ../site --out ../logs/analysis
"""

import argparse
import csv
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

from lab_common import TOKEN_RE, parse_iso

SESSION_GAP = 30 * 60
PAYLOAD_RE = re.compile(r"(?i)(\$\{jndi:|\$\{\$\{|\.\./\.\./|<script|union\s+select|/bin/(ba)?sh)")


def load_log(path):
    rows, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                bad += 1
                continue
            r["t"] = float(r.get("msec") or 0)
            try:
                r["hdrs"] = json.loads(r.get("headers") or "[]")      # [[name, value], ...] in arrival order
            except ValueError:
                r["hdrs"] = []
            rows.append(r)
    rows.sort(key=lambda r: r["t"])
    return rows, bad


def norm_path(uri):
    p = (uri or "").split("?")[0]
    if p.endswith("/"):
        p += "index.html"
    return p or "/index.html"


def robots_prefixes(site):
    try:
        txt = open(os.path.join(site, "robots.txt")).read()
    except OSError:
        return []
    return re.findall(r"(?im)^\s*Disallow:\s*(\S+)", txt)


def fmt(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if t else ""


def write_csv(out, name, header, rows):
    with open(os.path.join(out, name), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="/logs/nginx/access.json")
    ap.add_argument("--state", default=os.environ.get("CRAWL_STATE_DIR", "/state"))
    ap.add_argument("--site", default="/site")
    ap.add_argument("--out", default="/logs/analysis")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        raise SystemExit("No log at %s yet - start the lab and run some traffic first." % args.log)
    rows, bad = load_log(args.log)
    con = sqlite3.connect(os.path.join(args.state, "registry.sqlite"))
    con.row_factory = sqlite3.Row
    reg = {r["token"]: dict(r) for r in con.execute("SELECT * FROM tokens")}
    by_location = defaultdict(set)
    for tok, r in reg.items():
        by_location[norm_path(r["location"])].add(tok)
    disallow = robots_prefixes(args.site)
    os.makedirs(args.out, exist_ok=True)

    # --- events -------------------------------------------------------------------------------
    resolutions = []                       # (row, token)
    harvests = defaultdict(list)           # token -> [(t, ip)]
    per_ip = defaultdict(list)
    for r in rows:
        ip = r.get("client_ip", "?")
        per_ip[ip].append(r)
        path = norm_path(r.get("uri"))
        for tok in set(TOKEN_RE.findall(r.get("uri") or "")):
            if tok in reg:
                resolutions.append((r, tok))
        if str(r.get("status")) == "200":
            for tok in by_location.get(path, ()):
                harvests[tok].append((r["t"], ip))

    # --- per token ------------------------------------------------------------------------------
    tok_rows = []
    first_by_tok = {}
    for r, tok in resolutions:
        first_by_tok.setdefault(tok, r)
    for tok, meta in sorted(reg.items(), key=lambda kv: (kv[1]["placement"], kv[1]["depth"])):
        res = [r for r, t in resolutions if t == tok]
        created = parse_iso(meta["created_utc"]).timestamp()
        first = first_by_tok.get(tok)
        harvesters = sorted({ip for t, ip in harvests.get(tok, []) if not first or t <= first["t"]})
        resolvers = sorted({r["client_ip"] for r in res})
        tok_rows.append([
            tok, meta["deployment"], meta["placement"], meta["depth"], meta["doc_type"], meta["location"],
            "yes" if res else "no", len(res), len(resolvers),
            "%.1f" % (first["t"] - created) if first else "", first["client_ip"] if first else "",
            (first.get("user_agent") or "")[:60] if first else "",
            " ".join(harvesters), " ".join(resolvers),
            "yes" if first and first["client_ip"] not in harvesters else "",
        ])
    write_csv(args.out, "tokens.csv",
              ["token", "deployment", "placement", "depth", "doc_type", "location", "resolved", "resolutions",
               "distinct_resolvers", "time_to_first_resolution_s", "first_resolver", "first_resolver_ua",
               "harvested_by (before 1st resolution)", "resolved_by", "resolver_never_fetched_location"], tok_rows)

    # --- session after token access ---------------------------------------------------------------
    sess_rows = []
    for r, tok in resolutions:
        later = [x for x in per_ip[r["client_ip"]] if r["t"] < x["t"] <= r["t"] + SESSION_GAP]
        sess_rows.append([tok, reg[tok]["placement"], r["client_ip"], fmt(r["t"]), len(later),
                          "%.1f" % (later[-1]["t"] - r["t"]) if later else "0",
                          " ".join(x.get("uri", "") for x in later[:5])])
    write_csv(args.out, "sessions_after_token.csv",
              ["token", "placement", "client_ip", "resolved_at_utc", "requests_within_30min", "duration_s",
               "first_follow_up_paths"], sess_rows)

    # --- per client --------------------------------------------------------------------------------
    cl_rows = []
    for ip, rs in sorted(per_ip.items(), key=lambda kv: -len(kv[1])):
        uas = Counter(r.get("user_agent", "") for r in rs)
        robots_t = min((r["t"] for r in rs if norm_path(r.get("uri")) == "/robots.txt"), default=None)
        dis = [r for r in rs if any(norm_path(r.get("uri")).startswith(p) or (r.get("uri") or "").startswith(p)
                                    for p in disallow)]
        hdr_payload = [r for r in rs if any(PAYLOAD_RE.search(str(v)) for k, v in r["hdrs"]
                                            if k.lower() not in ("host",))]
        url_payload = [r for r in rs if PAYLOAD_RE.search(r.get("uri") or "")]
        cl_rows.append([
            ip, len(rs), sum(1 for r in rs if str(r.get("status")) == "404"),
            sum(1 for r in rs if str(r.get("status")) == "400"), uas.most_common(1)[0][0][:70], len(uas),
            "yes" if robots_t else "no", len(dis), sum(1 for r, t in resolutions if r["client_ip"] == ip),
            len(url_payload), len(hdr_payload), fmt(rs[0]["t"]), "%.1f" % (rs[-1]["t"] - rs[0]["t"]),
        ])
    write_csv(args.out, "clients.csv",
              ["client_ip", "requests", "n_404", "n_400", "top_user_agent", "distinct_uas", "fetched_robots_txt",
               "requests_to_disallowed_paths", "token_resolutions", "payload_in_url", "payload_in_headers_only_visible_in_json",
               "first_seen_utc", "active_s"], cl_rows)

    # --- report ------------------------------------------------------------------------------------
    print("Log: %s  (%d requests, %d unparsable lines)" % (args.log, len(rows), bad))
    print("Registry: %d tokens, %d resolved at least once\n" % (len(reg), len(first_by_tok)))
    print("%-16s %-5s %-5s %-9s %-10s %-16s %s" % ("placement", "depth", "type", "resolved", "TTFR [s]", "first resolver", "harvested by"))
    for t in tok_rows:
        print("%-16s %-5s %-5s %-9s %-10s %-16s %s%s" % (t[2], t[3], t[4], "%s (%s)" % (t[6], t[7]), t[9], t[10], t[12],
                                                       "   <- resolver never fetched the carrier" if t[14] else ""))
    print("\n%-16s %8s %5s %5s %-8s %-6s %-8s %-8s  %s" % ("client", "requests", "404", "400", "robots?", "disall", "tokens", "hdr-pay", "user agent"))
    for c in cl_rows:
        print("%-16s %8d %5d %5d %-8s %-6d %-8d %-8d  %s" % (c[0], c[1], c[2], c[3], c[6], c[7], c[8], c[10], c[4][:50]))
    print("\nCSV files written to %s" % args.out)


if __name__ == "__main__":
    main()
