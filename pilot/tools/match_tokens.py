#!/usr/bin/env python3
"""Match node logs against the token registry (standard library only).

Based on playground/tools/match_tokens.py. Differences for real node logs:
  * reads several log files, including rotated and .gz ones
  * time-to-first-resolution (TTFR) is measured from exposed_utc (go-live), falling back to
    created_utc only if a token was never marked exposed (the CSV says which base was used)
  * every request under /docs/ is classified: exact token, near-miss (truncated or extended
    real token), or enumeration (a guess that matches no token)
  * control tokens: any hit on a negative control is a leak; positive controls verify the pipeline
  * --exclude-ips removes our own addresses from the analysis (controls are evaluated on all traffic)
  * accepts both log field names: client_ip (CRAWL format) and remote_addr (first pilot format)

Outputs contain raw IP addresses: write them into data/ (git-ignored), never into the repo.

    python3 pilot/tools/match_tokens.py --log data/n01/logs/requests.json.log* \\
        --state data/n01/state --site data/n01/site --out data/n01/match_out \\
        --exclude-ips data/n01/internal_ips.txt
"""

import argparse
import csv
import gzip
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

from common import HEX_RUN_RE, TOKEN_RE, parse_iso

PAYLOAD_RE = re.compile(r"(?i)(\$\{jndi:|\$\{\$\{|\.\./\.\./|<script|union\s+select|/bin/(ba)?sh)")
CARRIER_OK = {"200", "206", "304"}        # responses that count as "fetched the carrier"


def open_any(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def load_logs(paths):
    rows, bad, seen = [], 0, set()
    for path in paths:
        with open_any(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                # the same request can appear twice if both a rotated file and its .gz were pulled
                key = r.get("request_id") or line
                if key in seen:
                    continue
                seen.add(key)
                r["t"] = float(r.get("msec") or 0)
                r["ip"] = r.get("client_ip") or r.get("remote_addr") or "?"
                try:
                    r["hdrs"] = json.loads(r.get("headers") or "[]")    # [[name, value], ...] in arrival order
                except ValueError:
                    r["hdrs"] = []
                rows.append(r)
    rows.sort(key=lambda r: r["t"])
    return rows, bad


def load_excluded(spec):
    if not spec:
        return set()
    if os.path.exists(spec):
        with open(spec) as f:
            return {ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()}
    return {s.strip() for s in spec.split(",") if s.strip()}


def norm_path(uri):
    p = (uri or "").split("?")[0]
    if p.endswith("/"):
        p += "index.html"
    return p or "/index.html"


def robots_prefixes(site):
    try:
        with open(os.path.join(site, "robots.txt")) as f:
            return re.findall(r"(?im)^\s*Disallow:\s*(\S+)", f.read())
    except OSError:
        return []


def fmt(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if t else ""


def write_csv(out, name, header, rows):
    with open(os.path.join(out, name), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def classify(uri, reg):
    """Return ('exact', token) / ('near_miss', token) / ('enumeration', None) / ('none', None)."""
    u = (uri or "").lower()
    for tok in TOKEN_RE.findall(u):
        if tok in reg:
            return "exact", tok
    for run in HEX_RUN_RE.findall(u):
        for tok in reg:
            if run != tok and (tok.startswith(run) or run.startswith(tok)):
                return "near_miss", tok
    if norm_path(u).startswith("/docs/"):
        return "enumeration", None
    return "none", None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", nargs="+", required=True, help="one or more JSON log files (.gz allowed)")
    ap.add_argument("--state", required=True, help="folder with registry.sqlite")
    ap.add_argument("--site", required=True, help="the built site (for robots.txt)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--exclude-ips", help="file (one IP per line) or comma list of our own addresses")
    ap.add_argument("--session-gap", type=int, default=30 * 60, help="seconds after a resolution that count as its session")
    args = ap.parse_args()

    rows, bad = load_logs(args.log)
    con = sqlite3.connect(os.path.join(args.state, "registry.sqlite"))
    con.row_factory = sqlite3.Row
    reg = {r["token"]: dict(r) for r in con.execute("SELECT * FROM tokens")}
    if not reg:
        raise SystemExit("Registry in %s is empty - build the site first." % args.state)
    excluded = load_excluded(args.exclude_ips)
    # carrier -> tokens, with the window in which each token was actually on that page
    by_location = defaultdict(list)
    for tok, r in reg.items():
        if not r["control"]:
            start = parse_iso(r["exposed_utc"]).timestamp() if r["exposed_utc"] else float("-inf")
            end = parse_iso(r["retired_utc"]).timestamp() if r["retired_utc"] else float("inf")
            by_location[norm_path(r["location"])].append((tok, start, end))
    disallow = robots_prefixes(args.site)
    os.makedirs(args.out, exist_ok=True)

    # --- classify every request -------------------------------------------------------------
    events = []                            # (row, match_type, token)  for exact / near_miss / enumeration
    harvests = defaultdict(list)           # token -> [(t, ip)]
    per_ip = defaultdict(list)
    for r in rows:
        kind, tok = classify(r.get("uri"), reg)
        if kind != "none":
            events.append((r, kind, tok))
        if r["ip"] in excluded:
            continue
        per_ip[r["ip"]].append(r)
        if str(r.get("status")) in CARRIER_OK:
            for t, start, end in by_location.get(norm_path(r.get("uri")), ()):
                if start <= r["t"] < end:
                    harvests[t].append((r["t"], r["ip"]))

    # --- controls (all traffic, including our own) -------------------------------------------
    ctrl_rows = []
    for r, kind, tok in events:
        if tok and reg[tok]["control"]:
            ctrl_rows.append([reg[tok]["control"], tok, kind, fmt(r["t"]), r["ip"],
                              "yes" if r["ip"] in excluded else "", (r.get("user_agent") or "")[:80]])
    write_csv(args.out, "controls.csv", ["control", "token", "match", "time_utc", "client_ip", "internal_ip",
                                         "user_agent"], ctrl_rows)

    # --- everything below: planted tokens, external traffic only -----------------------------
    ext = [(r, k, t) for r, k, t in events if r["ip"] not in excluded and not (t and reg[t]["control"])]
    resolutions = [(r, t) for r, k, t in ext if k == "exact"]

    write_csv(args.out, "doc_requests.csv",
              ["time_utc", "client_ip", "match", "token", "placement", "uri", "status", "user_agent"],
              [[fmt(r["t"]), r["ip"], k, t or "", reg[t]["placement"] if t else "", (r.get("uri") or "")[:200],
                r.get("status"), (r.get("user_agent") or "")[:80]] for r, k, t in ext])

    first_by_tok = {}
    for r, tok in resolutions:
        first_by_tok.setdefault(tok, r)
    tok_rows = []
    for tok, meta in sorted(reg.items(), key=lambda kv: (kv[1]["deployment"], kv[1]["placement"], kv[1]["depth"])):
        if meta["control"]:
            continue
        res = [r for r, t in resolutions if t == tok]
        base_s, base_name = None, ""
        if meta["exposed_utc"]:
            base_s, base_name = parse_iso(meta["exposed_utc"]).timestamp(), "exposed"
        elif meta["created_utc"]:
            base_s, base_name = parse_iso(meta["created_utc"]).timestamp(), "created (never marked exposed)"
        retired_s = parse_iso(meta["retired_utc"]).timestamp() if meta["retired_utc"] else None
        first = first_by_tok.get(tok)
        harvesters = sorted({ip for t, ip in harvests.get(tok, []) if not first or t <= first["t"]})
        resolvers = sorted({r["ip"] for r in res})
        near = sum(1 for r, k, t in ext if k == "near_miss" and t == tok)
        tok_rows.append([
            tok, meta["node"], meta["deployment"], meta["placement"], meta["depth"], meta["doc_type"], meta["location"],
            "yes" if res else "no", len(res), len(resolvers), near,
            "%.1f" % (first["t"] - base_s) if first and base_s else "", base_name,
            first["ip"] if first else "", (first.get("user_agent") or "")[:60] if first else "",
            " ".join(harvesters), " ".join(resolvers),
            "yes" if first and first["ip"] not in harvesters else "",
            sum(1 for r in res if retired_s and r["t"] > retired_s),
        ])
    write_csv(args.out, "tokens.csv",
              ["token", "node", "deployment", "placement", "depth", "doc_type", "location", "resolved", "resolutions",
               "distinct_resolvers", "near_misses", "time_to_first_resolution_s", "ttfr_measured_from",
               "first_resolver", "first_resolver_ua", "harvested_by (before 1st resolution)", "resolved_by",
               "resolver_never_fetched_location", "resolutions_after_retirement"], tok_rows)

    # --- session after token access -------------------------------------------------------------
    sess_rows = []
    for r, tok in resolutions:
        later = [x for x in per_ip[r["ip"]] if r["t"] < x["t"] <= r["t"] + args.session_gap]
        sess_rows.append([tok, reg[tok]["placement"], r["ip"], fmt(r["t"]), len(later),
                          "%.1f" % (later[-1]["t"] - r["t"]) if later else "0",
                          " ".join(x.get("uri", "") for x in later[:5])])
    write_csv(args.out, "sessions_after_token.csv",
              ["token", "placement", "client_ip", "resolved_at_utc", "requests_within_gap", "duration_s",
               "first_follow_up_paths"], sess_rows)

    # --- per client ---------------------------------------------------------------------------------
    cl_rows = []
    for ip, rs in sorted(per_ip.items(), key=lambda kv: -len(kv[1])):
        uas = Counter(r.get("user_agent", "") for r in rs)
        robots_t = min((r["t"] for r in rs if norm_path(r.get("uri")) == "/robots.txt"), default=None)
        dis = [r for r in rs if any(norm_path(r.get("uri")).startswith(p) or (r.get("uri") or "").startswith(p)
                                    for p in disallow)]
        hdr_payload = [r for r in rs if any(PAYLOAD_RE.search(str(v)) for k, v in r["hdrs"]
                                            if str(k).lower() != "host")]
        url_payload = [r for r in rs if PAYLOAD_RE.search(r.get("uri") or "")]
        enum = sum(1 for r, k, t in ext if k == "enumeration" and r["ip"] == ip)
        cl_rows.append([
            ip, len(rs), sum(1 for r in rs if str(r.get("status")) == "404"),
            sum(1 for r in rs if str(r.get("status")) == "400"), uas.most_common(1)[0][0][:70], len(uas),
            "yes" if robots_t else "no", len(dis), sum(1 for r, t in resolutions if r["ip"] == ip), enum,
            len(url_payload), len(hdr_payload), fmt(rs[0]["t"]), "%.1f" % (rs[-1]["t"] - rs[0]["t"]),
        ])
    write_csv(args.out, "clients.csv",
              ["client_ip", "requests", "n_404", "n_400", "top_user_agent", "distinct_uas", "fetched_robots_txt",
               "requests_to_disallowed_paths", "token_resolutions", "enumeration_requests", "payload_in_url",
               "payload_in_headers", "first_seen_utc", "active_s"], cl_rows)

    # --- report ------------------------------------------------------------------------------------
    n_ext = sum(len(v) for v in per_ip.values())
    print("Logs: %d files, %d requests (%d from excluded IPs), %d unparsable lines"
          % (len(args.log), len(rows), len(rows) - n_ext, bad))
    planted = sum(1 for m in reg.values() if not m["control"])
    print("Registry: %d planted tokens, %d resolved at least once by external clients" % (planted, len(first_by_tok)))
    kinds = Counter(k for r, k, t in ext)
    print("Requests under /docs/ or containing token-like strings: %d exact, %d near-miss, %d enumeration\n"
          % (kinds["exact"], kinds["near_miss"], kinds["enumeration"]))
    print("%-14s %-16s %-5s %-6s %-9s %-10s %-16s %s" % ("deployment", "placement", "depth", "type", "resolved",
                                                          "TTFR [s]", "first resolver", "harvested by"))
    for t in tok_rows:
        print("%-14s %-16s %-5s %-6s %-9s %-10s %-16s %s%s%s" % (
            t[2], t[3], t[4], t[5], "%s (%s)" % (t[7], t[8]), t[11], t[13], t[15],
            "   <- resolver never fetched the carrier" if t[17] else "",
            "   <- %s after retirement" % t[18] if t[18] else ""))
    neg = [c for c in ctrl_rows if c[0] == "negative"]
    pos = [c for c in ctrl_rows if c[0] == "positive"]
    print("\nControls: %d hits on NEGATIVE controls%s, %d hits on positive controls"
          % (len(neg), "  <-- LEAK OR CONTAMINATION, check controls.csv" if neg else "", len(pos)))
    print("\nCSV files written to %s" % args.out)


if __name__ == "__main__":
    main()
