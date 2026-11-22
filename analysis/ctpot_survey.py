#!/usr/bin/env python3
"""
ctpot_survey.py - analysis of the CTPOT dataset (ctpot_data.csv) from
"Uninvited Guests: Analyzing the Identity and Behavior of Certificate
Transparency Bots" (Kondracki, So, Nikiforakis, USENIX Security 2022),
https://uninvited-guests.github.io

Runs locally, Python 3.8+, standard library only (matplotlib optional, for charts).
Nothing is uploaded anywhere.

Usage:
    1. Set DATA_FILE and OUT_DIR in the "Settings" block below.
    2. python3 ctpot_survey.py
    Optional: python3 ctpot_survey.py --keep-ips      # keep real IPs in the outputs

Expected columns (as in the published file):
    request_timestamp, host, path, user_agent, ja3_fingerprint, client_ip, port,
    method, scheme, org, country_name, asn_type, cert_reg_ts, type

Why this dataset matters for CRAWL: every host name in it existed only in a
Certificate Transparency log. So each host behaves like a honeytoken whose only
"placement" is the CT log, and the same metrics CRAWL needs can be tried here:
time from certificate registration to the first request (~ time-to-first-resolution),
what the first visitor did next (~ session length after token access), how many
clients and networks came later (~ resolution frequency).

Outputs (CSV, in OUT_DIR):
    0_summary.txt               key numbers and the assumptions made
    1_field_completeness.csv    per column: empty share, distinct values
    2_by_type.csv               per certificate type: hosts, requests, clients, delays
    3_hosts.csv                 per host: cert time, first request, delay, first visitor
    4_top_values.csv            top paths / UAs / orgs / JA3 ... by requests and by clients
    5_patterns.csv              heuristic pattern hits (probe paths, payloads, bot UAs ...)
    6_clients.csv               one row per client IP (pseudonymised by default)
    7_sessions.csv              one row per session (client + inactivity gap)
    8_sessions_by_asn_type.csv  session length and size per network type
    9_ja3_vs_user_agent.csv     per JA3: how many different User-Agent families use it
    10_ua_family_vs_ja3.csv     per claimed User-Agent family: how many JA3 fingerprints
    11_path_set_groups.csv      clients requesting exactly the same set of paths (campaigns)
    12_timestamp_resolution.csv how often one client sends >1 request in the same second
    charts/*.png                if matplotlib is installed

Pattern rules and User-Agent families are heuristics, not verdicts.
"""

import argparse
import csv
import hashlib
import hmac
import os
import re
import secrets
import statistics
import sys
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ----------------------------------------------------------------------------
# Settings - edit these, then just run:  python3 ctpot_survey.py
# ----------------------------------------------------------------------------

DATA_FILE = os.path.expanduser("~/Downloads/ctpot_data.csv")   # <- path to the downloaded file
OUT_DIR = os.path.expanduser("~/Downloads/ctpot_survey_out")    # <- where results are written

SESSION_GAP_S = 30 * 60      # a client's session ends after this many seconds without a request
TOP_N = 30                   # rows per column in 4_top_values.csv
MIN_GROUP_CLIENTS = 5        # path-set groups with fewer clients are not reported
MIN_GROUP_PATHS = 2          # a client needs at least this many non-trivial paths to be grouped
PATH_CAP = 2000              # distinct paths remembered per client (memory guard)
TRIVIAL_PATHS = {"/", "/favicon.ico", "/robots.txt"}  # ignored when grouping by path set

# The file's timestamps carry no time zone. They are treated as UTC, and
# request_timestamp and cert_reg_ts are assumed to use the same clock.
# For stable pseudonyms across runs, set the environment variable CTPOT_PSEUDO_KEY
# to a secret string; otherwise a random key is used for each run.

# ----------------------------------------------------------------------------
# Heuristic rules (same spirit as log_survey.py - edit freely)
# ----------------------------------------------------------------------------

PROBE_PATHS = re.compile(
    r"(?i)(/\.env\b|/\.git(/|$)|/\.svn(/|$)|/\.aws|/\.ssh|/wp-login\.php|/wp-admin|/wp-content|/wp-includes|"
    r"/xmlrpc\.php|/phpmyadmin|/pma/|/cgi-bin/|/vendor/phpunit|/boaform|/actuator|/server-status|/\.DS_Store|"
    r"/config\.(php|json|yml)|/backup|\.sql(\.gz)?$|\.bak$|/etc/passwd|/manager/html|/solr/|/jenkins|"
    r"/owa/|/autodiscover|/hnap1|/console|/\.well-known/security\.txt)"
)
CVE_PAYLOAD = re.compile(
    r"(?i)(\$\{jndi:|%24%7bjndi|\$\{\$\{|\.\./\.\./|%2e%2e%2f|%2e%2e/|\bunion\b.{0,20}\bselect\b|"
    r"<script|%3cscript|\bwget\b.{0,20}http|\bcurl\b.{0,20}http|/bin/(ba)?sh|\bcmd\.exe\b)"
)
BOT_UA = re.compile(
    r"(?i)(googlebot|bingbot|yandexbot|baiduspider|duckduckbot|applebot|gptbot|chatgpt-user|oai-searchbot|"
    r"ccbot|claudebot|anthropic|perplexity|bytespider|amazonbot|facebookexternalhit|semrush|ahrefs|mj12bot|"
    r"petalbot|zgrab|masscan|nmap|censys|shodan|expanse|nuclei|nikto|sqlmap|netcraft|leakix|"
    r"internet-measurement|python-requests|python-urllib|aiohttp|go-http-client|curl/|wget/|libwww|"
    r"okhttp|java/|headlesschrome|phantomjs|spider|crawler|scanner|bot\b)"
)
SCANNER_UA = re.compile(
    r"(?i)(zgrab|masscan|nmap|censys|shodan|nuclei|nikto|sqlmap|expanse|netcraft|internet-measurement|leakix)")
BROWSER_FAMILIES = ("Chrome", "Firefox", "Safari", "Edge", "Opera", "IE")

PATTERNS = ["declared_bot_ua", "scanner_tool_ua", "robots_txt", "probe_path",
            "cve_or_injection_payload", "empty_user_agent", "non_get_method"]
SUSPICIOUS = {"probe_path", "cve_or_injection_payload", "scanner_tool_ua"}


def classify(method, path, ua):
    hits = set()
    p = path.split("?")[0].lower()
    if p == "/robots.txt":
        hits.add("robots_txt")
    if PROBE_PATHS.search(path):
        hits.add("probe_path")
    if CVE_PAYLOAD.search(path) or CVE_PAYLOAD.search(ua):
        hits.add("cve_or_injection_payload")
    if ua in ("", "-"):
        hits.add("empty_user_agent")
    else:
        if SCANNER_UA.search(ua):
            hits.add("scanner_tool_ua")
        if BOT_UA.search(ua):
            hits.add("declared_bot_ua")
    if method and method.upper() not in ("GET", "HEAD"):
        hits.add("non_get_method")
    return hits


def ua_family(ua):
    """Coarse User-Agent family: a declared tool/bot token, a claimed browser, or 'other'."""
    if ua in ("", "-"):
        return "(empty)"
    m = BOT_UA.search(ua)
    if m:
        return "tool:" + m.group(1).lower().rstrip("/")
    if "Edg/" in ua or "Edge/" in ua:
        return "Edge"
    if "OPR/" in ua or "Opera" in ua:
        return "Opera"
    if "Firefox/" in ua:
        return "Firefox"
    if "Chrome/" in ua or "CriOS/" in ua:
        return "Chrome"
    if "Safari/" in ua and "Version/" in ua:
        return "Safari"
    if "MSIE " in ua or "Trident/" in ua:
        return "IE"
    return "other"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
              "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z")


def parse_ts(s):
    """Return epoch seconds (float, UTC) or None. Accepts ISO-like strings and epoch numbers."""
    s = (s or "").strip()
    if not s or s == "-":
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", s):
        v = float(s)
        return v / 1000.0 if v > 1e11 else v      # milliseconds -> seconds
    dt = None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for f in TS_FORMATS:
            try:
                dt = datetime.strptime(s, f)
                break
            except ValueError:
                pass
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def fmt_ts(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t is not None else ""


def quantiles(vals):
    """(n, p10, median, p90) of a list; empty strings when there is no data."""
    if not vals:
        return 0, "", "", ""
    v = sorted(vals)
    n = len(v)
    q = lambda p: v[min(n - 1, int(round(p * (n - 1))))]
    return n, q(0.10), q(0.50), q(0.90)


def hours(x):
    return "" if x == "" or x is None else "%.2f" % (x / 3600.0)


class Pseudonymizer:
    def __init__(self, keep):
        self.keep = keep
        env = os.environ.get("CTPOT_PSEUDO_KEY")
        self.stable = bool(env)
        self.key = env.encode() if env else secrets.token_bytes(16)   # never written to disk
        self.cache = {}

    def __call__(self, ip):
        if self.keep:
            return ip
        p = self.cache.get(ip)
        if p is None:
            p = "ip_" + hmac.new(self.key, ip.encode(), hashlib.sha256).hexdigest()[:10]
            self.cache[ip] = p
        return p


def write_csv(out_dir, name, header, rows):
    with open(os.path.join(out_dir, name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


# ----------------------------------------------------------------------------
# Charts (optional: pip install matplotlib)
# ----------------------------------------------------------------------------

# Validated categorical palette, light mode, fixed order (slot 1 = blue, 2 = orange, ...).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
C_BLUE, C_ORANGE = SERIES[0], SERIES[1]
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"


def make_charts(out_dir, daily, type_delays, asn_rows, org_rows, pattern_totals):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter
    except ImportError:
        print("matplotlib not installed - skipping charts (pip install matplotlib).", file=sys.stderr)
        return
    cdir = os.path.join(out_dir, "charts")
    os.makedirs(cdir, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.edgecolor": GRID, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.axisbelow": True, "axes.spines.top": False, "axes.spines.right": False,
        "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    })
    thousands = FuncFormatter(lambda v, _: "{:,.0f}".format(v))

    def hbar(fname, title, labels, values, xlabel, fmt="{:,.0f}", note=None):
        if not labels:
            return
        fig, ax = plt.subplots(figsize=(8.5, max(2.6, 0.34 * len(labels) + 1.4)))
        y = list(range(len(labels)))[::-1]
        ax.barh(y, values, color=C_BLUE, height=0.62)
        ax.set_yticks(y)
        ax.set_yticklabels(labels)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel(xlabel)
        if fmt == "{:,.0f}":
            ax.xaxis.set_major_formatter(thousands)
        vmax = max(values) or 1
        for yi, v in zip(y, values):
            ax.text(v + vmax * 0.01, yi, fmt.format(v), va="center", fontsize=9, color=INK)
        ax.set_xlim(0, vmax * 1.15)
        ax.set_title(title)
        if note:
            fig.text(0.01, 0.01, note, fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03 if note else 0, 1, 1))
        fig.savefig(os.path.join(cdir, fname), dpi=160)
        plt.close(fig)

    # 1) requests per day + suspicious share (two panels, never a dual axis)
    days = sorted(daily)
    if len(days) >= 2:
        xs = list(range(len(days)))
        fig, (a1, a2) = plt.subplots(2, 1, figsize=(8.5, 5.6), sharex=True, gridspec_kw={"height_ratios": [3, 2]})
        a1.plot(xs, [daily[d][0] for d in days], color=C_BLUE, linewidth=2)
        a1.yaxis.set_major_formatter(thousands)
        a1.set_ylabel("requests / day")
        a1.set_title("Requests to CT-only hosts over time")
        a2.plot(xs, [100.0 * daily[d][1] / daily[d][0] for d in days], color=C_ORANGE, linewidth=2)
        a2.set_ylabel("suspicious, % of day")
        step = max(1, len(days) // 12)
        a2.set_xticks(xs[::step])
        a2.set_xticklabels(days[::step], rotation=45, ha="right")
        fig.text(0.01, 0.01, "Days in UTC (assumed). Suspicious = probe path, CVE/injection payload or scanner-tool User-Agent.",
                 fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        fig.savefig(os.path.join(cdir, "1_requests_per_day.png"), dpi=160)
        plt.close(fig)

    # 2) ECDF: hours from certificate registration to the first request, per certificate type
    series = [(t, sorted(v)) for t, v in sorted(type_delays.items(), key=lambda kv: -len(kv[1])) if v]
    if len(series) > len(SERIES):     # fold the rest into one "other types" series
        rest = sorted(x for _, v in series[len(SERIES) - 1:] for x in v)
        series = series[:len(SERIES) - 1] + [("other types", rest)]
    pos = [(t, [max(x, 1.0) for x in v if x >= 0]) for t, v in series]
    pos = [(t, v) for t, v in pos if v]
    if pos:
        fig, ax = plt.subplots(figsize=(8.5, 5.0))
        for i, (t, v) in enumerate(pos):
            ys = [(k + 1) / len(v) * 100 for k in range(len(v))]
            ax.step(v, ys, where="post", color=SERIES[i], linewidth=2, label="%s (n=%d)" % (t, len(v)))
        ax.set_xscale("log")
        lo_x = min(v[0] for _, v in pos)
        hi_x = max(v[-1] for _, v in pos)
        ticks = [(1, "1 s"), (10, "10 s"), (60, "1 min"), (600, "10 min"), (3600, "1 h"), (6 * 3600, "6 h"),
                 (86400, "1 day"), (7 * 86400, "1 week"), (30 * 86400, "30 days"), (365 * 86400, "1 year")]
        ticks = [(x, l) for x, l in ticks if lo_x / 3 <= x <= hi_x * 3] or ticks[:1]
        ax.set_xticks([x for x, _ in ticks])
        ax.set_xticklabels([l for _, l in ticks])
        ax.minorticks_off()
        ax.set_xlabel("time from certificate registration to first request (log scale)")
        ax.set_ylabel("% of hosts already visited")
        ax.set_ylim(0, 102)
        ax.set_title("How fast CT-only hosts get their first visitor")
        ax.legend(frameon=False, loc="lower right")
        fig.text(0.01, 0.01, "Hosts with no cert_reg_ts or a first request before registration are left out. Delays under 1 s are drawn at 1 s.",
                 fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        fig.savefig(os.path.join(cdir, "2_time_to_first_request_ecdf.png"), dpi=160)
        plt.close(fig)

    # 3) network types, 4) top networks by clients, 5) pattern hits
    hbar("3_requests_by_asn_type.png", "Requests by network type (asn_type)",
         [r[0] for r in asn_rows], [r[1] for r in asn_rows], "requests")
    hbar("4_top_orgs_by_clients.png", "Networks sending the most distinct clients",
         [r[0][:45] for r in org_rows], [r[1] for r in org_rows], "distinct client IPs")
    items = sorted(pattern_totals.items(), key=lambda kv: -kv[1])
    hbar("5_pattern_hits.png", "Requests matching each heuristic pattern",
         [k for k, _ in items], [v for _, v in items], "matching requests",
         note="Heuristics, not verdicts: a match means 'worth a look'.")
    print("Charts written to %s" % cdir, file=sys.stderr)


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

EXPECTED = ["request_timestamp", "host", "path", "user_agent", "ja3_fingerprint", "client_ip", "port",
            "method", "scheme", "org", "country_name", "asn_type", "cert_reg_ts", "type"]
TOP_COLUMNS = ["path", "user_agent", "org", "ja3_fingerprint", "country_name", "asn_type",
               "scheme", "port", "method", "type"]
IP_SET_COLUMNS = {"path", "user_agent", "org", "ja3_fingerprint"}   # also count distinct clients per value


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data_file", nargs="?", default=DATA_FILE, help="path to ctpot_data.csv (default: DATA_FILE)")
    ap.add_argument("out_dir", nargs="?", default=OUT_DIR, help="output folder (default: OUT_DIR)")
    ap.add_argument("--keep-ips", action="store_true", help="do not pseudonymise client IPs in outputs")
    ap.add_argument("--limit", type=int, default=0, help="read only the first N rows (quick test)")
    args = ap.parse_args()

    if not os.path.isfile(args.data_file):
        sys.exit("Data file not found: %r - set DATA_FILE at the top of the script." % args.data_file)
    os.makedirs(args.out_dir, exist_ok=True)
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2 ** 31 - 1)
    pseudo = Pseudonymizer(args.keep_ips)

    # --- accumulators -------------------------------------------------------
    n_rows = bad_ts = short_rows = 0
    empty = Counter()
    distinct = defaultdict(set)
    top = defaultdict(Counter)                    # column -> value -> requests
    top_ips = defaultdict(lambda: defaultdict(set))  # column -> value -> {ip ids}
    ip_ids, ip_names = {}, []                     # ip string <-> small int
    host_ids, host_names = {}, []

    hosts = {}            # host -> dict
    types = defaultdict(lambda: {"requests": 0, "hosts": set(), "ips": set(), "https": 0, "suspicious": 0})
    clients = []          # per ip id -> dict
    pattern_req = Counter()
    pattern_ips = defaultdict(set)
    pattern_by_asn = defaultdict(Counter)
    daily = defaultdict(lambda: [0, 0])
    ja3_stats = defaultdict(lambda: {"requests": 0, "families": Counter(), "uas": set(), "ips": set()})
    fam_ja3 = defaultdict(lambda: {"requests": 0, "ja3": Counter(), "no_ja3": 0})
    tmin = tmax = None

    with open(args.data_file, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.reader(fh)
        header = [h.strip().lower() for h in next(reader)]
        missing = [c for c in EXPECTED if c not in header]
        if missing:
            print("warning: columns not found, treated as empty: %s" % ", ".join(missing), file=sys.stderr)
        col = {c: header.index(c) for c in EXPECTED if c in header}
        ncol = len(header)

        for row in reader:
            if not row or not any(x.strip() for x in row):
                continue
            n_rows += 1
            if args.limit and n_rows > args.limit:
                n_rows -= 1
                break
            if len(row) < ncol:
                short_rows += 1
            get = lambda c: row[col[c]].strip() if c in col and col[c] < len(row) else ""
            r = {c: get(c) for c in EXPECTED}

            for c in EXPECTED:
                v = r[c]
                if v in ("", "-"):
                    empty[c] += 1
                elif c not in ("request_timestamp",):
                    if len(distinct[c]) < 2_000_000:
                        distinct[c].add(v)

            ts = parse_ts(r["request_timestamp"])
            if ts is None:
                bad_ts += 1
                continue
            tmin = ts if tmin is None or ts < tmin else tmin
            tmax = ts if tmax is None or ts > tmax else tmax

            ip = r["client_ip"] or "(no ip)"
            iid = ip_ids.get(ip)
            if iid is None:
                iid = ip_ids[ip] = len(ip_names)
                ip_names.append(ip)
                clients.append({"ts": array("d"), "hix": array("l"), "requests": 0, "hosts": set(),
                                "paths": set(), "path_cap_hit": False, "orgs": Counter(), "asn": Counter(),
                                "country": Counter(), "fam": Counter(), "ja3": set(), "flags": Counter(),
                                "scheme": Counter()})
            host = r["host"].lower() or "(no host)"
            hid = host_ids.get(host)
            if hid is None:
                hid = host_ids[host] = len(host_names)
                host_names.append(host)

            path, ua, method = r["path"], r["user_agent"], r["method"]
            fam = ua_family(ua)
            hits = classify(method, path, ua)
            sus = bool(hits & SUSPICIOUS)

            # top values
            for c in TOP_COLUMNS:
                v = r[c] if r[c] else "(empty)"
                if c == "path":
                    v = v[:300]
                elif c == "user_agent":
                    v = v[:300]
                top[c][v] += 1
                if c in IP_SET_COLUMNS:
                    top_ips[c][v].add(iid)

            # per host
            h = hosts.get(host)
            if h is None:
                h = hosts[host] = {"type": r["type"] or "(empty)", "cert": parse_ts(r["cert_reg_ts"]),
                                   "first": None, "first_iid": None, "first_row": None, "first_https": None,
                                   "requests": 0, "ips": set(), "orgs": set()}
            if h["cert"] is None and r["cert_reg_ts"]:
                h["cert"] = parse_ts(r["cert_reg_ts"])
            h["requests"] += 1
            h["ips"].add(iid)
            h["orgs"].add(r["org"])
            if h["first"] is None or ts < h["first"]:
                h["first"], h["first_iid"] = ts, iid
                h["first_row"] = (r["org"], r["asn_type"], r["scheme"], path[:200], fam)
            if r["scheme"].lower() == "https" and (h["first_https"] is None or ts < h["first_https"]):
                h["first_https"] = ts

            # per type
            t = types[h["type"]]
            t["requests"] += 1
            t["hosts"].add(hid)
            t["ips"].add(iid)
            t["https"] += r["scheme"].lower() == "https"
            t["suspicious"] += sus

            # per client
            cl = clients[iid]
            cl["ts"].append(ts)
            cl["hix"].append(hid)
            cl["requests"] += 1
            cl["hosts"].add(hid)
            if len(cl["paths"]) < PATH_CAP:
                cl["paths"].add(path.split("?")[0])
            else:
                cl["path_cap_hit"] = True
            cl["orgs"][r["org"]] += 1
            cl["asn"][r["asn_type"] or "(empty)"] += 1
            cl["country"][r["country_name"]] += 1
            cl["fam"][fam] += 1
            cl["scheme"][r["scheme"].lower()] += 1
            if r["ja3_fingerprint"]:
                cl["ja3"].add(r["ja3_fingerprint"])
            for p in hits:
                cl["flags"][p] += 1
                pattern_req[p] += 1
                pattern_ips[p].add(iid)
                pattern_by_asn[p][r["asn_type"] or "(empty)"] += 1

            # JA3 vs User-Agent
            j = r["ja3_fingerprint"]
            if j:
                s = ja3_stats[j]
                s["requests"] += 1
                s["families"][fam] += 1
                if len(s["uas"]) < 1000:
                    s["uas"].add(ua)
                s["ips"].add(iid)
            fj = fam_ja3[fam]
            if r["scheme"].lower() == "https":
                fj["requests"] += 1
                if j:
                    fj["ja3"][j] += 1
                else:
                    fj["no_ja3"] += 1

            day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
            daily[day][0] += 1
            daily[day][1] += sus

            if n_rows % 250000 == 0:
                print("  %d rows ..." % n_rows, file=sys.stderr)

    if not n_rows:
        sys.exit("No data rows found in %s." % args.data_file)
    out = args.out_dir
    good_rows = n_rows - bad_ts

    # --- 1 field completeness ----------------------------------------------
    write_csv(out, "1_field_completeness.csv", ["column", "empty_rows", "pct_empty", "distinct_values"],
              [[c, empty[c], "%.2f" % (100.0 * empty[c] / n_rows),
                len(distinct[c]) if c != "request_timestamp" else ""] for c in EXPECTED])

    # --- sessions (per client, inactivity gap) ------------------------------
    session_rows = []
    sess_by_asn = defaultdict(lambda: {"dur": [], "req": [], "hosts": []})
    bounds = {}                      # iid -> (starts, ends, n_requests)
    same_second_req = same_second_ips = 0
    for iid, cl in enumerate(clients):
        order = sorted(range(len(cl["ts"])), key=cl["ts"].__getitem__)
        tss = [cl["ts"][k] for k in order]
        hix = [cl["hix"][k] for k in order]
        asn = cl["asn"].most_common(1)[0][0]
        starts, ends, sizes = [], [], []
        s0 = 0
        had_same = False
        for k in range(1, len(tss) + 1):
            if k < len(tss) and int(tss[k]) == int(tss[k - 1]):
                same_second_req += 1
                had_same = True
            if k == len(tss) or tss[k] - tss[k - 1] > SESSION_GAP_S:
                dur = tss[k - 1] - tss[s0]
                nreq = k - s0
                nh = len(set(hix[s0:k]))
                starts.append(tss[s0])
                ends.append(tss[k - 1])
                sizes.append(nreq)
                session_rows.append([pseudo(ip_names[iid]), len(starts), fmt_ts(tss[s0]), int(dur), nreq, nh, asn])
                sess_by_asn[asn]["dur"].append(dur)
                sess_by_asn[asn]["req"].append(nreq)
                sess_by_asn[asn]["hosts"].append(nh)
                s0 = k
        same_second_ips += had_same
        bounds[iid] = (starts, ends, sizes)
        cl["n_sessions"] = len(starts)
        cl["sorted_ts"] = tss
        cl["sorted_hix"] = hix

    write_csv(out, "7_sessions.csv",
              ["client", "session_no", "start_utc", "duration_s", "requests", "distinct_hosts", "asn_type"], session_rows)
    rows = []
    for asn, d in sorted(sess_by_asn.items(), key=lambda kv: -len(kv[1]["dur"])):
        n, p10, med, p90 = quantiles(d["dur"])
        rows.append([asn, n, int(med), int(p90), "%g" % statistics.median(d["req"]), max(d["req"]),
                     "%g" % statistics.median(d["hosts"]), "%.1f" % (100.0 * sum(1 for x in d["req"] if x == 1) / n)])
    write_csv(out, "8_sessions_by_asn_type.csv",
              ["asn_type", "sessions", "median_duration_s", "p90_duration_s", "median_requests", "max_requests",
               "median_distinct_hosts", "pct_single_request_sessions"], rows)

    # --- 3 hosts (CT-only domains as honeytokens) ---------------------------
    host_rows = []
    type_delays = defaultdict(list)
    before_cert = no_cert = 0
    for host, h in hosts.items():
        delay = None
        if h["cert"] is None:
            no_cert += 1
        else:
            delay = h["first"] - h["cert"]
            if delay < 0:
                before_cert += 1
            type_delays[h["type"]].append(delay)
        # what did the first visitor do in the session that contains its first request here?
        iid = h["first_iid"]
        starts, ends, sizes = bounds[iid]
        si = max(0, bisect_right(starts, h["first"]) - 1)
        cl = clients[iid]
        hid = host_ids[host]
        lo = bisect_left(cl["sorted_ts"], starts[si])
        hi = bisect_right(cl["sorted_ts"], ends[si])
        on_host = sum(1 for k in range(lo, hi) if cl["sorted_hix"][k] == hid)
        org, asn_t, scheme, fpath, fam = h["first_row"]
        host_rows.append([
            host, h["type"], fmt_ts(h["cert"]), fmt_ts(h["first"]),
            int(delay) if delay is not None else "", hours(delay) if delay is not None else "",
            fmt_ts(h["first_https"]), h["requests"], len(h["ips"]), len(h["orgs"]),
            pseudo(ip_names[iid]), org, asn_t, scheme, fam, fpath,
            int(ends[si] - starts[si]), sizes[si], on_host,
        ])
    host_rows.sort(key=lambda r: (r[4] == "", r[4] if r[4] != "" else 0))
    write_csv(out, "3_hosts.csv",
              ["host", "type", "cert_reg_utc", "first_request_utc", "delay_s", "delay_h", "first_https_utc",
               "requests", "distinct_clients", "distinct_orgs", "first_client", "first_org", "first_asn_type",
               "first_scheme", "first_ua_family", "first_path",
               "first_client_session_s", "first_client_session_requests", "first_client_session_requests_this_host"],
              host_rows)

    # --- 2 by type ------------------------------------------------------------
    rows = []
    for t, s in sorted(types.items(), key=lambda kv: -kv[1]["requests"]):
        pos = [d for d in type_delays.get(t, []) if d >= 0]
        n, p10, med, p90 = quantiles(pos)
        rows.append([t, len(s["hosts"]), s["requests"], len(s["ips"]),
                     "%.1f" % (100.0 * s["https"] / s["requests"]), "%.2f" % (100.0 * s["suspicious"] / s["requests"]),
                     n, hours(p10), hours(med), hours(p90)])
    write_csv(out, "2_by_type.csv",
              ["type", "hosts", "requests", "distinct_clients", "pct_https", "pct_suspicious",
               "hosts_with_delay", "delay_p10_h", "delay_median_h", "delay_p90_h"], rows)

    # --- 4 top values ---------------------------------------------------------
    rows = []
    for c in TOP_COLUMNS:
        for v, n in top[c].most_common(TOP_N):
            rows.append([c, "by_requests", v, n, len(top_ips[c][v]) if c in IP_SET_COLUMNS else ""])
        if c in IP_SET_COLUMNS:
            by_ips = sorted(top_ips[c].items(), key=lambda kv: -len(kv[1]))[:TOP_N]
            for v, s in by_ips:
                rows.append([c, "by_distinct_clients", v, top[c][v], len(s)])
    write_csv(out, "4_top_values.csv", ["column", "ranking", "value", "requests", "distinct_clients"], rows)

    # --- 5 patterns -----------------------------------------------------------
    asn_types = [a for a, _ in top["asn_type"].most_common()]
    rows = [[p, pattern_req[p], "%.3f" % (100.0 * pattern_req[p] / good_rows), len(pattern_ips[p])]
            + [pattern_by_asn[p][a] for a in asn_types] for p in PATTERNS]
    write_csv(out, "5_patterns.csv",
              ["pattern", "requests", "pct_of_requests", "distinct_clients"] + ["requests_" + a for a in asn_types], rows)

    # --- 6 clients ------------------------------------------------------------
    rows = []
    for iid, cl in enumerate(clients):
        tss = cl["sorted_ts"]
        rows.append([
            pseudo(ip_names[iid]), cl["requests"], len(cl["hosts"]), len(cl["paths"]),
            "yes" if cl["path_cap_hit"] else "", cl["orgs"].most_common(1)[0][0], cl["asn"].most_common(1)[0][0],
            cl["country"].most_common(1)[0][0], "|".join("%s:%d" % kv for kv in cl["fam"].most_common(3)),
            len(cl["ja3"]), "|".join("%s:%d" % kv for kv in cl["scheme"].most_common()),
            fmt_ts(tss[0]), fmt_ts(tss[-1]), int(tss[-1] - tss[0]), cl["n_sessions"],
            "|".join("%s:%d" % kv for kv in cl["flags"].most_common(5)),
        ])
    rows.sort(key=lambda r: -r[2])
    write_csv(out, "6_clients.csv",
              ["client", "requests", "distinct_hosts", "distinct_paths", "path_cap_hit", "org", "asn_type", "country",
               "ua_families", "distinct_ja3", "schemes", "first_seen_utc", "last_seen_utc", "active_span_s",
               "sessions", "pattern_hits"], rows)

    # --- 9 / 10 JA3 vs User-Agent ---------------------------------------------
    rows = []
    for j, s in sorted(ja3_stats.items(), key=lambda kv: -kv[1]["requests"]):
        fams = s["families"]
        browser_claims = sum(v for k, v in fams.items() if k in BROWSER_FAMILIES)
        tool_claims = sum(v for k, v in fams.items() if k.startswith("tool:"))
        rows.append([j, s["requests"], len(s["ips"]), len(fams), len(s["uas"]),
                     "%.1f" % (100.0 * browser_claims / s["requests"]), "%.1f" % (100.0 * tool_claims / s["requests"]),
                     "|".join("%s:%d" % kv for kv in fams.most_common(5))])
    write_csv(out, "9_ja3_vs_user_agent.csv",
              ["ja3", "requests", "distinct_clients", "ua_families", "distinct_user_agents",
               "pct_claiming_browser", "pct_declared_tool", "top_ua_families"], rows)
    rows = []
    for fam, s in sorted(fam_ja3.items(), key=lambda kv: -kv[1]["requests"]):
        if not s["requests"]:
            continue
        shared = sum(1 for j in s["ja3"] if any(k.startswith("tool:") for k in ja3_stats[j]["families"]))
        rows.append([fam, "yes" if fam in BROWSER_FAMILIES else "", s["requests"], s["no_ja3"], len(s["ja3"]),
                     shared, "|".join("%s:%d" % (j[:12], n) for j, n in s["ja3"].most_common(3))])
    write_csv(out, "10_ua_family_vs_ja3.csv",
              ["ua_family", "claims_browser", "https_requests", "https_requests_without_ja3", "distinct_ja3",
               "ja3_also_seen_with_declared_tools", "top_ja3"], rows)

    # --- 11 path-set groups (possible campaigns) -------------------------------
    groups = defaultdict(list)
    for iid, cl in enumerate(clients):
        if cl["path_cap_hit"]:
            continue
        ps = sorted(p for p in cl["paths"] if p.lower() not in TRIVIAL_PATHS)
        if len(ps) < MIN_GROUP_PATHS:
            continue
        sig = hashlib.sha1("\n".join(ps).encode("utf-8", "replace")).hexdigest()[:12]
        groups[sig].append(iid)
    group_rows = []
    for sig, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(members) < MIN_GROUP_CLIENTS:
            continue
        cl0 = clients[members[0]]
        ps = sorted(p for p in cl0["paths"] if p.lower() not in TRIVIAL_PATHS)
        orgs = Counter(clients[m]["orgs"].most_common(1)[0][0] for m in members)
        asns = Counter(clients[m]["asn"].most_common(1)[0][0] for m in members)
        fams = Counter(clients[m]["fam"].most_common(1)[0][0] for m in members)
        countries = set(clients[m]["country"].most_common(1)[0][0] for m in members)
        group_rows.append([sig, len(members), sum(clients[m]["requests"] for m in members), len(ps),
                     " ".join(ps[:10])[:400], len(orgs), "|".join("%s:%d" % kv for kv in orgs.most_common(3)),
                     "|".join("%s:%d" % kv for kv in asns.most_common()), len(countries),
                     "|".join("%s:%d" % kv for kv in fams.most_common(3))])
    write_csv(out, "11_path_set_groups.csv",
              ["group", "clients", "requests", "paths_in_set", "sample_paths", "distinct_orgs", "top_orgs",
               "asn_types", "countries", "top_ua_families"], group_rows)

    # --- 12 timestamp resolution ------------------------------------------------
    write_csv(out, "12_timestamp_resolution.csv", ["metric", "value"], [
        ["requests sharing the same second with the client's previous request", same_second_req],
        ["pct of all requests", "%.2f" % (100.0 * same_second_req / good_rows)],
        ["clients with at least one same-second pair", same_second_ips],
        ["pct of clients", "%.2f" % (100.0 * same_second_ips / len(clients))],
    ])

    # --- 0 summary --------------------------------------------------------------
    pos_all = [d for v in type_delays.values() for d in v if d >= 0]
    n, p10, med, p90 = quantiles(pos_all)
    summary = [
        "Data file: %s" % os.path.abspath(args.data_file),
        "Rows: %d (unparseable timestamps: %d, rows with fewer columns than the header: %d)" % (n_rows, bad_ts, short_rows),
        "Time range (treated as UTC): %s to %s" % (fmt_ts(tmin), fmt_ts(tmax)),
        "Hosts: %d | client IPs: %d | certificate types: %d" % (len(hosts), len(clients), len(types)),
        "Hosts without cert_reg_ts: %d | hosts first requested BEFORE cert registration: %d" % (no_cert, before_cert),
        "Time from cert registration to first request (hosts with delay >= 0, n=%d): p10 %s h, median %s h, p90 %s h"
        % (n, hours(p10), hours(med), hours(p90)),
        "Sessions: %d (gap %d s)" % (len(session_rows), SESSION_GAP_S),
        "Requests sharing a second with the same client's previous request: %.2f%%" % (100.0 * same_second_req / good_rows),
        "Path-set groups with >= %d clients: %d" % (MIN_GROUP_CLIENTS, len(group_rows)),
        "",
        "Assumptions:",
        "- Timestamps have no time zone in the file; both columns are treated as UTC on the same clock.",
        "- A first request before cert registration usually means a clock/time-zone mismatch or discovery",
        "  through another channel; check those hosts by hand before using the delays.",
        "- JA3 exists only for HTTPS requests. Pattern rules and User-Agent families are heuristics.",
        "- Client IPs are %s." % ("kept as-is (--keep-ips)" if args.keep_ips else
                                  "pseudonymised (%s key)" % ("stable, from CTPOT_PSEUDO_KEY" if pseudo.stable else "random per-run")),
    ]
    with open(os.path.join(out, "0_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n")
    print("\n".join(summary), file=sys.stderr)

    # --- charts -------------------------------------------------------------------
    asn_rows = top["asn_type"].most_common(12)
    org_rows = sorted(((v, len(s)) for v, s in top_ips["org"].items()), key=lambda kv: -kv[1])[:15]
    make_charts(out, daily, type_delays, asn_rows, org_rows, pattern_req)
    print("\nResults written to %s" % os.path.abspath(out), file=sys.stderr)


if __name__ == "__main__":
    main()
