
#!/usr/bin/env python3
"""
log_survey.py - first-look survey of web server access logs (Apache/nginx
"common" and "combined" format, plain or .gz).
 
Runs entirely locally with the Python standard library only (Python 3.8+).
Nothing is uploaded anywhere.
 
Usage:
    1. Set LOG_DIR and OUT_DIR in the "Settings" block below (one folder with all logs).
    2. python3 log_survey.py
    Optional: python3 log_survey.py --keep-ips      # keep real IPs in the CSVs
    (Paths can still be given on the command line: python3 log_survey.py LOG_DIR OUT_DIR)
 
Every file directly inside LOG_DIR that ends in .log, .log.N (e.g. .log.1) or .gz is read.
The numbered files come from log rotation (logrotate): .log is the current file, .log.1 the
previous one, .log.2.gz and higher are older and compressed. Subfolders are not searched.
 
By default IP addresses are replaced by a per-run pseudonym (ip_xxxxxxxx) and
UUIDs / long hex IDs in paths are masked in all output files, so the results
are safer to keep in notes or share with your group. Use --keep-ips only if you
need the real addresses (e.g. for reverse-DNS checks) and are allowed to.
 
Outputs (CSV, in OUT_DIR):
    1_inventory.csv        one row per file: format, lines, parse failures, time range
    2_app_summary.csv      one row per application: volume, status mix, flagged traffic
    3_top_paths.csv        top paths per application
    3_top_user_agents.csv  top User-Agents per application (combined format only)
    4_ip_summary.csv       one row per client IP: volume, 4xx ratio, apps touched, flags
    5_pattern_counts.csv   how many requests matched each pattern, per application
    6_flagged_samples.csv  a few example lines per pattern (masked) for the report
    7_random_sample.csv    random lines (masked) to label by hand and check the rules
 
The pattern rules are heuristics, not verdicts: a match means "worth a look".
"""
 
import argparse
import csv
import gzip
import hashlib
import hmac
import os
import random
import re
import secrets
import sys
from collections import Counter, defaultdict
from datetime import timezone, datetime, timedelta
 
# ----------------------------------------------------------------------------
# Settings - edit these two paths, then just run:  python3 log_survey.py
# ----------------------------------------------------------------------------
 
LOG_DIR = "2026-09-29-logs-csg-apache2"          # one folder that contains ALL log files
OUT_DIR = "surveyout2"  # where the CSV results are written
 
# Which files in LOG_DIR count as logs: *.log, *.log.1 (rotated, uncompressed),
# *.log.2.gz (rotated, compressed) and any other *.gz
FANOUT_FRACTION = 0.5   # a client touching >= this fraction of all apps counts as "wide fan-out"
MIN_MONTH_REQUESTS = 50  # months with fewer requests are left out of the "% suspicious" chart (too noisy)
 
LOG_FILE_RE = re.compile(r"(\.log(\.\d+)?(\.gz)?|\.gz)$", re.I)
 
# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------
 
# [vhost:port] host ident user [time] "request" status bytes ["referer" "user-agent"]
# The optional leading vhost:port is Apache's "vhost_combined" format (other_vhosts_access.log).
LINE_RE = re.compile(
    r'^(?:(?P<vhost>[^\s:]+:\d+) )?(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
REQ_RE = re.compile(r'^(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>HTTP/\d(?:\.\d)?))?$')
TIME_RE = re.compile(r'^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$')
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
APP_RE = re.compile(r'^(?:access[_\-.]?)?(?P<app>.+?)(?:[_\-.]?access)?\.log(?:\.\d+)?(?:\.gz)?$', re.I)
 
 
def parse_time(s):
    """Parse '16/Sep/2026:00:00:22 +0200' into an aware UTC datetime (locale independent)."""
    m = TIME_RE.match(s)
    if not m:
        return None
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    if mon not in MONTHS:
        return None
    off = timedelta(hours=int(oh), minutes=int(om))
    if sign == "-":
        off = -off
    local = datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                     tzinfo=timezone(off))
    return local.astimezone(timezone.utc)
 
 
def app_name(filename):
    m = APP_RE.match(os.path.basename(filename))
    return m.group("app") if m else os.path.basename(filename)
 
 
def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")
 
 
# ----------------------------------------------------------------------------
# Pattern rules (heuristics - edit freely)
# ----------------------------------------------------------------------------

# paths scanners ask for hoping to find something exposed 
PROBE_PATHS = re.compile(
    r"(?i)(/\.env\b|/\.git(/|$)|/\.svn(/|$)|/\.aws|/\.ssh|/wp-login\.php|/wp-admin|/xmlrpc\.php|"
    r"/phpmyadmin|/pma/|/cgi-bin/|/vendor/phpunit|/boaform|/actuator|/server-status|/\.DS_Store|"
    r"/config\.(php|json|yml)|/backup|\.sql(\.gz)?$|\.bak$|/etc/passwd|/manager/html|/solr/|/jenkins)"
)
# attack strings, mostly checked in the URL and the User-Agent
CVE_PAYLOAD = re.compile(
    r"(?i)(\$\{jndi:|%24%7bjndi|\$\{\$\{|\.\./\.\./|%2e%2e%2f|%2e%2e/|\bunion\b.{0,20}\bselect\b|"
    r"<script|%3cscript|\bwget\b.{0,20}http|\bcurl\b.{0,20}http|/bin/(ba)?sh|\bcmd\.exe\b)"
)
# User-Agent strings that declare themselves as bots, crawlers, scanners, or known security tools
BOT_UA = re.compile(
    r"(?i)(bot\b|crawler|spider|slurp|gptbot|ccbot|claudebot|anthropic|perplexity|bytespider|"
    r"amazonbot|facebookexternalhit|semrush|ahrefs|mj12|petalbot|applebot|zgrab|masscan|nmap|"
    r"censys|shodan|nuclei|nikto|sqlmap|python-requests|go-http-client|curl/|wget/|libwww|okhttp)"
)
SCANNER_UA = re.compile(r"(?i)(zgrab|masscan|nmap|censys|shodan|nuclei|nikto|sqlmap|expanse|netcraft|internet-measurement|leakix)")
# User-Agents of AI companies' crawlers and agents (training, search index, or fetching for a user)
AI_AGENT_UA = re.compile(
    r"(?i)(gptbot|chatgpt-user|chatgpt-agent|oai-searchbot|claudebot|claude-user|claude-searchbot|"
    r"claude-web|anthropic|perplexitybot|perplexity-user|ccbot|bytespider|meta-externalagent|"
    r"meta-externalfetcher|google-extended|amazonbot|applebot-extended|cohere-ai|diffbot|"
    r"mistralai-user|duckassistbot|youbot|ai2bot|timpibot|petalbot)"
)
# subset of the above: fetched live because a human asked the assistant, not a background crawl
AI_USER_FETCH_UA = re.compile(
    r"(?i)(chatgpt-user|chatgpt-agent|claude-user|perplexity-user|meta-externalfetcher|mistralai-user)"
)
# WebDAV methods used by application clients
APP_CLIENT_METHODS = {"PROPFIND", "PROPPATCH", "MKCOL", "REPORT", "MOVE", "COPY", "LOCK", "UNLOCK"}
 
PATTERNS = [
    "declared_bot_ua", "declared_ai_agent_ua", "ai_user_fetch_ua", "scanner_tool_ua", "robots_txt", "probe_path",
    "cve_or_injection_payload", "malformed_non_http", "tls_on_http_port",
    "proxy_probe", "app_client_webdav", "empty_user_agent",
]
 
 
def classify(method, path, proto, raw_req, ua, status):
    """Return the set of pattern names that match one request."""
    hits = set()
    if proto is None and method is None:
        hits.add("malformed_non_http")
        if raw_req.startswith(("\\x16\\x03", "\x16\x03")):
            hits.add("tls_on_http_port")
    if method == "CONNECT" or (path and re.match(r"(?i)^https?://", path)):
        hits.add("proxy_probe")
    if method in APP_CLIENT_METHODS:
        hits.add("app_client_webdav")
    if path:
        if path.split("?")[0].lower() == "/robots.txt":
            hits.add("robots_txt")
        if PROBE_PATHS.search(path):
            hits.add("probe_path")
        if CVE_PAYLOAD.search(path):
            hits.add("cve_or_injection_payload")
    if ua is not None:
        if ua in ("", "-"):
            hits.add("empty_user_agent")
        else:
            if CVE_PAYLOAD.search(ua):
                hits.add("cve_or_injection_payload")
            if SCANNER_UA.search(ua):
                hits.add("scanner_tool_ua")
            if BOT_UA.search(ua):
                hits.add("declared_bot_ua")
            if AI_AGENT_UA.search(ua):
                hits.add("declared_ai_agent_ua")
            if AI_USER_FETCH_UA.search(ua):
                hits.add("ai_user_fetch_ua")
    return hits
 
 
# ----------------------------------------------------------------------------
# Masking
# ----------------------------------------------------------------------------
 
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
FILES_USER_RE = re.compile(r"(/(?:remote\.php/dav/(?:files|uploads|trashbin)|remote\.php/webdav|index\.php/apps/files)/)[^/\s?]+")
 
 
def mask_text(s):
    s = FILES_USER_RE.sub(r"\1<USER>", s)
    s = UUID_RE.sub("<UUID>", s)
    s = HEX_RE.sub("<HEX>", s)
    s = EMAIL_RE.sub("<EMAIL>", s)
    return s
 
 
class Pseudonymizer:
    def __init__(self, keep):
        self.keep = keep
        self.key = secrets.token_bytes(16)  # random per run, never written to disk
        self.cache = {}
 
    def __call__(self, ip):
        if self.keep:
            return ip
        p = self.cache.get(ip)
        if p is None:
            p = "ip_" + hmac.new(self.key, ip.encode(), hashlib.sha256).hexdigest()[:8]
            self.cache[ip] = p
        return p
 
 
# ----------------------------------------------------------------------------
# Main survey
# ----------------------------------------------------------------------------
 
# ----------------------------------------------------------------------------
# Charts (optional: needs matplotlib, `pip install matplotlib`)
# ----------------------------------------------------------------------------
 
# Palette: slots 1 and 2 of a validated categorical palette (colour-blind safe, passes
# contrast on the light surface). Blue = the thing being measured, orange = flagged/suspicious.
C_BLUE, C_ORANGE = "#2a78d6", "#eb6834"
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SUSPICIOUS = {"probe_path", "cve_or_injection_payload", "malformed_non_http", "scanner_tool_ua", "proxy_probe"}
PATTERN_LABELS = {
    "declared_bot_ua": "Declared bot / crawler User-Agent",
    "declared_ai_agent_ua": "Declared AI crawler / agent User-Agent",
    "ai_user_fetch_ua": "AI fetch on behalf of a user (subset of AI agent)", "scanner_tool_ua": "Scanner-tool User-Agent",
    "robots_txt": "robots.txt request", "probe_path": "Probe path (/.env, wp-login, ...)",
    "cve_or_injection_payload": "CVE / injection payload", "malformed_non_http": "Malformed / non-HTTP request",
    "tls_on_http_port": "TLS handshake sent to HTTP port (subset of malformed)", "proxy_probe": "Proxy probe (CONNECT / absolute URL)",
    "app_client_webdav": "WebDAV app client (PROPFIND, ...)", "empty_user_agent": "Empty User-Agent",
}
 
 
def make_charts(out_dir, app_rows, pattern_totals, monthly, ip_points, ua_totals=None):
    """Write PNG charts to out_dir/charts. All inputs are plain aggregates (no raw IPs)."""
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
 
    def hbar(fname, title, labels, values, xlabel, fmt="{:,.0f}", color=C_BLUE, note=None):
        if not labels:
            return
        h = max(2.6, 0.34 * len(labels) + 1.4)
        fig, ax = plt.subplots(figsize=(8.5, h))
        y = list(range(len(labels)))[::-1]
        ax.barh(y, values, color=color, height=0.62)
        ax.set_yticks(y)
        ax.set_yticklabels(labels)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel(xlabel)
        ax.xaxis.set_major_formatter(thousands) if fmt == "{:,.0f}" else None
        vmax = max(values) if values else 1
        for yi, v in zip(y, values):
            ax.text(v + vmax * 0.01, yi, fmt.format(v), va="center", fontsize=9, color=INK)
        ax.set_xlim(0, vmax * 1.12)
        ax.set_title(title)
        if note:
            fig.text(0.01, 0.01, note, fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03 if note else 0, 1, 1))
        fig.savefig(os.path.join(cdir, fname), dpi=160)
        plt.close(fig)
 
    # 1) volume per application
    rows = sorted(app_rows, key=lambda r: -r["requests"])[:20]
    hbar("1_requests_per_app.png", "Requests per application (top %d)" % len(rows),
         [r["app"] for r in rows], [r["requests"] for r in rows], "requests in all log files")
 
    # 2) share of suspicious requests per application (only apps with enough traffic)
    rows = [r for r in app_rows if r["requests"] >= 100 and r["suspicious"] > 0]
    rows = sorted(rows, key=lambda r: -r["suspicious"] / r["requests"])[:20]
    hbar("2_suspicious_share_per_app.png", "Share of suspicious requests per application",
         [r["app"] for r in rows], [100.0 * r["suspicious"] / r["requests"] for r in rows],
         "% of the application's requests", fmt="{:.2f}%",
         note="Suspicious = probe path, CVE/injection payload, malformed non-HTTP, scanner-tool User-Agent, proxy probe. Apps with <100 requests omitted.")
 
    # 3) pattern totals
    items = sorted(pattern_totals.items(), key=lambda kv: -kv[1])
    hbar("3_pattern_counts.png", "Requests matching each pattern (all applications)",
         [PATTERN_LABELS.get(k, k) for k, _ in items], [v for _, v in items], "matching requests")
 
    # 4) requests over time (two stacked panels: volume, suspicious share - never a dual axis)
    months = sorted(m for m in monthly if monthly[m][0] >= MIN_MONTH_REQUESTS)
    if len(months) >= 2:
        tot = [monthly[m][0] for m in months]
        share = [100.0 * monthly[m][1] / monthly[m][0] for m in months]
        fig, (a1, a2) = plt.subplots(2, 1, figsize=(8.5, 5.8), sharex=True, gridspec_kw={"height_ratios": [3, 2]})
        xs = list(range(len(months)))
        a1.plot(xs, tot, color=C_BLUE, linewidth=2)
        a1.yaxis.set_major_formatter(thousands)
        a1.set_ylabel("all requests / month")
        a1.set_title("Traffic over time")
        a2.plot(xs, share, color=C_ORANGE, linewidth=2)
        a2.set_ylabel("suspicious requests, %")
        step = max(1, len(months) // 12)
        a2.set_xticks(xs[::step])
        a2.set_xticklabels(months[::step], rotation=45, ha="right")
        fig.text(0.01, 0.01, "Months are in UTC. Months with fewer than %d requests (often partial first/last months) are omitted."
                 % MIN_MONTH_REQUESTS, fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        fig.savefig(os.path.join(cdir, "4_traffic_over_time.png"), dpi=160)
        plt.close(fig)
 
    # 5) per-IP behaviour: requests vs share of 4xx, flagged candidates in orange
    if ip_points:
        fig, ax = plt.subplots(figsize=(8.5, 5.4))
        norm = [p for p in ip_points if not p[3]]
        cand = [p for p in ip_points if p[3]]
        ax.scatter([p[0] for p in norm], [100 * p[1] for p in norm], s=22, color=C_BLUE, alpha=0.55,
                   edgecolors=SURFACE, linewidths=0.6, marker="o", label="other clients (%d)" % len(norm))
        ax.scatter([p[0] for p in cand], [100 * p[1] for p in cand], s=34, color=C_ORANGE, alpha=0.8,
                   edgecolors=SURFACE, linewidths=0.6, marker="^", label="candidates (%d)" % len(cand))
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(thousands)
        ax.xaxis.set_minor_formatter(FuncFormatter(lambda v, _: "{:,.0f}".format(v) if v in (2, 3, 5, 20, 30, 50, 200, 300, 500, 2000, 3000, 5000) else ""))
        ax.set_xlabel("requests per client IP (log scale)")
        ax.set_ylabel("% of its requests answered with 4xx")
        ax.set_ylim(-3, 103)
        ax.set_title("Client behaviour: volume vs. failed requests")
        ax.legend(frameon=False, loc="center right")
        fig.text(0.01, 0.01, "Each dot is one client IP. Candidate = pattern hits, many 4xx, or wide fan-out across applications (see 4_ip_summary.csv).",
                 fontsize=8, color=INK2)
        fig.tight_layout(rect=(0, 0.03, 1, 1))
        fig.savefig(os.path.join(cdir, "5_clients_volume_vs_4xx.png"), dpi=160)
        plt.close(fig)
 
        # 6) fan-out: how many applications does each client touch?
        fan = Counter(p[2] for p in ip_points)
        ks = sorted(fan)
        fig, ax = plt.subplots(figsize=(8.5, 4.2))
        ax.bar(ks, [fan[k] for k in ks], color=C_BLUE, width=0.62)
        if ks[-1] <= 40:
            ax.set_xticks(range(1, ks[-1] + 1))
        ax.set_yscale("log")
        ax.grid(axis="x", visible=False)
        ax.set_xlabel("number of different applications a client IP contacted")
        ax.set_ylabel("client IPs (log scale)")
        for k in ks:
            ax.text(k, fan[k] * 1.08, "{:,}".format(fan[k]), ha="center", fontsize=8, color=INK)
        ax.set_title("Cross-application fan-out")
        fig.tight_layout()
        fig.savefig(os.path.join(cdir, "6_client_fanout.png"), dpi=160)
        plt.close(fig)

    # 7) top User-Agents across all applications (combined format only; strings are already masked)
    if ua_totals:
        items = ua_totals.most_common(20)

        def ua_label(u):
            if u in ("", "-"):
                return "(empty User-Agent)"
            # keep start and end: browser UAs often differ only in the version at the end
            return u if len(u) <= 65 else u[:32] + " ... " + u[-28:]
        hbar("7_top_user_agents.png", "Top User-Agents, all applications (top %d)" % len(items),
             [ua_label(u) for u, _ in items], [c for _, c in items], "requests",
             note="Combined-format logs only. Long User-Agents are shortened; full strings are in 3_top_user_agents.csv.")
 
    print("Charts written to %s" % cdir, file=sys.stderr)
 
 
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log_dir", nargs="?", default=LOG_DIR, help="folder with all log files (default: LOG_DIR above)")
    ap.add_argument("out_dir", nargs="?", default=OUT_DIR, help="folder for the CSV results (default: OUT_DIR above)")
    ap.add_argument("--keep-ips", action="store_true", help="do not pseudonymize IP addresses in outputs")
    ap.add_argument("--top", type=int, default=20, help="top-N paths / user agents per app (default 20)")
    ap.add_argument("--samples", type=int, default=5, help="example lines per pattern (default 5)")
    ap.add_argument("--random-sample", type=int, default=100, help="random lines for hand-labelling (default 100)")
    ap.add_argument("--seed", type=int, default=1, help="seed for the random sample")
    args = ap.parse_args()
 
    if not os.path.isdir(args.log_dir):
        sys.exit("Log folder not found: %r - set LOG_DIR at the top of the script." % args.log_dir)
    # One fixed folder, no searching: take every file directly inside it that looks like a log
    # (.log, .log.1, .log.2.gz, .gz, ...). Subfolders are not entered.
    files = sorted(
        os.path.join(args.log_dir, n) for n in os.listdir(args.log_dir)
        if os.path.isfile(os.path.join(args.log_dir, n)) and LOG_FILE_RE.search(n)
    )
    if not files:
        sys.exit("No log files (.log, .log.N, .gz) found directly in %s." % args.log_dir)
    os.makedirs(args.out_dir, exist_ok=True)
 
    rng = random.Random(args.seed)
    pseudo = Pseudonymizer(args.keep_ips)
 
    inventory = []
    app_stats = defaultdict(lambda: {
        "requests": 0, "status": Counter(), "methods": Counter(),
        "paths": Counter(), "uas": Counter(), "ips": set(),
        "min": None, "max": None, "formats": set(),
    })
    pattern_counts = defaultdict(Counter)       # app -> pattern -> n
    monthly = defaultdict(lambda: [0, 0])       # "YYYY-MM" -> [all requests, suspicious requests]
    ip_stats = {}
    samples = defaultdict(list)                 # pattern -> list of rows
    sample_seen = Counter()
    reservoir = []                              # random sample for hand labelling
    seen_total = 0
 
    for fi, path in enumerate(files, 1):
        app = app_name(path)
        n = bad = 0
        fmt = Counter()
        tmin = tmax = None
        tzs = Counter()
        try:
            fh = open_log(path)
        except OSError as e:
            print("skip %s: %s" % (path, e), file=sys.stderr)
            continue
        with fh:
            try:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    n += 1
                    m = LINE_RE.match(line)
                    if not m:
                        bad += 1
                        continue
                    ip = m.group("ip")
                    vhost = m.group("vhost")
                    # vhost_combined: one file holds many sites, so use the site name as the app
                    lapp = vhost.rsplit(":", 1)[0].lower() if vhost else app
                    t = parse_time(m.group("time"))
                    tzm = TIME_RE.match(m.group("time"))
                    if tzm:
                        tzs[tzm.group(7) + tzm.group(8) + tzm.group(9)] += 1
                    if t:
                        tmin = t if tmin is None or t < tmin else tmin
                        tmax = t if tmax is None or t > tmax else tmax
                    raw_req = m.group("req")
                    rm = REQ_RE.match(raw_req)
                    method = rm.group("method") if rm else None
                    rpath = rm.group("path") if rm else None
                    proto = rm.group("proto") if rm else None
                    status = int(m.group("status"))
                    ua = m.group("ua")  # None for common format
                    lfmt = "vhost_combined" if vhost else ("combined" if ua is not None else "common")
                    fmt[lfmt] += 1
 
                    s = app_stats[lapp]
                    s["formats"].add(lfmt)
                    s["requests"] += 1
                    s["status"][status // 100] += 1
                    s["methods"][method or "(malformed)"] += 1
                    if rpath:
                        s["paths"][mask_text(rpath.split("?")[0])[:200]] += 1
                    if ua is not None:
                        s["uas"][mask_text(ua)[:200]] += 1
                    s["ips"].add(ip)
                    if t:
                        s["min"] = t if s["min"] is None or t < s["min"] else s["min"]
                        s["max"] = t if s["max"] is None or t > s["max"] else s["max"]
 
                    hits = classify(method, rpath, proto, raw_req, ua, status)
                    for h in hits:
                        pattern_counts[lapp][h] += 1
                    pattern_counts[lapp]["(all requests)"] += 1
                    if t:
                        mk = t.strftime("%Y-%m")
                        monthly[mk][0] += 1
                        if hits & SUSPICIOUS:
                            monthly[mk][1] += 1
 
                    st = ip_stats.get(ip)
                    if st is None:
                        st = ip_stats[ip] = {
                            "requests": 0, "e4xx": 0, "e404": 0, "paths": set(),
                            "apps": set(), "min": None, "max": None, "flags": Counter()}
                    st["requests"] += 1
                    if 400 <= status < 500:
                        st["e4xx"] += 1
                    if status == 404:
                        st["e404"] += 1
                    if rpath and len(st["paths"]) < 500:
                        st["paths"].add(rpath.split("?")[0])
                    st["apps"].add(lapp)
                    if t:
                        st["min"] = t if st["min"] is None or t < st["min"] else st["min"]
                        st["max"] = t if st["max"] is None or t > st["max"] else st["max"]
                    for h in hits:
                        st["flags"][h] += 1
 
                    masked = mask_text(line.replace(ip, pseudo(ip), 1))
                    for h in hits:
                        sample_seen[h] += 1
                        if len(samples[h]) < args.samples:
                            samples[h].append((h, lapp, masked[:400]))
                        else:  # reservoir sampling so examples are spread over the data
                            j = rng.randrange(sample_seen[h])
                            if j < args.samples:
                                samples[h][j] = (h, lapp, masked[:400])
                    seen_total += 1
                    if len(reservoir) < args.random_sample:
                        reservoir.append((lapp, masked[:400]))
                    else:
                        j = rng.randrange(seen_total)
                        if j < args.random_sample:
                            reservoir[j] = (lapp, masked[:400])
            except (OSError, EOFError) as e:
                print("warning: %s ended early (%s)" % (path, e), file=sys.stderr)
 
        inventory.append({
            "file": os.path.relpath(path, args.log_dir), "app": app,
            "format": "+".join(sorted(fmt)) or "(none parsed)", "lines": n, "unparsed_lines": bad,
            "first_utc": tmin.strftime("%Y-%m-%d %H:%M") if tmin else "",
            "last_utc": tmax.strftime("%Y-%m-%d %H:%M") if tmax else "",
            "timezone_offsets": ",".join("%s(%d)" % kv for kv in tzs.most_common(3)),
        })
        print("[%d/%d] %s: %d lines" % (fi, len(files), os.path.basename(path), n), file=sys.stderr)
 
    def write(name, header, rows):
        with open(os.path.join(args.out_dir, name), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
 
    # 1 inventory
    write("1_inventory.csv",
          ["file", "app", "format", "lines", "unparsed_lines", "first_utc", "last_utc", "timezone_offsets"],
          [[r[k] for k in ("file", "app", "format", "lines", "unparsed_lines", "first_utc", "last_utc", "timezone_offsets")]
           for r in inventory])
 
    # 2 app summary
    rows = []
    for app, s in sorted(app_stats.items(), key=lambda kv: -kv[1]["requests"]):
        tot = max(s["requests"], 1)
        pc = pattern_counts[app]
        flagged = sum(v for k, v in pc.items() if k in ("probe_path", "cve_or_injection_payload", "malformed_non_http", "scanner_tool_ua"))
        rows.append([
            app, s["requests"], len(s["ips"]), "+".join(sorted(s["formats"])),
            s["min"].strftime("%Y-%m-%d") if s["min"] else "", s["max"].strftime("%Y-%m-%d") if s["max"] else "",
            *["%.1f" % (100.0 * s["status"].get(c, 0) / tot) for c in (2, 3, 4, 5)],
            ", ".join("%s:%d" % kv for kv in s["methods"].most_common(4)),
            flagged, "%.2f" % (100.0 * flagged / tot),
        ])
    write("2_app_summary.csv",
          ["app", "requests", "distinct_ips", "format", "first_day_utc", "last_day_utc",
           "pct_2xx", "pct_3xx", "pct_4xx", "pct_5xx", "top_methods",
           "suspicious_requests", "suspicious_pct"], rows)
 
    # 3 top paths / user agents
    prow, urow = [], []
    for app, s in app_stats.items():
        for p, c in s["paths"].most_common(args.top):
            prow.append([app, p, c])
        for u, c in s["uas"].most_common(args.top):
            urow.append([app, u, c])
    write("3_top_paths.csv", ["app", "path", "requests"], prow)
    write("3_top_user_agents.csv", ["app", "user_agent", "requests"], urow)
 
    # 4 per-IP summary + simple candidate flag
    irow = []
    ip_points = []   # (requests, share_4xx, apps_touched, is_candidate) for the charts
    # "wide fan-out": a client that touches at least half of all applications (and at least 5).
    # Ordinary users rarely do; sweeping scanners do. Adjust FANOUT_FRACTION to taste.
    fanout_min = max(5, int(round(FANOUT_FRACTION * len(app_stats))))
    for ip, st in ip_stats.items():
        req = st["requests"]
        r4 = st["e4xx"] / req
        suspicious = sum(st["flags"].get(k, 0) for k in
                         ("probe_path", "cve_or_injection_payload", "malformed_non_http", "scanner_tool_ua", "proxy_probe"))
        reasons = []
        if suspicious:
            reasons.append("pattern_hits")
        if req >= 20 and r4 >= 0.5:
            reasons.append("many_4xx")
        if len(st["apps"]) >= fanout_min:
            reasons.append("wide_fanout")
        ip_points.append((req, r4, len(st["apps"]), bool(reasons)))
        dur = (st["max"] - st["min"]).total_seconds() if st["min"] and st["max"] else 0
        irow.append([
            pseudo(ip), req, "%.2f" % r4, st["e404"], len(st["paths"]), len(st["apps"]),
            st["min"].strftime("%Y-%m-%d %H:%M") if st["min"] else "", int(dur),
            suspicious, "|".join("%s:%d" % kv for kv in st["flags"].most_common(5)),
            ";".join(reasons) or "-",
        ])
    irow.sort(key=lambda r: (r[10] == "-", -r[1]))
    write("4_ip_summary.csv",
          ["client", "requests", "share_4xx", "n_404", "distinct_paths", "apps_touched",
           "first_seen_utc", "active_seconds", "suspicious_requests", "top_flags", "candidate_reasons"], irow)
 
    # 5 pattern counts
    crow = []
    for app, pc in pattern_counts.items():
        tot = pc["(all requests)"]
        for pat in PATTERNS:
            if pc.get(pat):
                crow.append([app, pat, pc[pat], "%.3f" % (100.0 * pc[pat] / tot)])
    crow.sort(key=lambda r: (r[0], -r[2]))
    write("5_pattern_counts.csv", ["app", "pattern", "requests", "pct_of_app_requests"], crow)
 
    # 6 flagged samples, 7 random sample
    write("6_flagged_samples.csv", ["pattern", "app", "masked_line"],
          [row for pat in PATTERNS for row in samples.get(pat, [])])
    write("7_random_sample.csv", ["app", "masked_line", "your_label"],
          [[a, l, ""] for a, l in reservoir])
 
    # charts (PNG)
    app_rows = [{"app": a, "requests": s["requests"],
                 "suspicious": sum(v for k, v in pattern_counts[a].items() if k in SUSPICIOUS)}
                for a, s in app_stats.items()]
    pattern_totals = Counter()
    for pc in pattern_counts.values():
        for k, v in pc.items():
            if k in PATTERNS:
                pattern_totals[k] += v
    ua_totals = Counter()
    for s in app_stats.values():
        ua_totals.update(s["uas"])
    make_charts(args.out_dir, app_rows, pattern_totals, monthly, ip_points, ua_totals)
 
    tot_lines = sum(r["lines"] for r in inventory)
    tot_bad = sum(r["unparsed_lines"] for r in inventory)
    print("\nDone: %d files, %d lines (%d unparsed), %d apps, %d client IPs." %
          (len(inventory), tot_lines, tot_bad, len(app_stats), len(ip_stats)), file=sys.stderr)
    print("CSV files written to %s" % os.path.abspath(args.out_dir), file=sys.stderr)
    if tot_bad:
        print("Note: some lines did not match the common/combined format; see 1_inventory.csv "
              "(unparsed_lines) and check those files by hand.", file=sys.stderr)
 
 
if __name__ == "__main__":
    main()

