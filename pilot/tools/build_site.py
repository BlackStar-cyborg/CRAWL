#!/usr/bin/env python3
"""Token generator + content builder for a real CRAWL node (standard library only).

Based on playground/tools/build_site.py, with the same placements, so playground results and
node results are comparable. Differences for the real deployment:
  * neutral site content (title configurable), no lab names, no ".test" domains
  * --base-url is required: it is the address written into the PDFs
  * 64-bit tokens, control tokens, optional security.txt (see common.py)
  * exposed_utc is NOT set here; deploy-site.sh sets it after the upload succeeded
    (and that step also retires the node's previous deployment)

Placements (one token each, times --per-placement):
  hidden_link       index page, <a> hidden with CSS                 depth 0
  html_comment      index page, URL only inside an HTML comment      depth 0
  visible_link      normal links at depth 1, 2 and 3
  robots_disallow   URL only listed as Disallow in robots.txt
  behind_disallow   link on /archive/, which robots.txt disallows    depth 1
  pdf_body_text     URL printed in the text of a PDF
  pdf_link          URL only in a PDF link annotation (text says "click here")
  pdf_metadata      URL only in the PDF metadata (Subject)
Controls (registered, never placed anywhere on the site):
  negative          must never be requested; a hit means a leak or contamination
  positive          we request these ourselves to check the pipeline end to end

Example:
    python3 pilot/tools/build_site.py --out data/n01/site --state data/n01/state \\
        --node n01 --deployment n01-2026-12 --base-url https://example.ch
"""

import argparse
import csv
import html
import os
import shutil
from datetime import datetime, timedelta, timezone

from common import load_secret, make_token, open_registry, utc_now_iso
from minipdf import make_pdf

BUILD_MARKER = ".crawl-build"   # never uploaded (deploy-site.sh excludes it)

SLUGS = ["annual-report", "staff-directory", "research-data", "project-budget", "meeting-minutes",
         "internal-wiki", "grant-proposal", "lab-inventory", "student-list", "server-notes"]


def page(site_title, title, body):
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s | %s</title>"
            "<style>body{font-family:sans-serif;max-width:760px;margin:2em auto;line-height:1.5}"
            "nav a{margin-right:1em}</style></head><body>\n"
            "<nav><a href=\"/\">Home</a><a href=\"/research/\">Reports</a><a href=\"/about.html\">About</a></nav>\n"
            "<h1>%s</h1>\n%s\n</body></html>\n") % (html.escape(title), html.escape(site_title),
                                                     html.escape(title), body)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="local web root to (re)build, e.g. data/n01/site")
    ap.add_argument("--state", required=True, help="registry + secret folder, e.g. data/n01/state")
    ap.add_argument("--base-url", required=True, help="public address of the node, e.g. https://example.ch")
    ap.add_argument("--node", required=True, help="node id, e.g. n01")
    ap.add_argument("--deployment", required=True, help="deployment window id; same id = same tokens")
    ap.add_argument("--site-title", default="Technical Notes Archive")
    ap.add_argument("--per-placement", type=int, default=1, help="token density: tokens per placement")
    ap.add_argument("--controls", type=int, default=2, help="negative and positive control tokens each")
    ap.add_argument("--contact", help="e-mail for /.well-known/security.txt (recommended)")
    args = ap.parse_args()

    base_url = args.base_url.rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        ap.error("--base-url must start with http:// or https://")
    if args.per_placement < 1 or args.controls < 0:
        ap.error("--per-placement must be >= 1 and --controls >= 0")
    site = args.site_title

    secret = load_secret(args.state)
    con = open_registry(args.state)
    now = utc_now_iso()

    # Rebuild the web root from scratch, but only a folder this script created itself:
    # it is emptied completely, so a wrong --out must never point at anything else.
    marker = os.path.join(args.out, BUILD_MARKER)
    if os.path.isdir(args.out) and os.listdir(args.out) and not os.path.exists(marker):
        ap.error("%s is not empty and was not created by build_site.py; refusing to wipe it" % args.out)
    os.makedirs(args.out, exist_ok=True)
    for name in os.listdir(args.out):
        p = os.path.join(args.out, name)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    with open(marker, "w") as f:
        f.write("built by pilot/tools/build_site.py - this folder is wiped on every build\n")

    def register(placement, depth, doc_type, location, i, control=None):
        tok = make_token(secret, args.node, args.deployment, placement, depth, doc_type, i)
        slug = SLUGS[int(tok[:8], 16) % len(SLUGS)]     # derived from the token: stable across rebuilds
        url_path = "/docs/%s-%s.html" % (slug, tok)
        con.execute("INSERT OR IGNORE INTO tokens (token, node, deployment, placement, depth, doc_type, location, "
                    "url_path, control, created_utc) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (tok, args.node, args.deployment, placement, depth, doc_type, location, url_path, control, now))
        return url_path

    def plant(placement, depth, doc_type, location):
        return [register(placement, depth, doc_type, location, i) for i in range(args.per_placement)]

    def write(rel, text):
        path = os.path.join(args.out, rel.lstrip("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    # --- index (depth 0): hidden link + HTML comment ---------------------------------------
    hidden = plant("hidden_link", 0, "html", "/index.html")
    comment = plant("html_comment", 0, "html", "/index.html")
    body = ["<p>Technical notes, reports and project documents.</p>",
            "<ul>",
            "<li><a href=\"/research/\">Reports</a></li>",
            "<li><a href=\"/files/annual-report-2019.pdf\">Annual report 2019 (PDF)</a></li>",
            "<li><a href=\"/files/project-summary.pdf\">Project summary (PDF)</a></li>",
            "<li><a href=\"/files/data-sheet.pdf\">Data sheet (PDF)</a></li>",
            "</ul>"]
    body += ["<a href=\"%s\" style=\"display:none\" aria-hidden=\"true\" tabindex=\"-1\">internal</a>" % u for u in hidden]
    body += ["<!-- old link, remove: %s -->" % u for u in comment]
    write("/index.html", page(site, site, "\n".join(body)))
    write("/about.html", page(site, "About", "<p>This archive collects technical notes and project documents.</p>"))

    # --- depth 1..3: visible links -------------------------------------------------------
    chain = [("/research/index.html", "Reports", "/research/projects/"),
             ("/research/projects/index.html", "Projects", "/research/projects/2019/"),
             ("/research/projects/2019/index.html", "Projects 2019", None)]
    for depth, (loc, title, nxt) in enumerate(chain, 1):
        urls = plant("visible_link", depth, "html", loc)
        items = ["<li><a href=\"%s\">%s</a></li>" % (u, "Project document %d" % (k + 1)) for k, u in enumerate(urls)]
        if nxt:
            items.append("<li><a href=\"%s\">More</a></li>" % nxt)
        write(loc, page(site, title, "<ul>\n%s\n</ul>" % "\n".join(items)))

    # --- robots.txt: /archive/ disallowed + robots-only token -------------------------------
    robots_only = plant("robots_disallow", 0, "robots", "/robots.txt")
    behind = plant("behind_disallow", 1, "html", "/archive/index.html")
    write("/robots.txt", "User-agent: *\nDisallow: /archive/\n%s\n" % "\n".join("Disallow: %s" % u for u in robots_only))
    write("/archive/index.html", page(site, "Archive", "<ul>\n%s\n</ul>" % "\n".join(
        "<li><a href=\"%s\">Old document</a></li>" % u for u in behind)))

    # --- PDFs ------------------------------------------------------------------------------
    os.makedirs(os.path.join(args.out, "files"), exist_ok=True)
    body_urls = plant("pdf_body_text", 1, "pdf", "/files/annual-report-2019.pdf")
    make_pdf(os.path.join(args.out, "files/annual-report-2019.pdf"), "Annual Report 2019",
             ["This report summarises the group's activities in 2019.",
              "The full data appendix is available at:"] + [base_url + u for u in body_urls],
             metadata={"Title": "Annual Report 2019", "Author": site})
    link_urls = plant("pdf_link", 1, "pdf", "/files/project-summary.pdf")
    make_pdf(os.path.join(args.out, "files/project-summary.pdf"), "Project Summary",
             ["Short summary of current projects.", "Click here for the detailed project plan."],
             link_url=base_url + link_urls[0], link_line=1,
             metadata={"Title": "Project Summary", "Author": site})
    meta_urls = plant("pdf_metadata", 1, "pdf", "/files/data-sheet.pdf")
    make_pdf(os.path.join(args.out, "files/data-sheet.pdf"), "Data Sheet",
             ["Measurement setup and data formats."],
             metadata={"Title": "Data Sheet", "Author": site, "Subject": "Source: " + base_url + meta_urls[0]})

    # --- landing page for every /docs/* request (nginx falls back to it) --------------------
    write("/decoy.html", page(site, "Document", "<p>This document has moved.</p><ul>"
                                                "<li><a href=\"/research/\">Reports</a></li>"
                                                "<li><a href=\"/files/annual-report-2019.pdf\">Annual report</a></li>"
                                                "<li><a href=\"/about.html\">About</a></li></ul>"))

    # --- security.txt (RFC 9116): contact for anyone who wonders what this server is ---------
    if args.contact:
        expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        write("/.well-known/security.txt",
              "Contact: mailto:%s\nExpires: %s\n"
              "Comment: This server is part of a university research measurement. Requests are logged.\n"
              % (args.contact, expires))

    # --- control tokens: registered, never written into the site -----------------------------
    controls = []
    for kind in ("negative", "positive"):
        for i in range(args.controls):
            controls.append((kind, register(kind + "_control", -1, "none", "-", i, control=kind)))

    con.commit()

    # human-readable copy of the registry (git-ignored, like everything in data/)
    rows = con.execute("SELECT * FROM tokens ORDER BY created_utc, placement, depth").fetchall()
    with open(os.path.join(args.state, "registry.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(rows[0].keys() if rows else [])
        w.writerows([tuple(r) for r in rows])

    live = [r for r in rows if r["deployment"] == args.deployment and r["node"] == args.node]
    print("Built site in %s  (node %s, deployment %s, base %s)" % (args.out, args.node, args.deployment, base_url))
    print("%d tokens in this deployment (%d planted, %d controls):" %
          (len(live), sum(1 for r in live if not r["control"]), sum(1 for r in live if r["control"])))
    for r in live:
        if not r["control"]:
            print("  %-16s depth %d  %-6s in %-34s -> %s" % (r["placement"], r["depth"], r["doc_type"],
                                                            r["location"], r["url_path"]))
    print("Positive controls (request these yourself after deploying):")
    for kind, u in controls:
        if kind == "positive":
            print("  " + base_url + u)


if __name__ == "__main__":
    main()
