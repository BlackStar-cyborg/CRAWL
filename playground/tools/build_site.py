#!/usr/bin/env python3
"""Token generator + content builder for the playground (standard library only).

Plays two roles of the CRAWL component map at once:
  * token generator / registry: one salted token per placement, written to state/registry.sqlite
  * content builder: a small believable website with the tokens planted in it

Placements (one token each, times --per-placement):
  hidden_link       index page, <a> hidden with CSS                 depth 0
  html_comment      index page, URL only inside an HTML comment      depth 0
  visible_link      normal links at depth 1, 2 and 3
  robots_disallow   URL only listed as Disallow in robots.txt
  behind_disallow   link on /archive/, which robots.txt disallows    depth 1
  pdf_body_text     URL printed in the text of a PDF
  pdf_link          URL only in a PDF link annotation (text says "click here")
  pdf_metadata      URL only in the PDF metadata (Subject)

Run inside the lab (docker compose does this) or locally:
    python3 build_site.py --out ../site --state ../state
"""

import argparse
import csv
import html
import os
import shutil
from datetime import datetime, timezone

from lab_common import load_secret, make_token, open_registry, utc_now_iso
from minipdf import make_pdf

SLUGS = ["annual-report", "staff-directory", "research-data", "project-budget", "meeting-minutes",
         "internal-wiki", "grant-proposal", "lab-inventory", "student-list", "server-notes"]


def page(title, body):
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s</title>"
            "<style>body{font-family:sans-serif;max-width:760px;margin:2em auto;line-height:1.5}"
            "nav a{margin-right:1em}</style></head><body>\n"
            "<nav><a href=\"/\">Home</a><a href=\"/research/\">Research</a><a href=\"/about.html\">About</a></nav>\n"
            "<h1>%s</h1>\n%s\n</body></html>\n") % (html.escape(title), html.escape(title), body)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="/site", help="web root to (re)build")
    ap.add_argument("--state", default=os.environ.get("CRAWL_STATE_DIR", "/state"), help="registry + secret folder")
    ap.add_argument("--base-url", default=os.environ.get("CRAWL_BASE_URL", "http://www.crawl-lab.test"),
                    help="absolute URL used inside PDFs")
    ap.add_argument("--node", default=os.environ.get("CRAWL_NODE", "node-a"))
    ap.add_argument("--deployment", default=os.environ.get("CRAWL_DEPLOYMENT") or
                    "pg-" + datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    help="deployment window id; same id = same tokens")
    ap.add_argument("--per-placement", type=int, default=1, help="token density: tokens per placement")
    args = ap.parse_args()

    secret = load_secret(args.state)
    con = open_registry(args.state)
    now = utc_now_iso()
    # retire tokens of earlier deployments on this node
    con.execute("UPDATE tokens SET retired_utc=? WHERE node=? AND deployment<>? AND retired_utc IS NULL",
                (now, args.node, args.deployment))

    os.makedirs(args.out, exist_ok=True)
    for name in os.listdir(args.out):              # rebuild the web root from scratch
        if name == ".gitkeep":
            continue
        p = os.path.join(args.out, name)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)

    slug_i = [0]
    tokens = {}

    def plant(placement, depth, doc_type, location):
        urls = []
        for i in range(args.per_placement):
            tok = make_token(secret, args.node, args.deployment, placement, depth, doc_type, i)
            slug = SLUGS[slug_i[0] % len(SLUGS)]
            slug_i[0] += 1
            url_path = "/docs/%s-%s.html" % (slug, tok)
            con.execute("INSERT OR IGNORE INTO tokens VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                        (tok, args.node, args.deployment, placement, depth, doc_type, location, url_path, now))
            urls.append(url_path)
        tokens.setdefault(placement, []).extend(urls)
        return urls

    def write(rel, text):
        path = os.path.join(args.out, rel.lstrip("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    # --- index (depth 0): hidden link + HTML comment ---------------------------------------
    hidden = plant("hidden_link", 0, "html", "/index.html")
    comment = plant("html_comment", 0, "html", "/index.html")
    body = ["<p>Welcome to the website of the (fictional) Institute for Applied Crawling.</p>",
            "<ul>",
            "<li><a href=\"/research/\">Research projects</a></li>",
            "<li><a href=\"/files/annual-report-2019.pdf\">Annual report 2019 (PDF)</a></li>",
            "<li><a href=\"/files/project-summary.pdf\">Project summary (PDF)</a></li>",
            "<li><a href=\"/files/data-sheet.pdf\">Data sheet (PDF)</a></li>",
            "</ul>"]
    body += ["<a href=\"%s\" style=\"display:none\" aria-hidden=\"true\" tabindex=\"-1\">internal</a>" % u for u in hidden]
    body += ["<!-- TODO remove before go-live: %s -->" % u for u in comment]
    write("/index.html", page("Institute for Applied Crawling", "\n".join(body)))
    write("/about.html", page("About us", "<p>We study how machines read the web. Contact: office@crawl-lab.test</p>"))

    # --- depth 1..3: visible links -------------------------------------------------------
    chain = [("/research/index.html", "Research", "/research/projects/"),
             ("/research/projects/index.html", "Projects", "/research/projects/2019/"),
             ("/research/projects/2019/index.html", "Projects 2019", None)]
    for depth, (loc, title, nxt) in enumerate(chain, 1):
        urls = plant("visible_link", depth, "html", loc)
        items = ["<li><a href=\"%s\">%s</a></li>" % (u, "Project document %d" % (k + 1)) for k, u in enumerate(urls)]
        if nxt:
            items.append("<li><a href=\"%s\">More</a></li>" % nxt)
        write(loc, page(title, "<ul>\n%s\n</ul>" % "\n".join(items)))

    # --- robots.txt: /archive/ disallowed + robots-only token -------------------------------
    robots_only = plant("robots_disallow", 0, "robots", "/robots.txt")
    behind = plant("behind_disallow", 1, "html", "/archive/index.html")
    write("/robots.txt", "User-agent: *\nDisallow: /archive/\n%s\n" % "\n".join("Disallow: %s" % u for u in robots_only))
    write("/archive/index.html", page("Archive", "<ul>\n%s\n</ul>" % "\n".join(
        "<li><a href=\"%s\">Old document</a></li>" % u for u in behind)))

    # --- PDFs ------------------------------------------------------------------------------
    os.makedirs(os.path.join(args.out, "files"), exist_ok=True)
    body_urls = plant("pdf_body_text", 1, "pdf", "/files/annual-report-2019.pdf")
    make_pdf(os.path.join(args.out, "files/annual-report-2019.pdf"), "Annual Report 2019",
             ["This report summarises the institute's activities in 2019.",
              "The full data appendix is available at:"] + [args.base_url + u for u in body_urls],
             metadata={"Title": "Annual Report 2019", "Author": "Institute for Applied Crawling"})
    link_urls = plant("pdf_link", 1, "pdf", "/files/project-summary.pdf")
    make_pdf(os.path.join(args.out, "files/project-summary.pdf"), "Project Summary",
             ["Short summary of our current projects.", "Click here for the detailed project plan."],
             link_url=args.base_url + link_urls[0], link_line=1,
             metadata={"Title": "Project Summary", "Author": "Institute for Applied Crawling"})
    meta_urls = plant("pdf_metadata", 1, "pdf", "/files/data-sheet.pdf")
    make_pdf(os.path.join(args.out, "files/data-sheet.pdf"), "Data Sheet",
             ["Measurement setup and data formats."],
             metadata={"Title": "Data Sheet", "Author": "Institute for Applied Crawling",
                       "Subject": "Source: " + args.base_url + meta_urls[0]})

    # --- landing page for every /docs/* request (nginx falls back to it) --------------------
    write("/decoy.html", page("Document", "<p>This document has moved.</p><ul>"
                                          "<li><a href=\"/research/\">Research overview</a></li>"
                                          "<li><a href=\"/files/annual-report-2019.pdf\">Annual report</a></li>"
                                          "<li><a href=\"/about.html\">Contact</a></li></ul>"))
    con.commit()

    # human-readable copy of the registry (git-ignored, like everything in state/)
    rows = con.execute("SELECT * FROM tokens ORDER BY created_utc, placement, depth").fetchall()
    with open(os.path.join(args.state, "registry.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(rows[0].keys() if rows else [])
        w.writerows([tuple(r) for r in rows])

    live = [r for r in rows if r["deployment"] == args.deployment and r["node"] == args.node]
    print("Built site in %s  (node %s, deployment %s)" % (args.out, args.node, args.deployment))
    print("%d live tokens:" % len(live))
    for r in live:
        print("  %-16s depth %d  %-5s  in %-34s -> %s" % (r["placement"], r["depth"], r["doc_type"], r["location"], r["url_path"]))


if __name__ == "__main__":
    main()
