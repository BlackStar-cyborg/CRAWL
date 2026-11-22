# Playground

A small, self-contained lab on your own laptop for learning and first experiments.
It is **not** the CRAWL testbed: nothing here is reachable from the internet, and the "visitors"
are scripts we wrote. Break it, change it, rebuild it.

## What runs

```
           internal Docker network "lab" (no internet)  172.30.0.0/24
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  polite   .101 ─┐                                                         │
 │  rude     .102 ─┤                                                         │
 │  scanner  .103 ─┼──► web  .10  nginx ──► logs/nginx/access.json           │
 │  fakebot  .104 ─┤    (apache .11)          access.combined.log            │
 │  resolver .105 ─┘                          access.common.log              │
 └───────────────────────────────────────────────────────────────────────────┘
   builder: writes site/ + state/registry.sqlite      matcher: logs + registry ─► logs/analysis/
```

| Piece | Role in the CRAWL component map | Files |
|---|---|---|
| `builder` | token generator + registry + content builder | `tools/build_site.py`, `tools/minipdf.py`, `tools/lab_common.py` |
| `web` (nginx) | web server + request logger, three log formats at once | `nginx/nginx.conf`, `nginx/headers.js` |
| `apache` (optional) | second web server for the banner exercise | `apache/httpd.conf` |
| `polite`, `rude`, `scanner`, `fakebot`, `resolver` | simulated visitors, each with its own IP | `tools/traffic.py` |
| `matcher` | enrich & match + a bit of analysis | `tools/match_tokens.py` |

The simulated visitors:

| Actor | Behaviour |
|---|---|
| `polite` | Own bot User-Agent, reads and obeys robots.txt, follows links, downloads PDFs but does not read them |
| `rude` | Pretends to be Chrome, ignores robots.txt (even visits what it disallows), reads HTML comments, extracts URLs from PDFs. PDF URLs are only *harvested*, not requested |
| `resolver` | A different machine that later requests the harvested URLs and browses a little: harvest and resolution come from different IPs, as in the task description |
| `scanner` | Probes /.env, /wp-login.php, /.git/config ..., sends a Log4Shell-style payload in a header, a request without Host header, a TLS handshake to the HTTP port, a log-injection attempt |
| `fakebot` | Claims to be Googlebot from a non-Google address |

Every actor writes what it actually did to `logs/ground_truth.jsonl`, so you can compare the logs
against the truth.

Planted tokens (one each by default): hidden link, HTML comment, visible links at depth 1–3,
robots.txt-only, behind a disallowed path, PDF body text, PDF link annotation, PDF metadata.

## Requirements

- Docker with Compose v2 (Docker Desktop, Colima or OrbStack on macOS)
- `make` (preinstalled on macOS/Linux; on Windows run the `docker compose` commands below directly)

## Run it

```bash
cd playground
make up        # build site + tokens, start nginx  -> open http://localhost:8080
make traffic   # run all visitors once (polite, rude, scanner, fakebot, resolver)
make match     # report: which tokens were resolved, by whom, how fast; CSVs in logs/analysis/
make logs      # watch the JSON log live (Ctrl-C to stop)
make down      # stop
make reset     # stop and delete logs, generated site, registry and token secret
```

Without make:

```bash
docker compose run --rm builder
docker compose up -d web
docker compose run --rm polite      # ... rude, scanner, fakebot, resolver
docker compose run --rm matcher
docker compose --profile banner up -d apache     # optional, http://localhost:8081
```

Rebuilding the site with the same deployment id keeps the same tokens. A new deployment window:
`docker compose run --rm -e CRAWL_DEPLOYMENT=pg-week2 builder` (older tokens are marked retired).
More tokens per placement (token density): add `--per-placement 3` to the builder command.

## Where to look

| File | What |
|---|---|
| `logs/nginx/access.json` | One JSON object per request, incl. all headers in arrival order (`headers`) |
| `logs/nginx/access.combined.log` / `access.common.log` | The same requests in the classic Apache formats |
| `logs/ground_truth.jsonl` | What the actors really did |
| `logs/harvested_urls.jsonl` | URLs the rude crawler pulled out of PDFs |
| `state/registry.csv` | All tokens with placement, depth, document type, deployment |
| `logs/analysis/*.csv` | Matcher output: tokens, sessions after token access, clients |
| `site/` | The generated website; open the PDFs in a text editor to see where the tokens sit |

Querying the JSON log with DuckDB (optional, `brew install duckdb`):

```sql
SELECT client_ip, user_agent, count(*) AS n, count(*) FILTER (WHERE status = '404') AS n404
FROM read_json_auto('logs/nginx/access.json') GROUP BY ALL ORDER BY n DESC;
```

## Exercises

Each one produces evidence for a design decision. Write findings down in `docs/` (requirements or
decision records).

1. **Blind log.** One person changes the actors (new behaviour, timing, User-Agents) without telling
   the others; another reconstructs from the logs what happened, using first only
   `access.common.log`, then `access.combined.log`, then `access.json`. Compare with
   `ground_truth.jsonl`. What could you no longer tell apart at each level?
   *Input for: logging requirements.*
2. **Honeytoken round trip.** Which placements did each actor find? Did the matcher attribute every
   resolution correctly, including harvester ≠ resolver? Add a placement (e.g. sitemap.xml, a
   DOCX, a compressed PDF) and check which extraction tools find it.
   *Input for: token placement design, registry schema.*
3. **Labelling calibration.** All three label the same clients/sessions independently, then
   compare and write a labelling guide. *(Can also be done on the CTPOT data.)*
4. **Banner disguise.** `make banner`, then compare `curl -I` on :8080 and :8081, their 404 pages,
   and header order. Change `server_tokens` / `ServerTokens` and try to make one look like the other.
   *Input for: banner variable.*
5. **Failure drills.** Stop `web` while traffic runs; fill the disk; send a 5 MB header; look at
   how the log-injection attempt appears in each format. What gets lost or corrupted?
   *Input for: non-functional requirements.*
6. **Extend the lab.** Add a log shipper container and a separate "central store" container;
   add TLS with a self-signed certificate and log TLS details; add a second web node with a
   different robots.txt.

## Known limits

- The actors are simple scripts, not real crawlers: use them to learn the mechanics, not to
  draw conclusions about real-world behaviour.
- Timestamps come from your laptop's clock; containers share it.
- The PDFs are uncompressed so tokens are easy to inspect. Real PDFs usually compress text, which
  changes what naive extractors find (part of exercise 2).
