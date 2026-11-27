# pilot/

The first real CRAWL deployment: one node (n01) with honeytokens, and the laptop-side tools to
build, upload, collect and match. Kept separate from `src/` and `infra/` while it is a pilot;
parts that prove themselves can move there later. Decision record: `docs/decisions/0002-node-deployment.md`.

| Folder | What |
|---|---|
| `node/` | `setup-node.sh` (runs on the node), `deploy-site.sh` and `pull-logs.sh` (run on the laptop) |
| `tools/` | token generator + registry, site builder, log matcher (Python, standard library only) |

The laptop scripts can be called from anywhere inside the repository; they find the repository
root themselves. Data always goes to `data/<node>/` (git-ignored).

Secrets (SSH keys, API tokens, token secrets) never go into this folder.

## What runs where

| Where | What | Files |
|---|---|---|
| Node (Ubuntu 24.04 VPS) | nginx serving the honeytoken site, JSON request log incl. header order, TLS, log rotation | `node/setup-node.sh` |
| Laptop (WSL on Windows) | token generation, registry, site build, upload, log pull, matching | `node/deploy-site.sh`, `node/pull-logs.sh`, `tools/` |

**The token registry and secret never go on the node.** They live in `data/<node>/state/` on the
laptop (git-ignored). Back that folder up (e.g. encrypted to the UZH OneDrive): without it the
tokens in the logs cannot be attributed any more.

Local layout per node (all git-ignored):

```
data/n01/
  state/          registry.sqlite, registry.csv, token_secret.key   <- back up, never share
  site/           the built site, exactly as uploaded
  logs/           copy of the node's /var/log/crawl/ (pull-logs.sh)
  journal/        SSH login journal snapshots (pull-logs.sh)
  internal_ips.txt  our own addresses, excluded from the analysis (deploy-site.sh adds yours)
  match_out/      matcher output (contains raw IPs)
```

## Runbook: first deployment on a node

Assumes SSH works with an alias (`ssh n01`) and the pilot setup (v1) may already be on the node.
Commands marked *laptop* run in WSL from the repository root.

**1. DNS (only with a domain).** At the registrar, create an **A record** for the domain pointing
to the node's IP. No AAAA record unless the node has working IPv6 (Let's Encrypt prefers IPv6
and validation can fail if IPv6 does not answer). Check from the laptop: `dig +short A example.ch` prints the node IP.
In the provider (Infomaniak) firewall, TCP 80 and 443 must be open; Let's Encrypt validates over port 80.

**2. Node setup**, with the domain configured but no certificate yet (*laptop*, then on the node):

```bash
scp pilot/node/setup-node.sh n01:
ssh n01
sudo DOMAIN=example.ch CERT_EMAIL=you@uzh.ch CERT=later bash setup-node.sh
exit        # log out and back in once: your user was added to group adm (needed to read logs)
```

Without a domain: `sudo bash setup-node.sh`. The summary at the end must say
`njs header logging: on` and `Self-test: OK`. Safe to re-run; each run backs up `/etc/nginx` to
`/root/nginx-backup-<time>` and restores it automatically if the new config fails `nginx -t`.

**3. Deploy the site** (*laptop*). Use the address the PDFs should contain:

```bash
bash pilot/node/deploy-site.sh n01 https://example.ch n01-2026-12 you@uzh.ch
# without a domain: bash pilot/node/deploy-site.sh n01 http://<node-ip> n01-2026-12 you@uzh.ch
```

This builds the site, writes the pre-registration hash, uploads, marks the tokens exposed, and
resolves the first positive control. With `https://` before step 4, the positive-control and
robots.txt checks warn that HTTPS does not answer yet. That is expected; step 5 repeats them.

**4. Certificate** (on the node; skip without a domain). Same command as step 2, without `CERT=later`:

```bash
sudo DOMAIN=example.ch CERT_EMAIL=you@uzh.ch bash setup-node.sh
```

It does a staging dry run first (so a DNS/firewall mistake does not burn Let's Encrypt rate limits),
then issues the certificate and switches HTTPS on. Issue time, serial and fingerprint go to
`/var/log/crawl/cert-issued.txt`. That is the start of the Certificate Transparency channel.

**5. Verify** (*laptop*):

```bash
bash pilot/node/deploy-site.sh n01 https://example.ch n01-2026-12 you@uzh.ch   # same id: no new tokens, re-checks over HTTPS
curl -sI https://example.ch/ | head -1           # HTTP/1.1 200 OK
curl -skI https://<node-ip>/ ; echo $?           # fails with a TLS error: expected (see TLS_ON_IP)
bash pilot/node/pull-logs.sh n01
python3 pilot/tools/match_tokens.py --log data/n01/logs/requests.json.log* \
  --state data/n01/state --site data/n01/site --out data/n01/match_out \
  --exclude-ips data/n01/internal_ips.txt
```

Expected: `controls.csv` lists the positive control (from your IP, `internal_ip=yes`) and
**no negative-control hit**. A negative-control hit means a token leaked outside the site
(e.g. a registry copy, a screenshot, a chat). Stop and find out how before continuing.

## Routine

- **Pull logs daily** (`pull-logs.sh`): a dead node then loses at most a day. It never deletes.
- **Match** whenever needed; the matcher reads rotated and `.gz` files and skips duplicates.
- **New deployment window**: run `deploy-site.sh` with a new id. New tokens are generated, the old
  ones are marked retired at go-live, and later hits on them are flagged ("after retirement").
- **Your IP changed** (home, mobile, VPN): run `deploy-site.sh` again with the same id, or add the
  address to `data/n01/internal_ips.txt` yourself. Entries are full addresses, `#` starts a comment.
- Logs on the node rotate daily, are compressed and are never deleted.

## Certificates: do we need one?

Not for the measurement to work: the node serves and logs plain HTTP, on the bare IP and on a
domain. A certificate is needed only for HTTPS on a domain (Let's Encrypt does not issue certificates
for bare IP addresses through this setup), and it is worth having:

- Many crawlers prefer or only use `https://` URLs, so an HTTP-only domain looks abandoned.
- Issuing it publishes the domain in Certificate Transparency logs, which CT-following crawlers and
  scanners watch. That is a discovery channel of its own, so its time is recorded
  (`cert-issued.txt`), and it should happen after the tokens are live (steps 3 and 4 above).
- Renewal is automatic (`certbot.timer`, about 30 days before expiry). Each renewal is a new CT entry;
  a hook appends its time to `cert-issued.txt` and reloads nginx.
- One certificate covers one name here (`example.ch`). `www.example.ch` is not included; give it no
  DNS record, or extend the certbot command.

`TLS_ON_IP=reject` (default) refuses HTTPS handshakes that do not ask for the domain, so IP-range
scanners on port 443 do not learn the domain from the certificate. With `TLS_ON_IP=cert` they get the
domain certificate. Choose deliberately: it decides whether the IP and domain channels stay separate.

## Logs written on the node (`/var/log/crawl/`)

| File | Content |
|---|---|
| `requests.json.log` | one JSON object per request: client IP/port, Host, method, URI, status, timings, TLS version/cipher/SNI, User-Agent, Accept\*, and `headers` = all request headers in arrival order |
| `requests.combined.log` | the same requests in Apache "combined" format (comparable with the TA logs) |
| `acme.json.log` | Let's Encrypt validation requests (kept out of the crawler data) |
| `error.log` | nginx errors (e.g. malformed requests) |
| `cert-issued.txt` | certificate dry-run, issue and renewal times |
| `access.json.log*` | the pilot (setup v1) log; no longer written after v2 |

The node itself makes one request at setup (`127.0.0.1`, user agent `crawl-setup-selftest`), and
`deploy-site.sh` makes two from your laptop (user agent `crawl-positive-control` and a robots.txt
check). All are excluded via `internal_ips.txt`.

## Rollback

On the node: `sudo rsync -a --delete /root/nginx-backup-<time>/ /etc/nginx/ && sudo nginx -t && sudo systemctl restart nginx`.
The web root can always be rebuilt with `deploy-site.sh` (same id = same tokens).

## `tools/`: token generator, registry, site builder, matcher

Production versions of the playground tools (`playground/tools/`), used by
`node/deploy-site.sh`. Same placements as the playground, so results stay comparable.
Standard library only (Python 3.8+). Run them on the laptop, never on a node.

| File | Purpose |
|---|---|
| `common.py` | HMAC token derivation (64-bit tokens), registry schema (SQLite), pre-registration hash |
| `build_site.py` | builds the site with one token per placement, plus negative/positive control tokens |
| `registry.py` | `prereg` (hash before go-live), `mark-exposed` (go-live time), `show`, `positive-urls` |
| `match_tokens.py` | matches node logs against the registry; writes `tokens.csv`, `doc_requests.csv`, `controls.csv`, `sessions_after_token.csv`, `clients.csv` |
| `minipdf.py` | unchanged copy of the playground's PDF writer |

Differences from the playground:

- **Tokens** are 16 hex characters (64 bits), so guessing one is hopeless even for large-scale
  enumeration. The playground's 10 characters (40 bits) are fine offline.
- **Time-to-first-resolution** is measured from `exposed_utc` (when the site went live), not from
  when it was built. `tokens.csv` says which base was used.
- **Harvested by** counts a fetch of the carrier page only while the token was on it (between
  go-live and retirement), so a later deployment's visitors are not credited with old tokens.
- **Every `/docs/` request is classified**: `exact` (a real token), `near_miss` (a real token cut
  short or extended: copy errors, truncating parsers), `enumeration` (a guess matching no token).
- **Controls.** Negative controls are registered but never published: any hit means a leak.
  Positive controls are resolved by us and check the pipeline end to end. Both are evaluated on all
  traffic, before our own IPs are excluded.
- **Pre-registration**: a SHA-256 over the deployment's token list, recorded before go-live.
  It reveals no tokens and can be shared, e.g. in a commit message or an email to the supervisors.
- Neutral site content (`--site-title`), optional `/.well-known/security.txt` with a research contact.
- The matcher reads several files including `.gz`, de-duplicates by `request_id`, and accepts the
  pilot's field name `remote_addr` as well as `client_ip`.

All outputs contain raw IP addresses: write them to `data/` (git-ignored), never into the repo.
