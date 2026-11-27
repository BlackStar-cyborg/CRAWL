# 0002: How the first node is deployed (setup v2, token tooling)

- **Status:** proposed
- **Date:** 2026-11-26
- **Deciders:** team 
- **Design topic:** #2 domains/TLS · #3 server/banners · #4 logging · #5 tokens · #6 reproducibility

## Context
The pilot node (setup v1) logged requests but held no tokens. The playground has a token builder,
registry and matcher. To start measuring, both have to come together on the real node without
putting the registry or secret on it, and with choices that do not bias the measurement.

## Options considered
1. **Run the playground Docker setup on the node.** Same code, but the registry/secret would sit on
   the internet-facing host, and Docker adds a layer between nginx and the network.
2. **nginx from Ubuntu on the node, all token logic on the laptop** (build, register, upload with
   rsync, pull logs, match offline).
3. **A web application (e.g. Flask) that issues tokens dynamically.** Flexible, but more attack
   surface and harder to show that tokens were fixed in advance.

## Decision
Option 2, kept together in `pilot/`: `pilot/node/setup-node.sh` (v2), `pilot/node/deploy-site.sh`,
`pilot/node/pull-logs.sh`, `pilot/tools/`.
Details that are experimental variables or affect validity:

| Choice | Value | Why |
|---|---|---|
| Token length | 64 bits | 40 bits (playground) is in reach of large-scale guessing; enumeration is measured separately |
| TTFR base | `exposed_utc` (upload time) | build time can be days earlier |
| Controls | 2 negative + 2 positive per deployment | detect leaks / verify the pipeline |
| Pre-registration | SHA-256 of the token list, before upload | shows tokens were not assigned after the fact |
| `/docs/*` response | same landing page (200) for real and guessed tokens | the response must not reveal which tokens exist |
| Header logging | all request headers in arrival order (njs) | header order fingerprints clients |
| `Server` banner | `nginx` without version (`server_tokens off`) | as in the playground; a banner experiment is a later decision |
| `Cache-Control` | `no-store` | every re-fetch reaches the log |
| `Referrer-Policy` | `same-origin` | internal Referer kept (which page led to a token); none sent to other sites |
| HTTP → HTTPS redirect | none | both channels stay observable |
| HTTPS on the bare IP | handshake refused (`TLS_ON_IP=reject`) | IP scanners do not learn the domain from the certificate |
| Certificate timing | after the tokens are live (`CERT=later`) | CT-driven visitors find the tokens; issue/renewal times recorded |
| Sitemap | none | would flatten the depth variable |

## Rationale and evidence
Pilot logs (n01, Nov 2026); playground exercises; attribution notes (carrier vs. token, controls,
pre-registration); Let's Encrypt / Certificate Transparency documentation.

## Consequences
- A teammate can rebuild the node from `pilot/` (runbook in `pilot/README.md`). Parts that prove
  themselves can later move to `src/` and `infra/`.
- The laptop's `data/<node>/state/` becomes critical and must be backed up.
- The log format changed from v1 (`access.json.log`, `remote_addr`) to v2 (`requests.json.log`,
  `client_ip`, + headers/TLS fields). The matcher reads both.
- To revisit: banner, TLS on IP, token density per placement, number of nodes.
