# CRAWL
Master Project @UZH

**CRAWL: Counter-Reconnaissance & AI-Web-Crawler Laboratory.** A testbed of web servers on several
public IP addresses, seeded with uniquely salted honeytokens, to observe and attribute how web
crawlers, vulnerability scanners and AI data-collection pipelines discover and use exposed content.

Communication Systems Group (CSG), Department of Informatics, University of Zurich.
Supervisors: Andy Aidoo, Thomas Grübl, Prof. Dr. Burkhard Stiller. Sept 2026 – Sept 2027.

## Repository layout

| Folder | What goes there |
|---|---|
| `playground/` | Local Docker lab for learning and first experiments. **Not the real testbed.** Start here. |
| `docs/` | Design notes, requirements, decision records, meeting notes |
| `analysis/` | Scripts that analyse logs and datasets (e.g. `ctpot_survey.py`) |
| `src/` | The CRAWL prototype components, once the design is settled (empty for now) |
| `infra/` | Deployment of the real nodes (later: provisioning, configuration management) |
| `data/` | Local data only. **Its contents are never committed** (see below) |

## Ground rules

1. **No data in git.** Real logs, IP addresses, datasets, packet captures, token secrets and
   pseudonymisation keys stay out of the repo. `.gitignore` blocks the usual file types; check
   `git status` before every commit anyway. If something slips in, tell the team. Removing it
   needs a history rewrite, not just a new commit.
2. **Scan only what we own.** Scanners and crawlers in the playground run on an internal Docker
   network. Never point them at hosts outside the lab.
3. **Nothing goes publicly online without supervisor approval** (data protection: IP addresses
   in logs are personal data).
4. **Decisions are written down** in `docs/decisions/` (one short file per decision). These become
   the "discussion of design choices" in the report.
5. **Work in branches, merge through pull requests**, each reviewed by one teammate.

## Getting started

```bash
git clone https://github.com/BlackStar-cyborg/CRAWL.git
cd CRAWL/playground
make up        # build the decoy site, start nginx on http://localhost:8080
make traffic   # run the simulated visitors
make match     # which honeytokens were resolved, by whom, how fast
```

Requirements: Docker (Docker Desktop, Colima or OrbStack on macOS) and `make`.
Details and exercises: [`playground/README.md`](playground/README.md).
