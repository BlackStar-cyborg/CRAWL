# analysis/

Scripts that analyse real logs and datasets. They read from `data/` (git-ignored) and write their
results outside the repo or into git-ignored `*_out/` folders.

| Script | What it does |
|---|---|
| `ctpot_survey.py` | Survey of the CTPOT dataset ("Uninvited Guests", USENIX Security 2022): time from certificate registration to first request, sessions, JA3 vs. User-Agent, path-set groups, timestamp resolution. Standard library only; charts need matplotlib. |
| `log_survey.py` | *(to add)* First-look survey of Apache/nginx access logs (common/combined format). |

Pseudonymised outputs: set `CTPOT_PSEUDO_KEY` (or the equivalent for each script) to a shared
secret so pseudonyms stay stable across runs. Never commit that secret.
