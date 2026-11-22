# Requirements

One file per area, each a table in this format. Every requirement has a source and a way to verify it.

| ID | Requirement | Rationale | Source | Priority (MoSCoW) | Verification |
|---|---|---|---|---|---|
| LOG-F-01 | *e.g. Every inbound HTTP request is recorded, including malformed requests and requests without a Host header.* | | *task description; log analysis; literature* | Must | *playground scanner actor sends such requests; check access.json* |

ID scheme: `<AREA>-<F|NF>-<nn>`, e.g. `LOG-F-03` (functional), `LOG-NF-02` (non-functional),
`TOK-F-01` (honeytokens). Areas: LOG, TOK, NODE, PIPE, SEC, LEGAL, EVAL.

Files:
- `logging.md`: request logging granularity
