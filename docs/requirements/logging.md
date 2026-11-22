# Requirements: request logging granularity

Status: draft. Owner: Simona.

## Sources used
- Task description (MAP-Taskdescription.pdf): "full-request logging", metrics (time-to-first-resolution,
  session length after token access, resolution frequency per placement), example scenarios.
- Log analysis: university access logs (`analysis/`), CTPOT dataset (`analysis/ctpot_survey.py`).
- Literature (see Background chapter).
- Playground experiments (`playground/`, exercises 1 and 5).

## Functional requirements

| ID | Requirement | Rationale | Source | Priority | Verification |
|---|---|---|---|---|---|
| LOG-F-01 | | | | | |

## Non-functional requirements

| ID | Requirement | Rationale | Source | Priority | Verification |
|---|---|---|---|---|---|
| LOG-NF-01 | | | | | |

## Granularity levels (options, to discuss with supervisors)

| Level | Content | Enables | Cost / risk |
|---|---|---|---|
| L0 | Common log format | | |
| L1 | Combined log format | | |
| L2 | L1 + Host, response time, TLS info, all headers | | |
| L3 | L2 + request bodies (size-capped) | | |
| L4 | + connection-level logs | | |
| L5 | + full packet capture | | |
