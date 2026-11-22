# 0001: Record design decisions in the repository

- **Status:** proposed
- **Date:** YYYY-MM-DD
- **Deciders:** team
- **Design topic:** all

## Context
The report must contain "the discussion of the design choices" and "a set of arguments on the final
design choice" (task description, section 6). Decisions are made over months, in meetings and chats,
and the reasons get lost.

## Options considered
1. **One file per decision in `docs/decisions/`**, numbered, reviewed via pull request.
2. **A single running design document.** Easier to read, harder to see when and why something changed.
3. **Nothing formal**, reconstruct when writing the report.

## Decision
To be agreed by the team.

## Rationale and evidence
Option 1 keeps the date, the alternatives and the evidence together and is reviewable like code.

## Consequences
Small overhead per decision; the report's design chapter can be assembled from these files.
