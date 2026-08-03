# Agent instructions — selfsight

This file is git-tracked and public. Keep private details — hostnames,
private repositories, internal tooling — out of it and out of every other
tracked file.

## Repo-local overrides of global rules

- README.md, REQUIREMENTS.md, PLAN.md, DESIGN.md, SECURITY.md, and AGENTS.md
  (with its CLAUDE.md symlink) are **git-tracked in this repo**. The repo
  `.gitignore` un-ignores them, overriding any global keep-untracked rule.
  Commit changes to them like any other file. MEMORY.md stays untracked.

## Hard rules

- **Never write to an AP without a fresh backup** taken immediately before.
- **Fleet writes and upgrades are strictly sequential** — one device at a
  time, never parallel. The server enforces this now rather than trusting
  callers: every operation that writes to an access point claims a single
  fleet-wide slot first (`beginWrite` in `internal/api`), and upgrades and
  ordinary writes lock each other out. Keep any new write behind that claim.
- **Never trust a write response.** Success means the change is visible on
  read-back, not that the AP said OK.
- **No secrets in this repository, ever** — including test fixtures and git
  history. Real IPs, SSIDs, MACs, and serials count as secrets here. Raw
  captures are sanitized *before* they enter the repo (see DESIGN.md,
  "Testing and fixtures").
- **Do not push to any remote.** The repo is structured push-ready, but
  pushing requires the maintainer's explicit go-ahead.

## Task tiers for coding agents

- **Green — do freely:** scaffolding, config loading, REST handlers, the
  React UI, Dockerfiles, docs, and any driver code written against the
  committed `testdata/` fixtures ("make the tests pass" work).
- **Yellow — do, but the maintainer reviews before commit:** the sanitizer
  and *every* sanitized fixture (git history is permanent), changes to the
  apply pipeline or session-handling code, protocol claims in DESIGN.md.
- **Red — only with the maintainer explicitly in the loop:** anything that
  talks to a live access point (read-only included), and every configuration
  write. If a fixture disagrees with a live device, stop and re-capture;
  never patch code toward a guess.

## Orientation

- README.md — public landing page. REQUIREMENTS.md — goal and scope.
  PLAN.md — build approach and status. DESIGN.md — architecture, protocol
  notes, examples, FAQ. SECURITY.md — how to report a problem, how to deploy
  safely, and which risks are accepted on purpose. All living documents; keep
  them current.
- Tasks and milestones are tracked in the maintainer's tracker, not in the
  docs.
- Deployment automation (real inventory and credentials) lives in a
  separate private repository, never here.
