---
name: handoff
description: Generate a handoff document summarising completed work, remaining tasks, and verification status for session continuity or developer review. Use when asked to create a handoff, summarise progress, or prepare for session end.
---

Handoff target: $ARGUMENTS

If no target is provided, summarise all work done in the current session.

## Goal

Produce a clear, actionable handoff document that enables another agent or developer to continue from exactly where work stopped, with no guesswork.

## Procedure

### Step 1 — Gather Context

- Run `git status` to see current state (staged, unstaged, untracked files).
- Run `git diff` to see all pending changes.
- Run `git log --oneline -10` to see recent commit history.
- Read `tasks.md` if it exists for task tracking state.
- Identify the current branch and its purpose.

### Step 2 — Summarise Completed Work

List every change made, grouped by module:

```markdown
## Completed

### <Module Name>
- **File:** `src/<module>/file.ts` — What was done and why.
- **File:** `src/<module>/other.ts` — What was done and why.
```

Include:
- New files created.
- Existing files modified (what changed).
- Files deleted (why).
- Migrations created (if any).

### Step 3 — Summarise Remaining Work

List what was not finished or was discovered during work:

```markdown
## Remaining

- [ ] Task description — why it's incomplete, what's needed to finish.
- [ ] Task description — blockers or decisions needed.
```

Be specific about blockers:
- Missing information or decisions.
- Dependencies not yet available.
- Errors encountered that need investigation.

### Step 4 — Verification Status

Report the current state of all quality gates:

```markdown
## Verification

| Check | Status | Notes |
|---|---|---|
| `npm run typecheck` | Pass / Fail / Not run | Details |
| `npm run lint:check` | Pass / Fail / Not run | Details |
| `npm run test` | Pass / Fail / Not run | X passed, Y failed |
| `npm run test:e2e` | Pass / Fail / Not run | Details |
| Policy scripts | Pass / Fail / Not run | Which ones |
```

### Step 5 — Write the Handoff Document

File: `HANDOFF.md` (project root)

```markdown
# Handoff — <Date> — <Brief Description>

## Branch
`<current-branch-name>`

## Summary
<1-3 sentence overview of the work session>

## Completed
<Step 2 output>

## Remaining
<Step 3 output>

## Verification
<Step 4 output>

## Key Decisions
- Decision made and rationale (if any architectural or design choices were made).

## Files Changed
<List from git status>

## Notes for Next Session
- Specific guidance for whoever picks this up next.
- Known quirks, gotchas, or context that isn't obvious from the code.
```

### Step 6 — Verify the Handoff

Confirm:
- Every changed file is accounted for.
- Remaining tasks are actionable (not vague).
- Verification status is current (run checks if not already done).
- No sensitive information in the handoff document (credentials, tokens).

## Rules

- Always write `HANDOFF.md` to the project root.
- If a previous `HANDOFF.md` exists, archive its content under a dated section or replace it entirely (the latest handoff should always be current).
- Keep the document concise — a developer should be able to read it in under 2 minutes.
- Do not include full file contents in the handoff; reference file paths instead.
