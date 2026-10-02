# 0002. What "ready" means, and what it cannot mean

**Status:** accepted

## Decision

A domain is ready for a stricter policy when the reports span at least 7
days, cover at least 100 messages, and the share of messages failing for a
fixable reason (ADR 1) is at most 0.5%. All three are options.

The next step follows from the published policy: `none` to `quarantine`,
`quarantine` to `reject`, and a `pct` below 100 is raised first.

## Reasoning

- **Seven days** because daily reports hide the weekly job and the Monday
  newsletter. It does not cover a quarterly statement run, and the output
  says how many days it saw so the reader can judge.
- **A share, not zero**, because a rule of "no fixable failures" is never
  met by a domain of any size, and a rule nobody can meet gets switched off.
  0.5% is a starting point. It is not derived from a standard, and the flag
  exists because the right figure depends on what a lost message costs.
- **A floor on volume**, because a domain with 12 messages and no failures
  has shown nothing.

## What "ready" cannot mean

The reports describe mail that reached a receiver which sends reports.
They do not show mail to receivers that send none, and they cannot show a
sender who is silent for the whole window. "Ready" means *the evidence
supplied shows no problem*, not that the change is safe.
