# How this was built

If you arrived here from the commit list, one thing needs saying plainly:
the first public commit is a snapshot, not the start of the work.

This project was built privately, in gated stages, over October 2026, and
published to GitHub as a single initial commit (77,594 insertions across
7,920 files) once the first stage gates had passed. The commits after that
first one are the real working history — audit fixes land as separate
branches and pull requests, and a finding only counts as closed when an
independent reviewer has re-verified the fix on a fresh clone at the
pinned commit.

The contemporaneous record of the private build is a paper trail, not
commits: dated stage reports, gate results, and audit packs, summarised at
https://polyculturemarkets.org/methodology.html — including the fact that
the consolidated specification is still an unratified draft, and what
remains open in it.

Two honest limits, stated up front:

- The reviewers so far have been AI reviewers working independently of the
  code's author. A human code review has not happened yet; it is the
  stated gate before any mainnet use, and nothing here has had a mainnet
  sign-off.
- The history will not be rewritten to look incremental. The audit reports
  and methodology page pin specific commit SHAs; those pins are worth more
  than better-looking optics.
