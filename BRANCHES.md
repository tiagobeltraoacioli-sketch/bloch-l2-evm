# Branch index: the lines pushed on 2026-11-17

Which branch is what, which is audited or reviewed, which is work in progress, and how to verify it.
Tips are those of `origin` at 2026-11-17 04:32 UTC; branches keep moving during the day, so read the current tip with
`git ls-remote origin <branch>`. "Audit candidate" and "fit for external audit" are the verdicts of this
project's own reviewers; no external audit has been done. Nothing on any branch is deployed by being here.

| Branch | Tip | What it is | Status |
|---|---|---|---|
| `main` | `521a53844` | L2 deposit-only launch kit 2de669e plus the epoch-8620 monitor fix and the release recipe (integrator: agent 383) | launch kit reviewed fit (review 308); NOT yet rebuilt against the released node |
| `codex/l2-dec-merge-r17-20261117` | `e75a8a36f` | December line re-pinned to the merged native commit (agent 382) | WIP; every L2 gate stays inert (u64::MAX) |
| `codex/l2-follower-8620-r17-20261117` | `521a53844` | The follower and producer against node release 906336fd; kit pins | same tree as main when pushed |
| `codex/l2-launch-rebuild-r17-20261117` | `3d35a0f42` | Launch kit rebuilt against the released node, reproducible on two hosts (agent 383) | WIP; the launch guest ELF and verification key must not move |
| `codex/l2-r15-recipients-20261116` | `f73131f0c` | December build with the owner's fee recipients | superseded by codex/l2-r17-pins-20261117 |
| `codex/l2-r17-20261117` | `8c5d9ac71` | L2 open items after round 17 (agent 334) | under review (review 335 / 384) |
| `codex/l2-r17-pins-20261117` | `99da26287` | Round-17 pins of the December line (agent 334) | under review (review 335 / 384) |
| `codex/l2-review-r17-20261117` | `0969ac4d0` | Reviewer demonstrations | review material, not for merge |

Status words: **audit candidate / fit for external audit**: the internal reviewers found no open Critical,
High or Medium finding on that tip; **reviewed**: an internal review pass covered that tip; **WIP**: work in
progress, tests not necessarily green; **superseded**: kept for history, do not build on it; **review
material**: tests and scripts that demonstrate review findings, never merged.

## How to verify a line

```
git fetch origin
git checkout --detach origin/<branch>
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
launch kit: sha256sum -c deployment/mainnet/GO-LIVE-PINS.sha256 from the kit layout described in deployment/mainnet
```

A tip's own documents (the route or package document under `docs/`) give its full test table and rehearsals.
