# AgentGuard project memory

The implementation control plane lives at
`docs/06_delivery/roadmap/`. Read its `README.md` and run
`uv run python scripts/roadmap-tools.py ready` before starting repository work.

## Mandatory task lifecycle

1. The primary worktree is for reading, coordination and integration checks only.
   Implement every roadmap task in a dedicated Git worktree and a `codex/`
   branch created from the latest `origin/dev`.
2. Only a blue `ready` task may be claimed. Before editing implementation files,
   an integration owner must run `roadmap-tools.py claim` in a dedicated
   allocation worktree and land that state update on `dev`. The claim records the
   node, owner, branch, base SHA, worktree slug and exclusive change surfaces.
3. A feature worktree may append evidence only for its claimed node. It must not
   edit another node's lifecycle or hand-edit `roadmap/generated/`.
4. Run `add-evidence` for implementation, tests, CI, review and rollback proof.
   A dirty worktree or branch-local commit is pending evidence, never completion.
5. After the implementation and required evidence are merged into `origin/dev`,
   the integration owner must immediately run `close`. A node becomes green only
   when its completion commit is reachable from `origin/dev` and all exit
   acceptance items are verified. Closing a node recalculates the blue Ready Queue.
6. Use `block`/`resume` for a real hold. Never delete or rewrite a status/evidence
   record to hide history.
7. Run `validate`, `build` and `check` before every roadmap state PR. Generated
   files must be rebuilt from source; never resolve their conflicts manually.

## Parallel work safety

- Create worktrees as `../agent-guard-worktrees/<node-id>` on branches such as
  `codex/<node-id>-<slug>`.
- Do not run two active claims against the same exclusive surface. The integration
  owner serializes evaluation activation, Guard API production wiring, Audit
  schema/storage, runtime binding activation, Dashboard mappers/store and the
  roadmap catalog/generated artifacts.
- `I01` and `R05P` currently overlap
  `apps/guard-api/guard_api/services/evaluation.py`; they may develop in parallel,
  but their shared production wiring must be integrated serially. Neither active
  worktree means Gate A or RTE-05 has passed.

## Roadmap invariants

- One node represents one task or acceptance step explicitly present in a cited
  project document. Do not invent combined nodes.
- A dependency edge needs a documented or recorded decision, an explicit
  blocking phase (`start`, `activate`, `exit`) and a rationale.
- Git chronology alone is only `observed_sequence`; it is not a dependency.
- The four primary display states are green completed, amber in progress, blue
  ready and gray not ready. `ready` is derived and must never be stored manually.
