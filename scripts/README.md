# Script ownership

Productization Alpha classifies repository scripts by responsibility. Existing root-level entry points remain supported for this milestone; new scripts must be added to one of the directories below.

- `dev/`: local setup, smoke tests, and adapter/plugin development helpers.
- `bench/`: benchmark runners, scoring, effect analysis, and experimental tooling.
- `roadmap/`: roadmap validation and generated-contract tooling.
- `release/`: version, artifact, install, SBOM, and release-readiness checks. These scripts must not publish by default.

Root-level scripts are compatibility entry points. They may be moved behind wrappers only when their import paths, package scripts, documentation, and CI callers have contract coverage.
