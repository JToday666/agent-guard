# Release-readiness scripts

Scripts in this directory validate builds and supply-chain metadata without publishing. Productization Alpha does not push packages, images, tags, or releases.

The root-level `check-release-*`, `release-artifact-manifest.py`, `verify-wheel-install.py`, and `verify-npm-tarball.mjs` remain compatibility entry points for the current `0.1.x` line.

Run `productization-alpha-gate.sh fast` for local checks or `productization-alpha-gate.sh --full` when PostgreSQL, Playwright, Docker, and Syft are available.
