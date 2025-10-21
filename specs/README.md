# Specs / OpenSpec — How this repo uses it

This project includes an OpenSpec copy under `specs/OpenSpec/`. We use OpenSpec for structured spec editing and for managing agent-related docs in a way that can be programmatically built and merged.

What is OpenSpec here
- OpenSpec is a spec tooling system (https://github.com/Fission-AI/OpenSpec) used to manage large, changing specs in markdown. It provides commands to validate, build, and merge spec fragments.
- This repo vendors a working OpenSpec instance in `specs/OpenSpec/` for local spec workflows and prototyping.

Key files
- `specs/OpenSpec/build.js` — local build script used to assemble outputs from the spec sources.
- `specs/OpenSpec/AGENTS.md` — agent instructions and managed blocks (look for `<!-- OPENSPEC:START -->` markers).
- `specs/OpenSpec/openspec-parallel-merge-plan.md` — notes and plans for collaborative editing and merging.

Quick developer workflow
1. Edit spec files under `specs/OpenSpec/openspec/` or the top-level managed files (for example `specs/OpenSpec/AGENTS.md`).
2. Run the build script locally to sanity-check and generate any derived outputs:

```bash
# from repo root
node specs/OpenSpec/build.js
```

3. Review build output and any diagnostic messages. OpenSpec's managed markers will indicate where automated tooling can update sections.
4. When preparing a PR that touches specs, include a short note in the PR description about which OpenSpec files changed and whether `node specs/OpenSpec/build.js` was run.

Notes & best practices
- Keep managed blocks (`<!-- OPENSPEC:START -->` / `<!-- OPENSPEC:END -->`) stable; changes to spacing can confuse diffs.
- Use `openspec change` tooling (if available) in CI for more advanced workflows; the local `build.js` is a lightweight starting point.
- If you want to adopt `spec-kit` later, we can add a mapping layer that converts spec-kit outputs to OpenSpec inputs — for now OpenSpec is the primary spec tool in this repo.

Troubleshooting
- If `node specs/OpenSpec/build.js` fails, inspect `specs/OpenSpec/package.json` for required node versions or dev tooling. Install dependencies inside `specs/OpenSpec` with `npm install` if necessary.

Contact / ownership
- Add a short note in PRs when updating spec files so reviewers can confirm the build output.
