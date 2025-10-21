---
title: Wallet Integration Options
date: 2025-10-20
status: draft
owner: rv404
slug: wallet-integration
---

## Overview
- **Problem**: Decide whether to stick with first-party `@stacks/connect` flows or leverage turnkey embedded-wallet repos/iframe wrappers without compromising extensibility, offline dev, or maintainability.
- **Audience**: Engineering and product stakeholders evaluating wallet UX tradeoffs.
- **Related Specs**: 2025-10-20-wallet-flow, 2025-10-20-mint-flow (planned).

## Goals
1. Catalogue viable embedded-wallet options (including iframe-based connectors) and note integration cost.
2. Define architectural hooks so wallet providers can be swapped like LEGO bricks.
3. Establish evaluation criteria (security, offline support, API boundaries) before we commit to external kits.

## Non-Goals
- Implementing or vendoring third-party code before due diligence.
- Covering non-Stacks wallets.
- Building custom wallet UIs from scratch.

## User Narrative
### Primary Flow
1. Developer reviews comparison table in this spec.
2. Team agrees on default path (baseline Stacks Connect vs turnkey embed).
3. Engineering updates `client/modules/wallet.js` to use the selected adapter pattern.

### Alternate Flows
- If a turnkey repo is unsuitable (licenses, maintenance risk), stay with `@stacks/connect` but document how to add a connector later.
- If multiple connectors are needed, expose a configuration toggle and register them dynamically.

## Technical Plan
- **Client**: Introduce a `wallet-adapters/` directory exporting a standard interface (`connect`, `getAddress`, `render`). Baseline adapter wraps `@stacks/connect`. Additional adapters can wrap iframe SDKs if adopted.
- **Server**: Continue serving static assets; optionally host iframe wrapper files locally to avoid network reliance.
- **Integrations**: Evaluate turnkey repos for API surface, dependency weight, license, and maintenance cadence.
- **Data/State**: Store active adapter choice in local state; future persistence via localStorage if multi-wallet support is required.

## Milestones
| Milestone | Deliverable | Owner | Target |
| --- | --- | --- | --- |
| Research | Comparative matrix + decision log | rv404 | 2025-10-27 |
| Adapter API | Document interface + baseline implementation | rv404 | 2025-10-28 |
| Decision Review | Confirm adoption plan with stakeholders | team | 2025-10-29 |

## Acceptance Criteria
- [ ] Matrix covers at least baseline Stacks Connect and two turnkey repos (pending offline review).
- [ ] Adapter interface defined and committed.
- [ ] Decision recorded with rationale and follow-up tasks.

## Risks & Mitigations
| Risk | Mitigation |
| --- | --- |
| Turnkey repo unmaintained | Set update cadence checks; prefer actively maintained kits. |
| Security concerns with iframe embeds | Sandbox iframes, host assets locally, review CSP headers. |
| Increased bundle size | Lazy-load adapters; document performance impact. |

## Open Questions
- Which turnkey repos align with the project license and support Stacks testnet?
- Can the iframe kits run offline or do they require remote services?
- Do we need analytics/telemetry hooks to monitor wallet connections?

## References
- docs/PRD.md
- specs/2025-10-20-wallet-flow.md
- Placeholder: review turnkey repos once accessible offline snapshot is available
