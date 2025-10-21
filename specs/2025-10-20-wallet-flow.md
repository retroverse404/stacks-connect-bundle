---
title: Wallet Connect Flow
date: 2025-10-20
status: draft
owner: rv404
slug: wallet-flow
---

## Overview
- **Problem**: Ensure the Finding Nakamoto MVP can connect a Leather (Stacks) wallet, surface the user’s testnet address, and render either an iframe embed or inline HTML scene using HTMX without fragile hacks.
- **Audience**: Core devs, design collaborators, and future contributors who need to understand wallet/scene scaffolding.
- **Related Specs**: 2025-10-20-mint-flow (planned), 2025-10-20-tts-proxy (planned).

## Goals
1. Provide a reliable Leather wallet connect button that writes the resolved Stacks testnet address into the UI.
2. Offer a toggle between iframe and inline scene embeds, powered by HTMX partials that are easy to extend.
3. Document environment needs (Node 18, `.env`, future API keys) so anyone can reproduce the flow.

## Non-Goals
- Shipping production UI polish or animations.
- Integrating mainnet wallets or signing real transactions.
- Implementing persistence of scene state beyond in-memory/session examples.

## User Narrative
### Primary Flow
1. Developer runs `npm run dev`; server starts on `http://localhost:5173`.
2. User opens the page, clicks **Connect Wallet**, and authorizes Leather testnet.
3. The header shows the resolved `STX` testnet address.
4. User selects either **Inline Scene** or **Iframe Scene**.
5. HTMX loads the chosen fragment into the main viewport.

### Alternate Flows
- If no wallet is installed, the connect dialog informs the user and the address span remains empty.
- If the user cancels the connect flow, an informational message is logged and the UI remains unchanged.

## Technical Plan
- **Client**: `client/index.html` hosts toggle controls; `client/modules/wallet.js` manages Leather connect callbacks; new HTMX buttons load partials from `client/views/`. Future adapters live under `client/modules/wallet-adapters/` per the integration options spec.
- **Server**: Express static middleware serves `client` and nested `views` partials; no additional server routes needed.
- **Integrations**: Leather via `@stacks/connect`; future mint/TTS endpoints remain mocked. Adapter interface will allow turnkey iframe or embedded kits to plug in later.
- **Data/State**: Address stored in DOM; embed selection managed by HTMX using `hx-target="#view"`. Active wallet adapter tracked in module scope, optionally persisted in localStorage later.

## Milestones
| Milestone | Deliverable | Owner | Target |
| --- | --- | --- | --- |
| M1 Wallet Skeleton | Working connect button + address display | rv404 | 2025-10-25 |
| M1 Scene Embeds | HTMX-driven inline + iframe partials | rv404 | 2025-10-25 |
| M1 Docs | README entry + `.env.example` stub | rv404 | 2025-10-27 |

## Acceptance Criteria
- [ ] Leather connect resolves a testnet address and populates `#addr`.
- [ ] Buttons switch between iframe and inline partials without full page reload.
- [ ] README documents how to run the flow and where to place design assets.

## Risks & Mitigations
| Risk | Mitigation |
| --- | --- |
| Leather extension missing | Display friendly message + documentation link. |
| CDN scripts unavailable | Option to serve scripts locally/pinned versions. |
| HTMX partial paths change | Centralize partial paths in constants or README. |

## Open Questions
- Should we persist the selected embed type across sessions (localStorage)?
- Do we need a fallback if browsers block iframes?
- When do we introduce a router (e.g., file-based) for scene management?

## References
- PRD v0.2 (docs/PRD.md)
- Leather wallet docs (TBD link)
- Stacks Connect guide (TBD link)
