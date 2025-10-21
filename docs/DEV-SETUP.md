# DEV-SETUP (Finding Nakamoto)

This document contains minimal steps to run the M1 demo locally and notes on helpful dev tools.

Prereqs
- Node.js >= 18
- npm (or pnpm/yarn)
- A modern browser (Chrome/Firefox)

Install
```bash
# from repo root
npm install
```

Start the server (dev)
```bash
# runs nodemon if available, fallback to node
npm run dev
# or
node server/server.js
```

Quick smoke test
```bash
# Ensure server running (default PORT 5173)
curl -sS http://localhost:5173/api/ping | jq .
# Expected output: { "ok": true }
```

Wallets for local testing
- Leather (browser extension) is a good local wallet for onboarding tests. Install Leather in your browser and use the Connect button in the demo to approve the dapp.

Environment variables
- The project reads `.env` for secrets (via dotenv). Create a `.env` file locally (do NOT commit it). See `.env.example` for variables.

ElevenLabs and TTS
- To enable the optional TTS proxy, add your ElevenLabs API key to `.env` as `ELEVENLABS_API_KEY`.
- In M1 the server provides a stubbed `/api/tts` endpoint; the real ElevenLabs integration is optional and gated by the presence of the API key.

Developer notes
- The client currently uses a small adapter pattern at `client/modules/wallet-adapters/` to allow swapping wallet implementations (Leather, Xverse, etc.). See `docs/WALLET-ADAPTER.md` for upgrade instructions and API notes.
- If CDNs fail to deliver `@stacks/connect` ESM builds, run `npm install` and ensure the server serves `node_modules/` (recommended for local dev). See `server/server.js` for static paths.

Notes on storage and events
- The adapter writes the canonical storage key `rv.wallet.address` and also writes the legacy `wallet-adapter:address` for compatibility.
- The adapter emits a `wallet:connected` CustomEvent on `window` when a connection completes; listeners can read the payload from `event.detail`.

Support
- PRD and repo shortlist: `docs/PRD.md` and `docs/Repos-Shortlist.md`.

Hiro (Stacks) reference docs
- Local quick-reference for Hiro guides: `docs/HIRO-REFERENCES.md` — contains short summaries and links to Hiro guides (Pyth, Clarity, node sync, API keys, rate limits) useful when building on Stacks.
