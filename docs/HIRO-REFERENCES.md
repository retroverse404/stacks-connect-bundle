# Hiro Docs — Quick Reference (local copy for LLM/context)

This file collects short, 2–3 line summaries and links to selected Hiro (Hiro Systems) developer guides so they can be used as local context when working on Stacks integrations.

Entries below are intentionally brief — use the linked pages for full details.

- api-keys — https://docs.hiro.so/resources/guides/api-keys
  - How to generate and use Hiro API keys. Use `x-api-key` header for server requests; keep keys server-side to avoid leakage. Useful when exceeding free rate limits.

- build-a-decentralized-kickstarter — https://docs.hiro.so/resources/guides/build-a-decentralized-kickstarter
  - Step-by-step Clarity contract patterns for creating crowdfunding-style dapps: data maps for pledges, whitelists, and functions to create/cancel/fulfil pledges.

- build-an-nft-marketplace — https://docs.hiro.so/resources/guides/build-an-nft-marketplace
  - End-to-end patterns for listing, cancelling, and fulfilling NFT listings using SIP-010/traits; covers error constants, whitelisting, and post-condition-safe transfers.

- installing-docker — https://docs.hiro.so/resources/guides/installing-docker
  - Docker installation guidance and verification steps; useful for running local devnets and services (Stacks/Bitcoin nodes) inside containers.

- no-loss-lottery — https://docs.hiro.so/resources/guides/no-loss-lottery
  - Example contract that uses stacking yield for a lottery pool. Shows NFT ticket minting, participant bookkeeping, winner selection (VRF), and testing via Clarinet.

- rate-limits — https://docs.hiro.so/resources/guides/rate-limits
  - Hiro API rate limits: unauthenticated ~50 RPM per IP, authenticated with API key ~500 RPM. Separate quotas for Bitcoin vs Stacks services.

- response-headers — https://docs.hiro.so/resources/guides/response-headers
  - Describes service-specific headers (x-ratelimit-*, x-ratelimit-cost-*) returned by Hiro APIs; helpful for instrumentation and retry/backoff logic.

- sync-a-bitcoin-node — https://docs.hiro.so/resources/guides/sync-a-bitcoin-node
  - How to download, configure, and run bitcoind for a full node; tips for datadir placement, performance, and safe shutdown/restart.

- sync-a-stacks-node — https://docs.hiro.so/resources/guides/sync-a-stacks-node
  - Docker-managed stacks-node devnet/mainnet instructions, starting the service, logs, and monitoring sync progress; ideal for local integration testing.

- using-clarity-values — https://docs.hiro.so/resources/guides/using-clarity-values
  - Examples showing how to serialize/deserialize Clarity values (uintCV, buffer, etc.) and call read-only/public contract functions using the BlockChain API client.

- using-pyth-price-feeds — https://docs.hiro.so/resources/guides/using-pyth-price-feeds
  - Full integration guide for Pyth oracle: contract-side verification, decoding VAAs, frontend service for fetching VAA, and best practices (freshness, error handling).


How to use this file for LLM prompts
- Paste relevant sections into the model prompt when asking LLMs to write Clarity contracts, tests (Clarinet), or frontend integrations that use Pyth/Hiro APIs.
- Prefer linking small snippets (contract signatures, feed IDs, or header names) rather than the entire pages to keep prompts concise.
