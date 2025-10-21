# Wallet Adapter

Baseline integration uses `@stacks/connect` v8.2.0 to request the active wallet for an STX address. The adapter hides the SDK calls behind a minimal API so the rest of the client stays framework-free.

## Vendored SDK
- `client/modules/vendor/stacks-connect.js` re-exports the ESM build that Express serves from `/node_modules`. This keeps our source free of deep `node_modules` paths and lets us pin the SDK version in `package.json`.
- To bump the SDK, edit the version in `package.json` (and `package-lock.json` if you check that in) and run:
  ```sh
  npm install
  ```
  The server will then serve the updated `/node_modules/@stacks/connect/dist/index.mjs` without any extra bundling step.
- Optional sanity check after upgrades:
  ```sh
  node -e "console.log(require('./package.json').dependencies['@stacks/connect'])"
  ```
  Confirm it prints `8.2.0` (or whichever version you just pinned).

## Adapter API
All functions live in `client/modules/wallet-adapters/baseline.js`.

- `init({ appDetails, network, allowStubFallback, reset })`
  - `appDetails`: name/icon used in the stub prompt for clarity.
  - `network`: string forwarded to the `getAddresses` request (defaults to `testnet`).
  - `allowStubFallback`: set `false` to disable the manual prompt.
  - `reset`: clears cached state and storage.
- `async connect({ onFinish, onCancel, onError })`
  - Uses `request('getAddresses')` (and fallbacks) from `@stacks/connect`.
  - On success, caches only the public address and returns `{ address, addresses, provider, method, network }`.
  - On cancellation (`JsonRpcErrorCode.UserCanceled` or 4001), `null` is returned after calling `onCancel`.
  - When no wallet is detected and `allowStubFallback` is `true`, opens the local stub prompt.
- `getAddress()` pulls the cached STX address from memory/localStorage.
- `getLastResult()` returns the last successful payload (or `null`).

### Storage key and events

- Canonical storage key: `rv.wallet.address` — the adapter reads this key first and falls back to the legacy `wallet-adapter:address` key for compatibility. When a connection succeeds both keys are written.
- Global event: the adapter now dispatches a `wallet:connected` CustomEvent on `window` with the adapter `lastResult` object in `event.detail`.

## Smoke Testing Tips
- Launch the dev server (`npm run dev`) and click **Connect Wallet**. With Leather installed, approving the request should log the provider info and display the STX address in the UI.
- Without a wallet, keep the stub fallback enabled and enter a testnet address to simulate the flow. This mirrors the minimal expectations in the documentation checklist.
- For end-to-end verification, extend `scripts/test-smoke.mjs` to hit the wallet connect button and assert the address renders (pending broader UI automation).
