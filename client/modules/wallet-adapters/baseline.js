import {
  JsonRpcError,
  JsonRpcErrorCode,
  request,
  getStacksProvider,
  isProviderSelected,
  getSelectedProviderId,
} from '../vendor/stacks-connect.js';

console.log('wallet-adapter: baseline (stacks-connect) loaded');

const STORAGE_KEY = 'wallet-adapter:address';
// Canonical storage key used across projects and tests
const CANONICAL_KEY = 'rv.wallet.address';
const STUB_STORAGE_KEY = 'wallet-adapter:stub-address';

const state = {
  cachedAddress: null,
  lastResult: null,
  network: 'testnet',
  allowStubFallback: true,
  appDetails: { name: 'Finding Nakamoto', icon: 'https://placehold.co/64' },
};

state.cachedAddress = loadStoredAddress();

function loadStoredAddress() {
  if (typeof window === 'undefined') return null;
  try {
    // Prefer the canonical key, fall back to legacy adapter key
    const canonical = window.localStorage?.getItem(CANONICAL_KEY);
    if (canonical) return canonical;
    const stored = window.localStorage?.getItem(STORAGE_KEY);
    if (stored) return stored;
  } catch (err) {
    console.debug('wallet-adapter: unable to read stored address', err);
  }
  return loadStubAddress();
}

function saveAddress(address) {
  if (typeof window === 'undefined') return;
  try {
    if (address) {
      // write both canonical and legacy keys for compatibility
      window.localStorage?.setItem(CANONICAL_KEY, address);
      window.localStorage?.setItem(STORAGE_KEY, address);
    } else {
      window.localStorage?.removeItem(CANONICAL_KEY);
      window.localStorage?.removeItem(STORAGE_KEY);
    }
  } catch (err) {
    console.debug('wallet-adapter: unable to persist address', err);
  }
}

function loadStubAddress() {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage?.getItem(STUB_STORAGE_KEY) || null;
  } catch (err) {
    console.debug('wallet-adapter: unable to read stub address', err);
    return null;
  }
}

function saveStubAddress(address) {
  if (typeof window === 'undefined') return;
  try {
    if (address) {
      window.localStorage?.setItem(STUB_STORAGE_KEY, address);
    } else {
      window.localStorage?.removeItem(STUB_STORAGE_KEY);
    }
  } catch (err) {
    console.debug('wallet-adapter: unable to persist stub address', err);
  }
}

function hasInstalledProvider() {
  if (typeof window === 'undefined') return false;
  if (typeof getStacksProvider === 'function') {
    try {
      if (getStacksProvider()) return true;
    } catch (err) {
      console.debug('wallet-adapter: provider detection failed', err);
    }
  }
  if (window.StacksProvider) return true;
  const legacy = window.webbtc_stx_providers || window.wbip_providers;
  return Array.isArray(legacy) && legacy.length > 0;
}

const RPC_METHODS = [
  {
    method: 'getAddresses',
    extract: (response) => (response && Array.isArray(response.addresses) ? response.addresses : []),
  },
  {
    method: 'stx_getAddresses',
    extract: (response) => (response && Array.isArray(response.addresses) ? response.addresses : []),
  },
  {
    method: 'stx_getAccounts',
    extract: (response) => (response && Array.isArray(response.accounts) ? response.accounts : []),
  },
];

function pickStacksAddress(entries) {
  if (!Array.isArray(entries)) return null;

  const preferred = entries.find((entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const { address, chain, type, symbol } = entry;
    if (typeof chain === 'string' && chain.toLowerCase().includes('stacks')) return true;
    if (typeof symbol === 'string' && symbol.toLowerCase().includes('stx')) return true;
    if (typeof type === 'string' && type.toLowerCase().includes('stx')) return true;
    return typeof address === 'string' && /^S[T|P]/i.test(address);
  });

  if (preferred && typeof preferred.address === 'string') return preferred.address;

  const fallback = entries.find((entry) => typeof entry?.address === 'string');
  return fallback?.address || null;
}

function interpretError(error) {
  const code = error?.code;
  if (code === 4001 || code === '4001') return 'cancel';
  if (code === JsonRpcErrorCode.UserCanceled) return 'cancel';
  if (error instanceof JsonRpcError && error.code === JsonRpcErrorCode.UserCanceled) return 'cancel';
  return 'error';
}

function shouldFallbackToStub(error) {
  if (!state.allowStubFallback) return false;
  if (interpretError(error) === 'cancel') return false;
  return !hasInstalledProvider();
}

async function requestAddresses() {
  const params = state.network ? { network: state.network } : undefined;
  const requireWalletChoice = !isProviderSelected();
  const options = {
    forceWalletSelect: requireWalletChoice,
    persistWalletSelect: true,
    enableLocalStorage: false,
  };

  let lastError = null;

  for (const { method, extract } of RPC_METHODS) {
    try {
      const args = params ? [options, method, params] : [options, method];
      const response = await request(...args);
      const entries = extract(response);
      if (Array.isArray(entries) && entries.length > 0) {
        return { method, entries };
      }
    } catch (err) {
      if (interpretError(err) === 'cancel') throw err;
      lastError = err;
    }
  }

  if (lastError) throw lastError;
  throw new Error('Wallet responded without any addresses');
}

function createStub() {
  const stubState = { address: loadStubAddress() };

  async function promptForAddress({ onFinish, onCancel, onError } = {}) {
    if (typeof window === 'undefined') {
      const err = new Error('wallet-adapter stub connect requires a browser window.');
      if (typeof onError === 'function') onError(err);
      throw err;
    }

    try {
      const existing = stubState.address || 'ST_TESTNET_ADDRESS';
      const label = `Enter a testnet STX address to simulate a wallet connection (${state.appDetails.name} stub mode):`;
      const input = window.prompt(label, existing);

      if (input === null) {
        if (typeof onCancel === 'function') onCancel();
        return null;
      }

      const trimmed = input.trim();
      if (!trimmed) {
        if (typeof onCancel === 'function') onCancel();
        return null;
      }

      stubState.address = trimmed;
      saveStubAddress(stubState.address);

      const result = { address: stubState.address, stub: true };
      if (typeof onFinish === 'function') onFinish(result);
      return result;
    } catch (err) {
      if (typeof onError === 'function') onError(err);
      throw err;
    }
  }

  return {
    connect: promptForAddress,
    getAddress() {
      return stubState.address || loadStubAddress();
    },
  };
}

const stub = createStub();

export function init(options = {}) {
  if (options.appDetails) state.appDetails = options.appDetails;
  if (options.network) state.network = options.network;
  if (options.allowStubFallback !== undefined) state.allowStubFallback = Boolean(options.allowStubFallback);
  if (options.reset) {
    state.cachedAddress = null;
    state.lastResult = null;
    saveAddress(null);
  }
}

export async function connect({ onFinish, onCancel, onError } = {}) {
  try {
    const { method, entries } = await requestAddresses();
    const address = pickStacksAddress(entries);

    if (!address) throw new Error('Wallet did not return a usable STX address');

    state.cachedAddress = address;
    state.lastResult = {
      address,
      addresses: entries,
      provider: getSelectedProviderId?.() || 'unknown-provider',
      method,
      network: state.network,
      stub: false,
    };

    saveAddress(address);
    // dispatch a global event for consumers who listen for wallet connections
    try {
      if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
        window.dispatchEvent(new CustomEvent('wallet:connected', { detail: state.lastResult }));
      }
    } catch (e) {
      console.debug('wallet-adapter: failed to dispatch wallet:connected', e);
    }
    if (typeof onFinish === 'function') onFinish(state.lastResult);
    return state.lastResult;
  } catch (err) {
    if (interpretError(err) === 'cancel') {
      if (typeof onCancel === 'function') onCancel();
      return null;
    }

    if (shouldFallbackToStub(err)) {
      console.warn('wallet-adapter: stacks-connect failed, falling back to stub', err);
      const result = await stub.connect({ onFinish, onCancel, onError });
      if (result && result.address) {
        state.cachedAddress = result.address;
        state.lastResult = { ...result, provider: 'stub', method: 'stub', network: state.network };
        saveAddress(result.address);
      }
      return result;
    }

    if (typeof onError === 'function') onError(err);
    throw err;
  }
}

export function getAddress() {
  if (state.cachedAddress) return state.cachedAddress;
  state.cachedAddress = loadStoredAddress();
  return state.cachedAddress;
}

export function getLastResult() {
  return state.lastResult;
}
