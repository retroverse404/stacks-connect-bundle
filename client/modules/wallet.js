import { init, connect, getAddress } from './wallet-adapters/baseline.js';

let connectButton;
let addressLabel;
const walletState = {
  address: null,
  connecting: false,
};

export function initWalletUI({ connectButtonId = 'btn-connect', addressLabelId = 'addr' } = {}) {
  init({
    appDetails: { name: 'Finding Nakamoto', icon: 'https://placehold.co/64/orange/000?text=FN' },
    allowStubFallback: true,
    network: 'testnet',
  });

  connectButton = document.getElementById(connectButtonId);
  addressLabel = document.getElementById(addressLabelId);

  if (connectButton) {
    connectButton.addEventListener('click', handleConnectClick);
  } else {
    console.warn('Connect button not found.');
  }

  const cached = getAddress();
  if (cached) {
    setAddress(cached, { emitEvent: true, reused: true });
  } else {
    updateAddressLabel('Not connected');
  }

  updateButtonState();
}

export function getCurrentAddress() {
  return walletState.address;
}

async function handleConnectClick() {
  if (walletState.connecting) return;
  walletState.connecting = true;
  updateButtonState();

  try {
    await connect({
      onFinish: ({ address, stub }) => {
        setAddress(address, { reused: Boolean(stub), emitEvent: true });
      },
      onCancel: () => {
        console.info('Wallet connection cancelled');
      },
      onError: (error) => {
        console.error('Wallet connection failed', error);
      },
    });
  } catch (error) {
    console.error('connect() threw', error);
  } finally {
    walletState.connecting = false;
    updateButtonState();
  }
}

function setAddress(address, { emitEvent = false, reused = false } = {}) {
  walletState.address = address || null;
  if (address) {
    updateAddressLabel(address);
    if (emitEvent) emitWalletConnected(address, reused);
  } else {
    updateAddressLabel('Not connected');
  }
}

function updateButtonState() {
  if (!connectButton) return;
  connectButton.disabled = walletState.connecting;
  connectButton.textContent = walletState.connecting ? 'Connecting…' : 'Connect Wallet';
}

function updateAddressLabel(value) {
  if (!addressLabel) return;
  addressLabel.textContent = value;
}

function emitWalletConnected(address, reused = false) {
  if (!address) return;
  window.dispatchEvent(
    new CustomEvent('wallet:connected', {
      detail: {
        address,
        reused,
        helper: true,
        timestamp: Date.now(),
      },
    }),
  );
}
