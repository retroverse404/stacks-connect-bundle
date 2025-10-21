console.log("wallet module loaded");
import { init, connect, getAddress } from './wallet-adapters/baseline.js';

const connectButton = document.getElementById('btn-connect');
const addressEl = document.getElementById('addr');

init({ appDetails: { name: 'Finding Nakamoto', icon: 'https://placehold.co/64' } });

if (!connectButton) {
  console.warn('Connect button #btn-connect not found.');
} else {
  connectButton.addEventListener('click', async () => {
    try {
      await connect({
        onFinish: () => {
          const address = getAddress();
          if (addressEl) addressEl.textContent = address || 'Connected';
        },
        onCancel: () => console.info('Wallet connection cancelled by user.'),
        onError: (err) => console.error('Wallet connection failed', err)
      });
    } catch (err) {
      console.error('connect() threw', err);
    }
  });
}
