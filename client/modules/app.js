import { initWalletUI, getCurrentAddress } from './wallet.js';
import { initAiGuideUI } from './ai-guide.js';

const viewEl = document.querySelector('#view');
const flowMapList = document.querySelector('#flow-map ol');
const navButtons = Array.from(document.querySelectorAll('[data-nav-screen]'));
const flowHintEl = document.querySelector('[data-flow-hint]');
const audioDisplayEl = document.querySelector('[data-audio-display]');
const nextScreenDisplayEl = document.querySelector('[data-next-screen]');
let flowHintTimer = null;
let flowHintPinned = false;

const SCREENS = Object.freeze({
  ENTRY: 'ENTRY',
  DASHBOARD: 'DASHBOARD',
  AI_GUIDE: 'AI_GUIDE',
  MINT: 'MINT',
  EXPLORE: 'EXPLORE',
  LOADING: 'LOADING',
});

const FLOW_STEPS = [
  { id: SCREENS.ENTRY, label: 'Entry' },
  { id: SCREENS.DASHBOARD, label: 'Dashboard' },
  { id: SCREENS.AI_GUIDE, label: 'AI Guide' },
  { id: SCREENS.MINT, label: 'Mint' },
  { id: SCREENS.EXPLORE, label: 'Explore' },
  { id: SCREENS.LOADING, label: 'Loading State' },
];

const SCREEN_LABEL_LOOKUP = FLOW_STEPS.reduce((acc, step) => {
  acc[step.id] = step.label;
  return acc;
}, {});

const PROGRESSION_CHAIN = [SCREENS.ENTRY, SCREENS.DASHBOARD, SCREENS.EXPLORE];

const PROGRESSION_RULES = {
  [SCREENS.DASHBOARD]: {
    requires: [SCREENS.ENTRY],
    reason: 'Enter the experience to bring the dashboard online.',
  },
  [SCREENS.AI_GUIDE]: {
    requires: [SCREENS.DASHBOARD],
    reason: 'Review the dashboard before syncing with the AI guide.',
  },
  [SCREENS.MINT]: {
    requires: [SCREENS.DASHBOARD],
    requiresWallet: true,
    reason: 'Connect your wallet to unlock the mint terminal.',
  },
  [SCREENS.EXPLORE]: {
    requires: [SCREENS.DASHBOARD],
    reason: 'Explore unlocked.',
  },
};

const state = {
  currentScreen: null,
  lastContext: {},
  visited: new Set(),
  wallet: { connected: false, address: null },
  aiLog: [],
  mint: { status: 'idle', txId: null, lastError: null },
  exploreMarkup: null,
};

const SCREEN_RENDERERS = {
  [SCREENS.ENTRY]: renderEntry,
  [SCREENS.DASHBOARD]: renderDashboard,
  [SCREENS.AI_GUIDE]: renderAIGuide,
  [SCREENS.MINT]: renderMint,
  [SCREENS.EXPLORE]: renderExplore,
  [SCREENS.LOADING]: renderLoading,
};

init();

function init() {
  window.addEventListener('wallet:connected', handleWalletConnected);
  document.addEventListener('click', handleActionClick);
  initWalletUI();
  const cached = getCurrentAddress();
  if (cached) {
    state.wallet.connected = true;
    state.wallet.address = cached;
  }
  setScreen(SCREENS.ENTRY);
}

function handleWalletConnected(event) {
  const address = event?.detail?.address || getCurrentAddress();
  if (!address) return;
  const duplicateHelper = Boolean(event?.detail?.helper) && state.wallet.connected && state.wallet.address === address;
  if (duplicateHelper) return;
  state.wallet.connected = true;
  state.wallet.address = address;
  if (state.mint.status === 'idle') state.mint.lastError = null;
  syncNavState();
  refreshCurrentScreen();
}

function handleActionClick(event) {
  const navButton = event.target.closest('[data-nav-screen]');
  if (navButton) {
    const targetScreen = normalizeScreen(navButton.dataset.navScreen);
    if (targetScreen) {
      navigateToScreen(targetScreen, {}, { sourceEl: navButton });
    }
    return;
  }

  const control = event.target.closest('[data-action]');
  if (!control || control.disabled) return;
  const action = control.dataset.action;

  switch (action) {
    case 'enter-experience':
      navigateToScreen(SCREENS.DASHBOARD, {}, { sourceEl: control });
      break;
    case 'navigate': {
      const screen = normalizeScreen(control.dataset.targetScreen);
      if (screen) {
        navigateToScreen(screen, {}, { sourceEl: control });
      }
      break;
    }
    case 'start-mint':
      requestMint();
      break;
    case 'reload-explore':
      state.exploreMarkup = null;
      refreshCurrentScreen();
      hydrateExploreScene();
      break;
    default:
      break;
  }
}

function logAIGuideEntry(role, text, audioUrl = null, actions = []) {
  if (!role || !text) return;
  state.aiLog.push({
    role,
    text,
    audioUrl: audioUrl || null,
    actions: Array.isArray(actions) ? actions : [],
    ts: Date.now(),
  });
}

function requestMint() {
  if (!state.wallet.connected || !state.wallet.address) {
    state.mint.status = 'error';
    state.mint.lastError = 'Connect wallet to mint.';
    refreshCurrentScreen();
    return;
  }

  const recipient = state.wallet.address;
  const tokenId = Date.now();

  state.mint.status = 'pending';
  state.mint.txId = null;
  state.mint.lastError = null;
  refreshCurrentScreen();

  submitMintRequest({ recipient, tokenId })
    .then(({ txId }) => {
      console.info('Mint transaction submitted', txId);
      state.mint.status = 'success';
      state.mint.txId = typeof txId === 'string' ? txId : txId ? String(txId) : null;
      state.mint.lastError = null;
      state.visited.add(SCREENS.MINT);
      refreshCurrentScreen();
      setFlowHint('Mint successful', 'success', { temporary: true });
    })
    .catch((error) => {
      console.error('Mint request failed', error);
      state.mint.status = 'error';
      state.mint.lastError = error?.message || 'Mint request failed.';
      refreshCurrentScreen();
    });
}

function renderEntry() {
  return `
    <article class="card entry-card">
      <p class="eyebrow">Start</p>
      <h2>Finding Nakamoto – Prototype Shell</h2>
      <p>Calm entry before we move into the dashboard. Take a breath, connect your wallet when ready, and tap below to continue.</p>
      <div class="actions-row">
        <button class="btn primary" data-action="enter-experience">Enter Experience</button>
      </div>
    </article>
  `;
}

function renderDashboard() {
  const address = state.wallet.address ? shorten(state.wallet.address) : 'Connect wallet to begin tracking progress.';
  const mintStatus = describeMintStatus();
  const quickActions = [SCREENS.AI_GUIDE, SCREENS.MINT, SCREENS.EXPLORE]
    .map((screenId) => {
      const gate = getScreenGate(screenId);
      const label = getScreenLabel(screenId);
      const suffix = gate.locked ? ' (Locked)' : '';
      const title = gate.locked ? gate.reason || '' : '';
      const lockedAttrs = gate.locked ? 'aria-disabled="true" data-button-locked="true"' : '';
      return `<button class="btn" data-action="navigate" data-target-screen="${screenId}" ${lockedAttrs} title="${escapeHtml(title)}">${escapeHtml(label)}${suffix}</button>`;
    })
    .join('');
  return `
    <article class="card dashboard-card">
      <p class="eyebrow">Dashboard</p>
      <h2>Main workspace</h2>
      <p>Wallet state, mint progress, and quick links to each screen live here. This remains the default view after entry.</p>
      <div class="stats-grid">
        <div class="stat">
          <h3>Wallet</h3>
          <p>${address}</p>
        </div>
        <div class="stat">
          <h3>Mint status</h3>
          <p>${mintStatus}</p>
        </div>
      </div>
      <div class="actions-row">${quickActions}</div>
    </article>
  `;
}

function renderAIGuide() {
  const log = state.aiLog.length
    ? state.aiLog
        .map(({ role, text, actions }) => {
          const label = role === 'user' ? 'You' : 'Guide reply';
          const actionsMarkup = role === 'guide' ? renderGuideActionsHtml(actions) : '';
          return `<div class="chat-row ${role}"><span>${label}</span><p>${escapeHtml(text)}</p>${actionsMarkup}</div>`;
        })
        .join('')
    : '<p class="muted" data-guide-placeholder>Guide log is empty. Ask the guide to get started.</p>';

  return `
    <article class="card guide-card">
      <p class="eyebrow">Operator Console</p>
      <h2>AI Guide</h2>
      <p>Ask the guide about wallet, mint, or the explore scene.</p>
      <div class="chat-log" data-guide-log aria-live="polite">${log}</div>
      <form data-guide-form class="guide-form">
        <label for="guide-prompt">Your question</label>
        <div class="input-row">
          <input
            id="guide-prompt"
            name="prompt"
            type="text"
            required
            placeholder="Send a question about wallet, minting, or explore"
            autocomplete="off"
            data-guide-input
          />
          <button type="submit" class="btn primary" data-guide-send>Send to guide</button>
        </div>
      </form>
      <div class="actions-row">
        <button class="btn" data-action="navigate" data-target-screen="DASHBOARD">Back to Dashboard</button>
      </div>
    </article>
  `;
}

function renderGuideActionsHtml(actions = []) {
  const normalized = Array.isArray(actions) ? actions : [];
  if (!normalized.length) {
    return '<div class="guide-actions" data-guide-actions hidden></div>';
  }
  const buttons = normalized.map(renderGuideActionButtonHtml).join('');
  return `<div class="guide-actions" data-guide-actions>${buttons}</div>`;
}

function renderGuideActionButtonHtml(action) {
  if (!action || typeof action !== 'object') {
    return '';
  }
  const label = escapeHtml(action.label || 'Action');
  const type = typeof action.type === 'string' ? action.type : '';
  const attrs = [`data-guide-action="${escapeHtml(type)}"`];
  if (action.type === 'open_url' && typeof action.url === 'string') {
    attrs.push(`data-guide-action-url="${escapeHtml(action.url)}"`);
  }
  if (action.type === 'open_route' && typeof action.screen === 'string') {
    attrs.push(`data-guide-action-screen="${escapeHtml(action.screen)}"`);
  }
  return `<button type="button" class="btn ghost" ${attrs.join(' ')}>${label}</button>`;
}

function renderMint() {
  const disabled = state.mint.status === 'pending';
  const walletCopy = state.wallet.connected ? `Wallet connected: ${shorten(state.wallet.address)}` : 'Connect wallet first.';
  const statusMarkup = (() => {
    switch (state.mint.status) {
      case 'pending':
        return '<p class="muted" data-mint-status>Submitting mint…</p>';
      case 'success': {
        const txMarkup = state.mint.txId
          ? `<p class="muted" data-mint-tx>txId: <code>${escapeHtml(String(state.mint.txId))}</code></p>`
          : '';
        return `<p class="success" data-mint-status>Mint successful.</p>${txMarkup}`;
      }
      case 'error':
        return state.mint.lastError ? `<p class="error" data-mint-status>${escapeHtml(String(state.mint.lastError))}</p>` : '';
      default:
        return '';
    }
  })();
  return `
    <article class="card mint-card">
      <p class="eyebrow">Mint</p>
      <h2>Genesis Mint (Prototype)</h2>
      <p>This button calls the backend SIP-009 mint service which signs and broadcasts a contract-call on testnet.</p>
      <div class="status-pill ${state.wallet.connected ? 'online' : 'offline'}">${walletCopy}</div>
      ${statusMarkup}
      <button class="btn primary" data-action="start-mint" ${!state.wallet.connected || disabled ? 'disabled' : ''}>Mint Test NFT</button>
      <div class="actions-row">
        <button class="btn" data-action="navigate" data-target-screen="DASHBOARD">Back to Dashboard</button>
      </div>
    </article>
  `;
}

function renderExplore() {
  const embed = state.exploreMarkup
    ? state.exploreMarkup
    : '<div class="loading-line" role="presentation"></div><p class="muted">Loading scene placeholder…</p>';

  return `
    <article class="card explore-card">
      <p class="eyebrow">Explore</p>
      <h2>Scene placeholder</h2>
      <p>This area loads an HTML view so we can embed loops, videos, or iframes without changing the core layout.</p>
      <div class="explore-frame" data-explore-frame>${embed}</div>
      <div class="actions-row">
        <button class="btn" data-action="reload-explore">Reload Scene</button>
        <button class="btn" data-action="navigate" data-target-screen="DASHBOARD">Back to Dashboard</button>
      </div>
    </article>
  `;
}

function renderLoading(context = {}) {
  const heading = context.heading || 'Loading…';
  const subtext = context.subtext || 'Preparing the next step.';
  return `
    <article class="card loading-card">
      <p class="eyebrow">System</p>
      <h2>${heading}</h2>
      <p>${subtext}</p>
      <div class="loading-line" aria-hidden="true"></div>
    </article>
  `;
}

function setScreen(target, context = {}) {
  const screen = normalizeScreen(target);
  const renderer = SCREEN_RENDERERS[screen];
  if (!renderer) throw new Error(`Unknown screen: ${screen}`);

  state.currentScreen = screen;
  state.lastContext = context;
  state.visited.add(screen);

  if (viewEl) {
    viewEl.innerHTML = renderer(context);
    hydrateScreenModules(screen);
  }

  setAudioMode(getAudioModeForScreen(screen));
  syncNavState();
  renderFlowMap();
}

function refreshCurrentScreen() {
  if (!state.currentScreen) return;
  const renderer = SCREEN_RENDERERS[state.currentScreen];
  if (!renderer || !viewEl) return;
  viewEl.innerHTML = renderer(state.lastContext);
  hydrateScreenModules(state.currentScreen);
  syncNavState();
  renderFlowMap();
}

function hydrateScreenModules(screen) {
  if (screen === SCREENS.EXPLORE) {
    hydrateExploreScene();
  }
  if (screen === SCREENS.AI_GUIDE) {
    initAiGuideUI({
      onLogEntry: (entry) => {
        if (!entry) return;
        logAIGuideEntry(entry.role, entry.text, entry.audioUrl, entry.actions);
      },
      setScreen,
    });
  }
}

function hydrateExploreScene() {
  if (state.exploreMarkup) {
    renderExploreMarkup();
    return;
  }
  fetch('./views/embed-inline.html')
    .then((response) => response.text())
    .then((markup) => {
      state.exploreMarkup = markup;
      renderExploreMarkup();
    })
    .catch((error) => {
      console.error('Failed to load explore scene', error);
      state.exploreMarkup = '<p class="error">Unable to load placeholder scene.</p>';
      renderExploreMarkup();
    });
}

function renderExploreMarkup() {
  if (state.currentScreen !== SCREENS.EXPLORE) return;
  const frame = document.querySelector('[data-explore-frame]');
  if (frame) frame.innerHTML = state.exploreMarkup;
}

function renderFlowMap() {
  if (!flowMapList) return;
  const active = state.currentScreen;
  const next = computeNextScreen();
  if (nextScreenDisplayEl) {
    const label = next ? getScreenLabel(next) : 'Free roam';
    nextScreenDisplayEl.textContent = label;
  }
  flowMapList.innerHTML = FLOW_STEPS.map((step) => {
    const gate = getScreenGate(step.id);
    const isActive = step.id === active;
    const isComplete = state.visited.has(step.id) && !isActive;
    const isNext = !isActive && !isComplete && !gate.locked && step.id === next;
    const classNames = [
      isActive ? 'is-active' : '',
      isComplete ? 'is-complete' : '',
      gate.locked ? 'is-locked' : '',
      isNext ? 'is-next' : '',
    ]
      .filter(Boolean)
      .join(' ');
    const stateLabel = isActive
      ? 'Current'
      : gate.locked
        ? 'Locked'
        : isComplete
          ? 'Visited'
          : isNext
            ? 'Next'
            : '';
    return `<li class="${classNames}"><span>${step.label}</span><span class="state">${stateLabel}</span></li>`;
  }).join('');
  updateDefaultFlowHint();
}

function syncNavState() {
  const nextScreen = computeNextScreen();
  navButtons.forEach((button) => {
    const target = normalizeScreen(button.dataset.navScreen);
    const gate = getScreenGate(target);
    const isActive = target === state.currentScreen || (target === SCREENS.DASHBOARD && state.currentScreen === SCREENS.ENTRY);
    const isNext = !gate.locked && target === nextScreen;
    button.classList.toggle('is-active', Boolean(isActive));
    button.classList.toggle('is-next', Boolean(isNext && !isActive));
    button.classList.toggle('is-locked', Boolean(gate.locked));
    button.setAttribute('aria-disabled', gate.locked ? 'true' : 'false');
    button.title = gate.locked ? gate.reason || 'Complete prior step' : '';
  });
}

function describeMintStatus() {
  switch (state.mint.status) {
    case 'pending':
      return 'Submitting mint request…';
    case 'success':
      return state.mint.txId ? `Mint successful (${shorten(state.mint.txId)})` : 'Mint successful.';
    case 'error':
      return state.mint.lastError || 'Mint error';
    default:
      return 'Not started';
  }
}

function shorten(value) {
  if (!value || value.length < 11) return value || '';
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}

function escapeHtml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeScreen(value) {
  if (!value) return null;
  const upper = value.toUpperCase();
  if (SCREENS[upper]) return SCREENS[upper];
  const match = Object.values(SCREENS).find((screen) => screen === value);
  return match || null;
}

function getAudioModeForScreen(screen) {
  switch (screen) {
    case SCREENS.AI_GUIDE:
    case SCREENS.MINT:
      return 'focus';
    case SCREENS.LOADING:
      return 'system';
    default:
      return 'ambient';
  }
}

function setAudioMode(mode) {
  console.info('[audio] mode ->', mode);
  if (audioDisplayEl) {
    const label = mode ? `${mode.slice(0, 1).toUpperCase()}${mode.slice(1)}` : 'Ambient';
    audioDisplayEl.textContent = label;
  }
}

function navigateToScreen(target, context = {}, options = {}) {
  const screen = normalizeScreen(target);
  if (!screen) return false;
  const gate = getScreenGate(screen);
  if (gate.locked && !options.force) {
    setFlowHint(gate.reason || 'Complete the previous objective first.', 'warning', { temporary: true });
    flagDeniedInteraction(options.sourceEl);
    return false;
  }
  const alreadyVisited = state.visited.has(screen);
  setScreen(screen, context);
  if (!alreadyVisited && options.flash !== false && screen !== SCREENS.LOADING) {
    const label = getScreenLabel(screen);
    if (label) {
      setFlowHint(`${label} online`, 'progress', { temporary: true });
    }
  }
  return true;
}

function getScreenGate(screen) {
  if (!screen) return { locked: false };
  if (screen === SCREENS.ENTRY || screen === SCREENS.LOADING) {
    return { locked: false };
  }
  const rule = PROGRESSION_RULES[screen];
  if (!rule) return { locked: false };
  if (rule.requires && rule.requires.length) {
    const missing = rule.requires.find((req) => !state.visited.has(req));
    if (missing) {
      return {
        locked: true,
        reason: rule.reason || `Complete ${getScreenLabel(missing)} to unlock ${getScreenLabel(screen)}.`,
        tone: 'warning',
      };
    }
  }
  if (rule.requiresWallet && !state.wallet.connected) {
    return {
      locked: true,
      reason: 'Connect wallet to unlock Mint.',
      tone: 'warning',
    };
  }
  return { locked: false };
}

function getScreenLabel(screen) {
  return SCREEN_LABEL_LOOKUP[screen] || screen || '';
}

function computeNextScreen() {
  return PROGRESSION_CHAIN.find((screen) => !state.visited.has(screen)) || null;
}

function setFlowHint(message, tone = 'info', { temporary = false } = {}) {
  if (!flowHintEl) return;
  if (!message) {
    flowHintEl.textContent = '';
    flowHintEl.dataset.hintState = '';
    flowHintEl.hidden = true;
    return;
  }
  flowHintEl.hidden = false;
  flowHintEl.textContent = message;
  flowHintEl.dataset.hintState = tone;
  if (temporary) {
    flowHintPinned = true;
    if (flowHintTimer) window.clearTimeout(flowHintTimer);
    flowHintTimer = window.setTimeout(() => {
      flowHintPinned = false;
      updateDefaultFlowHint();
    }, 4200);
  }
}

function updateDefaultFlowHint() {
  if (flowHintPinned) return;
  const nextScreen = computeNextScreen();
  if (nextScreen) {
    setFlowHint(`Next objective: ${getScreenLabel(nextScreen)}`);
  } else {
    setFlowHint('All objectives complete — free roam enabled.', 'success');
  }
}

function flagDeniedInteraction(element) {
  if (!element) return;
  element.classList.remove('is-denied');
  // Force reflow so the animation can retrigger.
  // eslint-disable-next-line no-unused-expressions
  element.offsetWidth;
  element.classList.add('is-denied');
  element.addEventListener(
    'animationend',
    () => {
      element.classList.remove('is-denied');
    },
    { once: true },
  );
}

async function submitMintRequest({ recipient, tokenId }) {
  const response = await fetch('/api/mint', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient, tokenId }),
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    // Ignore JSON parse errors so we can surface a readable message below.
  }

  if (!response.ok || !payload?.ok) {
    const message = payload?.error || `Mint failed with status ${response.status}`;
    throw new Error(message);
  }

  return payload;
}
