const GUIDE_LOG_SELECTOR = '[data-guide-log]';
const GUIDE_FORM_SELECTOR = '[data-guide-form]';
const GUIDE_INPUT_SELECTOR = '[data-guide-input]';
const GUIDE_SEND_SELECTOR = '[data-guide-send]';
const GUIDE_ACTION_SELECTOR = '[data-guide-action]';
let audioElement = null;

export function initAiGuideUI(options = {}) {
  const logEl = document.querySelector(GUIDE_LOG_SELECTOR);
  const form = document.querySelector(GUIDE_FORM_SELECTOR);
  const input = form?.querySelector(GUIDE_INPUT_SELECTOR);
  const sendButton = form?.querySelector(GUIDE_SEND_SELECTOR);

  if (!form || !input || !logEl) {
    return;
  }

  if (form.dataset.guideBound === 'true') {
    return;
  }
  form.dataset.guideBound = 'true';

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) {
      return;
    }

    appendLogEntry(logEl, 'user', value);
    notifyLog(options, { role: 'user', text: value, actions: [] });
    scrollLog(logEl);
    input.value = '';
    setPending(true);

    try {
      const response = await sendGuideMessage(value);
      const replyText = response?.text && response.text.trim().length > 0
        ? response.text
        : 'Guide is unavailable for this question. Try again soon.';
      appendLogEntry(logEl, 'guide', replyText, response?.actions ?? []);
      notifyLog(options, {
        role: 'guide',
        text: replyText,
        audioUrl: response?.audioUrl ?? null,
        actions: Array.isArray(response?.actions) ? response.actions : [],
      });
    } catch (error) {
      console.error('Guide request failed', error);
      const fallback = 'Guide link offline. Please retry in a moment.';
      appendLogEntry(logEl, 'guide', fallback, []);
      notifyLog(options, { role: 'guide', text: fallback, audioUrl: null, actions: [] });
    } finally {
      setPending(false);
      scrollLog(logEl);
      input.focus();
    }
  });

  logEl.addEventListener('click', (event) => {
    const button = event.target.closest(GUIDE_ACTION_SELECTOR);
    if (!button) return;
    const type = button.dataset.guideAction;
    if (type === 'open_url') {
      const url = button.dataset.guideActionUrl;
      if (url) {
        window.open(url, '_blank', 'noopener');
      }
      return;
    }
    if (type === 'open_route') {
      const screen = button.dataset.guideActionScreen;
      if (screen && typeof options?.setScreen === 'function') {
        options.setScreen(screen);
      }
    }
  });

  function setPending(isPending) {
    input.disabled = isPending;
    if (sendButton) {
      sendButton.disabled = isPending;
    }
    form.dataset.pending = isPending ? 'true' : 'false';
  }
}

export async function sendGuideMessage(text) {
  const response = await fetch('/api/guide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: text }),
  });

  if (!response.ok) {
    throw new Error(`Guide request failed with status ${response.status}`);
  }

  const payload = await response.json();
  const normalized = {
    text: typeof payload?.text === 'string' ? payload.text : '',
    audioUrl: typeof payload?.audioUrl === 'string' && payload.audioUrl.trim().length > 0 ? payload.audioUrl : null,
    actions: normalizeGuideActions(payload?.actions),
  };

  if (normalized.audioUrl) {
    playGuideAudio(normalized.audioUrl);
  }

  return normalized;
}

export function playGuideAudio(audioUrl) {
  if (!audioUrl) {
    return;
  }

  if (!audioElement) {
    audioElement = document.createElement('audio');
    audioElement.hidden = true;
    audioElement.preload = 'auto';
    audioElement.dataset.role = 'guide-audio';
    document.body?.appendChild(audioElement);
  }

  audioElement.src = audioUrl;
  audioElement.play().catch((error) => {
    console.warn('Unable to play guide audio', error);
  });
}

function appendLogEntry(container, role, text, actions = []) {
  const placeholder = container.querySelector('[data-guide-placeholder]');
  if (placeholder) {
    placeholder.remove();
  }

  const row = document.createElement('div');
  row.className = `chat-row ${role}`;

  const label = document.createElement('span');
  label.textContent = role === 'user' ? 'You' : 'Guide reply';

  const body = document.createElement('p');
  body.textContent = text;

  row.appendChild(label);
  row.appendChild(body);
  if (role === 'guide') {
    const actionsContainer = document.createElement('div');
    actionsContainer.className = 'guide-actions';
    actionsContainer.setAttribute('data-guide-actions', '');
    renderGuideActions(actionsContainer, actions);
    row.appendChild(actionsContainer);
  }
  container.appendChild(row);
}

function notifyLog(options, entry) {
  if (typeof options?.onLogEntry === 'function') {
    options.onLogEntry({
      ...entry,
      actions: Array.isArray(entry?.actions) ? entry.actions : [],
    });
  }
}

function scrollLog(container) {
  requestAnimationFrame(() => {
    container.scrollTop = container.scrollHeight;
  });
}

function normalizeGuideActions(actions) {
  if (!Array.isArray(actions)) {
    return [];
  }
  return actions
    .map((action) => {
      if (!action || typeof action !== 'object') return null;
      const type = typeof action.type === 'string' ? action.type : '';
      const label = typeof action.label === 'string' && action.label.trim().length > 0 ? action.label.trim() : null;
      if (type === 'open_url' && typeof action.url === 'string' && action.url.trim().length > 0) {
        return {
          type,
          url: action.url.trim(),
          label: label || 'Open link',
        };
      }
      if (type === 'open_route' && typeof action.screen === 'string' && action.screen.trim().length > 0) {
        return {
          type,
          screen: action.screen.trim(),
          label: label || 'Go to route',
        };
      }
      return null;
    })
    .filter(Boolean);
}

function renderGuideActions(container, actions) {
  if (!container) return;
  container.innerHTML = '';
  const list = normalizeGuideActions(actions);
  if (!list.length) {
    container.hidden = true;
    return;
  }
  container.hidden = false;
  list.forEach((action) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn ghost';
    button.textContent = action.label || 'Action';
    button.dataset.guideAction = action.type;
    if (action.type === 'open_url') {
      button.dataset.guideActionUrl = action.url;
    }
    if (action.type === 'open_route') {
      button.dataset.guideActionScreen = action.screen;
    }
    container.appendChild(button);
  });
}
