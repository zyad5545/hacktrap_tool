// attacks-poller.js - poll /api/attacks on same origin
async function fetchAttacks() {
  try {
    const resp = await fetch('/api/attacks', { credentials: 'same-origin' });
    const contentType = resp.headers.get('content-type') || '';
    if (!resp.ok) {
      console.warn('attacks poll bad status', resp.status);
      return [];
    }
    if (contentType.includes('application/json')) {
      return await resp.json();
    } else {
      // Received HTML or text instead of JSON — avoid bad_json
      console.warn('attacks poll got non-json:', contentType);
      return [];
    }
  } catch (e) {
    console.error('attacks poll error', e);
    return [];
  }
}

function renderAttacks(list) {
  // simple renderer (replace with your real rendering)
  const el = document.getElementById('attacks-list');
  if (!el) return;
  el.innerHTML = list.length ? list.map(a => `<li>${a.id} ${a.payload || ''} ${a.severity || ''}</li>`).join('') : '<li>No attacks</li>';
}

async function startPoller(intervalSeconds = 2.0) {
  setInterval(async () => {
    const attacks = await fetchAttacks();
    renderAttacks(attacks);
  }, Math.max(500, intervalSeconds * 1000));
}

// start
startPoller(parseFloat(window.DASH_POLL_INTERVAL || 2.0));
