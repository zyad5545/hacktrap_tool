// dashboard/static/attacks-poller.js
const API_KEY = 'demo-key';
async function fetchAttacks() {
    try {
        const res = await fetch('/api/attacks?limit=50', {
            headers: { 'X-API-KEY': API_KEY }
        });
        const data = await res.json();
        if (data.attacks) {
            renderAttacks(data.attacks);
        }
    } catch (e) {
        console.error('Failed to fetch attacks', e);
    }
}

function renderAttacks(attacks) {
    const tbody = document.getElementById('attacks-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    attacks.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${a.id}</td>
            <td>${a.attack_type}</td>
            <td>${a.source_ip}</td>
            <td>${a.timestamp}</td>
            <td>${a.status || 'unknown'}</td>
            <td>${a.severity || ''}</td>
            <td>${a.blockchain_tx_hash ? `<a href="#" title="${a.blockchain_tx_hash}">${a.blockchain_tx_hash.slice(0,10)}...</a>` : '—'}</td>
            <td><button class="view-details" data-id="${a.id}">View</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// poll every 5s
setInterval(fetchAttacks, 5000);
document.addEventListener('DOMContentLoaded', fetchAttacks);
