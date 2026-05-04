/* ======================================================
   Protocol Visualizer — visualizer.js
   ====================================================== */

/* ──────────────────────────────────────
   TAB NAVIGATION
   ────────────────────────────────────── */
function showViz(id, btn) {
    document.querySelectorAll('.viz-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.viz-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('sec-' + id).classList.add('active');
    if (btn) btn.classList.add('active');
}

/* ══════════════════════════════════════
   LIVE FEED — Real-time SocketIO
   ══════════════════════════════════════ */
let liveSocket = null;
let liveStats  = { sessions: new Set(), msgs: 0, rotations: 0 };

const PIPE_MAP = {
    dh_start:     'pipe-dh',
    dh_exchange:  'pipe-dh',
    hkdf:         'pipe-hkdf',
    session_ready:'pipe-hkdf',
    aes_encrypt:  'pipe-enc',
    aes_decrypt:  'pipe-dec',
    key_rotation: null
};

function initLiveFeed() {
    // Re-use the socket already loaded via base.html (socket.io.js)
    liveSocket = io();

    liveSocket.on('connect', () => {
        liveSocket.emit('join_visualizer');
        document.getElementById('lsb-conn-val').textContent = '🟢 Connected';
        pulseBox('lsb-conn');
    });

    liveSocket.on('disconnect', () => {
        document.getElementById('lsb-conn-val').textContent = '🔴 Disconnected';
    });

    liveSocket.on('crypto_event', (data) => {
        handleCryptoEvent(data);
    });

    liveSocket.on('session_state_update', (data) => {
        document.getElementById('lsb-fingerprint').textContent   = data.fingerprint;
        document.getElementById('lsb-until-rotation').textContent = data.msgs_until_rotation + ' msgs';
        pulseBox('lsb-conn');
    });
}

function handleCryptoEvent(data) {
    const { phase, label, detail, color, room_id } = data;

    // Track stats
    if (phase === 'session_ready') {
        liveStats.sessions.add(room_id);
        document.getElementById('lsb-sessions-val').textContent = liveStats.sessions.size;
        document.getElementById('lsb-fingerprint').textContent  = data.fingerprint || '—';
    }
    if (phase === 'aes_encrypt') {
        liveStats.msgs++;
        document.getElementById('lsb-msgs-val').textContent = liveStats.msgs;
        updateDetailCard(data);
    }
    if (phase === 'key_rotation') {
        liveStats.rotations++;
        document.getElementById('lsb-rotations-val').textContent = liveStats.rotations;
        document.getElementById('lsb-fingerprint').textContent   = data.new_fingerprint || '—';
    }

    // Highlight pipeline stage
    const pipeId = PIPE_MAP[phase];
    highlightPipe(pipeId);

    // Also activate net stage on every aes_encrypt (message in transit)
    if (phase === 'aes_encrypt') {
        setTimeout(() => highlightPipe('pipe-net'), 200);
    }

    // Add log entry
    addLogEntry(label, detail, color);
}

function highlightPipe(pipeId) {
    if (!pipeId) return;
    // Reset all
    document.querySelectorAll('.pipeline-stage').forEach(s => {
        s.classList.remove('active-stage');
        const dot = s.querySelector('.pipe-status');
        if (dot) { dot.className = 'pipe-status done'; }
    });
    const stage = document.getElementById(pipeId);
    if (stage) {
        stage.classList.add('active-stage');
        const dot = stage.querySelector('.pipe-status');
        if (dot) dot.className = 'pipe-status active';
        setTimeout(() => {
            stage.classList.remove('active-stage');
            if (dot) dot.className = 'pipe-status done';
        }, 1800);
    }
}

function updateDetailCard(data) {
    document.getElementById('live-detail-card').style.display = 'grid';
    document.getElementById('ldc-plain').textContent = data.plaintext   || '—';
    document.getElementById('ldc-iv').textContent    = data.iv          || '—';
    document.getElementById('ldc-ct').textContent    = data.ciphertext_preview || '—';
    document.getElementById('ldc-tag').textContent   = data.tag         || '—';
    document.getElementById('ldc-fp').textContent    = document.getElementById('lsb-fingerprint').textContent;
}

function addLogEntry(label, detail, color) {
    const log = document.getElementById('live-log');

    // Remove idle message if present
    const idle = log.querySelector('.idle-msg');
    if (idle) idle.remove();

    const div = document.createElement('div');
    div.className = `live-event ev-${color || 'green'}`;
    div.innerHTML = `
        <div class="ev-dot"></div>
        <div class="ev-body">
            <div class="ev-label">${label}</div>
            <div class="ev-detail">${detail}</div>
            <div class="ev-time">${new Date().toLocaleTimeString()}</div>
        </div>`;

    // Insert newest at top
    log.insertBefore(div, log.firstChild);

    // Cap log at 40 entries
    while (log.children.length > 40) log.removeChild(log.lastChild);
}

function pulseBox(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add('pulse');
    setTimeout(() => el.classList.remove('pulse'), 800);
}

function clearLiveLog() {
    document.getElementById('live-log').innerHTML =
        '<div class="live-event idle-msg">⏳ Log cleared. Waiting for activity…</div>';
}

/* ══════════════════════════════════════
   VISUALIZER 1 — DH Key Exchange
   ══════════════════════════════════════ */
let dhStep = 0;

const DH_STEPS = [
    {
        label: "Step 1: Alice generates her secret private key (a). This stays on her device ONLY.",
        show: ['dh-a-priv'], arrows: [],
        eve: "Eve sees: Nothing (private keys are never transmitted)"
    },
    {
        label: "Step 2: Bob generates his secret private key (b). This also stays on his device ONLY.",
        show: ['dh-b-priv'], arrows: [],
        eve: "Eve sees: Nothing (private keys are never transmitted)"
    },
    {
        label: "Step 3: Alice computes her PUBLIC key (g^a mod p) and sends it over the network.",
        show: ['dh-a-pub'], arrows: ['dh-arr1'],
        eve: "Eve sees: Alice's Public Key → g^a mod p = <b style='color:#4da6ff;'>82</b>"
    },
    {
        label: "Step 4: Bob computes his PUBLIC key (g^b mod p) and sends it over the network.",
        show: ['dh-b-pub'], arrows: ['dh-arr1', 'dh-arr2'],
        eve: "Eve sees: A_pub=<b style='color:#4da6ff;'>82</b>, B_pub=<b style='color:#4da6ff;'>57</b>. Cannot compute K without knowing (a) or (b)."
    },
    {
        label: "Step 5: Alice uses Bob's public key + her private key to compute the Shared Secret K.",
        show: ['dh-a-shared'], arrows: ['dh-arr1', 'dh-arr2'],
        eve: "Eve still sees only public keys. She cannot solve the Discrete Log Problem to find K. 🔒"
    },
    {
        label: "Step 6: Bob independently computes the SAME Shared Secret K. Both have K — it was NEVER transmitted!",
        show: ['dh-b-shared'], arrows: ['dh-arr1', 'dh-arr2'],
        eve: "Eve captures: A_pub=82, B_pub=57. She CANNOT compute K = (A_pub)^b mod p without b. ✅ DH is secure."
    }
];

function dhNext() {
    if (dhStep >= DH_STEPS.length) return;
    const s = DH_STEPS[dhStep];
    s.show.forEach(id => document.getElementById(id).classList.add('visible'));
    document.querySelectorAll('.dh-arrow').forEach(a => a.classList.remove('visible'));
    s.arrows.forEach(id => document.getElementById(id).classList.add('visible'));
    document.getElementById('dh-step-label').textContent = s.label;
    document.getElementById('dh-eve').innerHTML = s.eve;
    dhStep++;
    if (dhStep >= DH_STEPS.length) document.getElementById('dh-next').disabled = true;
}

function dhReset() {
    dhStep = 0;
    document.querySelectorAll('.dh-value').forEach(el => el.classList.remove('visible'));
    document.querySelectorAll('.dh-arrow').forEach(el => el.classList.remove('visible'));
    document.getElementById('dh-step-label').textContent = 'Press "Next Step" to begin the simulation.';
    document.getElementById('dh-eve').textContent = 'Eve sees: Nothing yet (no traffic)';
    document.getElementById('dh-next').disabled = false;
}

/* ══════════════════════════════════════
   VISUALIZER 2 — AES-GCM
   ══════════════════════════════════════ */
let aesTamper = false;
let aesEncrypted = false;

function aesToggleTamper() { aesTamper = document.getElementById('tamper-check').checked; }

function aesEncrypt() {
    const iv  = generateFakeHex(12);
    const ct  = generateFakeHex(24);
    const tag = generateFakeHex(16);
    setField('aes-iv',  `IV (Random): <b>${iv}</b>`, '');
    setField('aes-enc', `Ciphertext: <b>${ct}</b>`, 'cipher');
    setField('aes-tag', `Auth Tag: <b>${tag}</b>`, 'tag');
    setField('aes-relay', `Relaying: <b>${ct.slice(0,16)}…</b>`, 'cipher');
    window._aesData = { ct, tag, iv };
    document.getElementById('aes-step-label').textContent =
        '🔒 AES-GCM encrypted! Alice\'s plaintext is now ciphertext. Server relays without reading it.';
    document.getElementById('aes-decrypt-btn').disabled = false;
    aesEncrypted = true;
}

function aesDecrypt() {
    if (!aesEncrypted) return;
    const d = window._aesData;
    if (aesTamper) {
        const tampered = d.ct.slice(0,-1) + ((d.ct.slice(-1)==='a')?'b':'a');
        setField('aes-recv-cipher', `Ciphertext (TAMPERED): <b>${tampered}</b>`, 'fail');
        setField('aes-recv-tag',   `Auth Tag: <b>${d.tag}</b>`, 'tag');
        setTimeout(() => {
            setField('aes-result', `❌ AUTH TAG MISMATCH — DECRYPTION REJECTED`, 'fail');
            document.getElementById('aes-step-label').textContent =
                '💀 AES-GCM auth tag verification FAILED. Bob rejects the tampered message. Integrity preserved!';
        }, 600);
    } else {
        setField('aes-recv-cipher', `Ciphertext: <b>${d.ct}</b>`, 'cipher');
        setField('aes-recv-tag',   `Auth Tag: <b>${d.tag}</b>`, 'tag');
        setTimeout(() => {
            setField('aes-result', `✅ Plaintext: <b>"Hello Bob!"</b>`, 'plain');
            document.getElementById('aes-step-label').textContent =
                '✅ AES-GCM decryption successful! Auth tag matched. Confidentiality + Integrity preserved.';
        }, 600);
    }
}

function aesReset() {
    [['aes-iv','IV (Random): <b>—</b>',''],['aes-enc','Ciphertext: <b>—</b>','cipher'],
     ['aes-tag','Auth Tag: <b>—</b>','tag'],['aes-relay','—','cipher'],
     ['aes-recv-cipher','Ciphertext: <b>—</b>','cipher'],['aes-recv-tag','Auth Tag: <b>—</b>','tag'],
     ['aes-result','Decrypted: <b>—</b>','']].forEach(([id,html,cls]) => setField(id,html,cls));
    document.getElementById('aes-step-label').textContent = 'Press "Encrypt" to start.';
    document.getElementById('aes-decrypt-btn').disabled = true;
    document.getElementById('tamper-check').checked = false;
    aesTamper = false; aesEncrypted = false;
}

function setField(id, html, cls) {
    const el = document.getElementById(id);
    el.innerHTML = html;
    el.className = 'aes-field' + (cls ? ' ' + cls : '');
}
function generateFakeHex(bytes) {
    let r='0x'; const c='0123456789abcdef';
    for(let i=0;i<bytes*2;i++) r+=c[Math.floor(Math.random()*16)];
    return r;
}

/* ══════════════════════════════════════
   VISUALIZER 3 — Forward Secrecy Timeline
   ══════════════════════════════════════ */
const FS_WINDOWS = [
    { key:'K₁', hash:'3a8fd2c1', msgs:['Msg 1','Msg 2','Msg 3','Msg 4','Msg 5'] },
    { key:'K₂', hash:'b7e41f09', msgs:['Msg 6','Msg 7','Msg 8','Msg 9','Msg 10'] },
    { key:'K₃', hash:'f2c09a5e', msgs:['Msg 11','Msg 12','Msg 13','Msg 14','Msg 15'] },
];
function fsRender(compromisedKey=null) {
    const c = document.getElementById('fs-timeline');
    c.innerHTML='';
    FS_WINDOWS.forEach(w => {
        const isC = compromisedKey && w.key===compromisedKey;
        const isP = compromisedKey && w.key!==compromisedKey;
        const div = document.createElement('div');
        div.className='fs-window'+(isC?' compromised':isP?' protected':'');
        div.innerHTML=`<div class="fs-key-label"><div class="key-id">${w.key}</div><div class="key-hash">${w.hash}</div></div>
            <div class="fs-messages">${w.msgs.map(m=>`<span class="fs-msg${isC?' compromised-msg':isP?' protected-msg':''}">${m}</span>`).join('')}</div>
            ${isC?'<div class="fs-status bad">💀 EXPOSED</div>':isP?'<div class="fs-status ok">🛡️ SAFE</div>':''}`;
        c.appendChild(div);
    });
}
function fsSimulate() {
    fsRender('K₃');
    document.getElementById('fs-attacker-action').style.display='flex';
    document.getElementById('fs-stolen-key').textContent='K₃ (f2c09a5e)';
    document.getElementById('fs-step-label').innerHTML=
        '💥 Attacker steals <strong>K₃</strong>. Messages 1–10 (K₁+K₂) remain <strong style="color:var(--green)">PERMANENTLY PROTECTED</strong>. Only 11–15 exposed. <strong style="color:var(--green)">Forward Secrecy!</strong>';
}
function fsReset() {
    fsRender(null);
    document.getElementById('fs-attacker-action').style.display='none';
    document.getElementById('fs-step-label').textContent='Press "Simulate Compromise" to show forward secrecy in action.';
}

/* ══════════════════════════════════════
   VISUALIZER 4 — Attack Matrix
   ══════════════════════════════════════ */
const MATRIX_DATA=[
    {attack:'Passive Eavesdropping',
     plain:{cls:'cell-red',label:'💀 Plaintext Visible',detail:'Attacker reads every message. Full confidentiality loss.'},
     enc:{cls:'cell-green',label:'✅ Ciphertext Only',detail:'Only AES-GCM blobs intercepted. Cannot read without key.'},
     fs:{cls:'cell-green',label:'✅ Ciphertext Only',detail:'Same as encrypted, plus rekeying hampers traffic analysis.'}},
    {attack:'Database Leak',
     plain:{cls:'cell-red',label:'💀 Full History Exposed',detail:'All stored messages are plaintext. One breach = all history stolen.'},
     enc:{cls:'cell-yellow',label:'⚠️ Ciphertext (Key risk)',detail:'Ciphertexts only. But if static key leaks, all history decrypts.'},
     fs:{cls:'cell-green',label:'✅ Ciphertext Only',detail:'Even if one key leaks, only one window of msgs is at risk.'}},
    {attack:'Session Key Compromise',
     plain:{cls:'cell-red',label:'🚫 N/A (No Keys)',detail:'No encryption. All messages always exposed.'},
     enc:{cls:'cell-red',label:'💀 Entire Session Exposed',detail:'Single static key compromised = all history decryptable.'},
     fs:{cls:'cell-yellow',label:'⚠️ Current Window Only',detail:'Past keys permanently destroyed. Only ~5 recent msgs exposed.'}},
    {attack:'Replay Attack',
     plain:{cls:'cell-red',label:'💀 Accepted',detail:'Replayed message accepted verbatim. No detection.'},
     enc:{cls:'cell-yellow',label:'⚠️ May Be Accepted',detail:'AES-GCM checks integrity but not sequence without app nonce.'},
     fs:{cls:'cell-green',label:'✅ Rejected',detail:'Key rotation means old ciphertexts fail under new keys.'}},
    {attack:'Message Tampering',
     plain:{cls:'cell-red',label:'💀 Accepted',detail:'No integrity. Attacker can modify content freely.'},
     enc:{cls:'cell-green',label:'✅ Rejected',detail:'Any 1-bit change breaks AES-GCM auth tag. Rejected.'},
     fs:{cls:'cell-green',label:'✅ Rejected',detail:'Same AES-GCM guarantee. Tampering always rejected.'}}
];

function renderMatrix() {
    const tb=document.getElementById('matrix-body'); tb.innerHTML='';
    MATRIX_DATA.forEach(row => {
        const tr=document.createElement('tr');
        tr.innerHTML=`<td class="attack-label">${row.attack}</td>
            <td class="${row.plain.cls}">${row.plain.label}<div class="cell-tooltip">${row.plain.detail}</div></td>
            <td class="${row.enc.cls}">${row.enc.label}<div class="cell-tooltip">${row.enc.detail}</div></td>
            <td class="${row.fs.cls}">${row.fs.label}<div class="cell-tooltip">${row.fs.detail}</div></td>`;
        tb.appendChild(tr);
    });
}

/* ══════════════════════════════════════
   INIT
   ══════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
    initLiveFeed();
    dhReset();
    fsRender(null);
    renderMatrix();
});


