// Petri Net Protocol Viewer — Interactive SVG simulator
// Matches the formal model in docs/protocol.md
// Responsive: vertical happy path on wide screens, horizontal on narrow

export class PetriNetViewer {
  constructor(container) {
    this.container = container;
    this.marking = {};
    this.log = [];
    this.completed = false;
    this._defineNet();
    this._build();
    this._onResize = () => this._applyLayout();
    window.addEventListener('resize', this._onResize);
    this.reset();
  }

  // ── Net definition (topology only, no coords) ──────────────

  _defineNet() {
    this.places = [
      // Happy path (center column)
      { id: 'ready', label: 'ready' },
      { id: 'swap_agreed', label: 'swap_agreed' },
      { id: 'btc_locked', label: 'btc_locked' },
      { id: 'both_locked', label: 'both_locked' },
      { id: 'presigs_ready', label: 'presigs_ready' },
      { id: 't_revealed', label: 't_revealed' },
      { id: 'done', label: 'done' },
      // Cancel path
      { id: 'alph_refundable', label: 'alph_refundable' },
      { id: 'btc_cancel_wait', label: 'btc_cancel_wait' },
      { id: 'btc_cancel_refundable', label: 'btc_cancel_refundable' },
      { id: 'recovery_done', label: 'recovery_done' },
      // Abort path
      { id: 'btc_abort_wait', label: 'btc_abort_wait' },
      { id: 'btc_abort_refundable', label: 'btc_abort_refundable' },
    ];

    this.transitions = [
      { id: 'start', label: 'start', actor: null,
        inputs: [], outputs: ['ready'],
        desc: 'Initialize the protocol' },
      { id: 'negotiate', label: 'negotiate', actor: null,
        inputs: ['ready'], outputs: ['swap_agreed'],
        desc: 'Both parties agree on swap parameters' },
      { id: 'negotiate_timeout', label: 'neg_timeout', actor: 'timeout',
        inputs: ['swap_agreed'], outputs: ['done'],
        desc: 'Bob doesn\'t lock BTC — abort' },
      { id: 'lock_btc', label: 'lock_btc', actor: 'Bob',
        inputs: ['swap_agreed'], outputs: ['btc_locked'],
        desc: 'Bob locks BTC in taproot output' },
      { id: 'lock_timeout', label: 'lock_timeout', actor: 'timeout',
        inputs: ['btc_locked'], outputs: ['btc_abort_wait'],
        desc: 'Alice doesn\'t lock ALPH — Bob waits for refund' },
      { id: 'lock_alph', label: 'lock_alph', actor: 'Alice',
        inputs: ['btc_locked'], outputs: ['both_locked'],
        desc: 'Alice locks ALPH in Ralph contract' },
      { id: 'exchange_presigs', label: 'exch_presigs', actor: null,
        inputs: ['both_locked'], outputs: ['presigs_ready'],
        desc: 'Exchange adaptor pre-signatures via Nostr' },
      { id: 'exchange_timeout', label: 'exch_timeout', actor: 'timeout',
        inputs: ['both_locked'], outputs: ['alph_refundable', 'btc_cancel_wait'],
        desc: 'Pre-sig exchange stalls — fork to cancel' },
      { id: 'alice_claims_btc', label: 'alice_claim', actor: 'Alice',
        inputs: ['presigs_ready'], outputs: ['t_revealed'],
        desc: 'Alice claims BTC, revealing adaptor secret t' },
      { id: 't2_timeout', label: 't2_timeout', actor: 'timeout',
        inputs: ['presigs_ready'], outputs: ['alph_refundable', 'btc_cancel_wait'],
        desc: 'Alice doesn\'t claim — fork to cancel' },
      { id: 'bob_claims_alph', label: 'bob_claim', actor: 'Bob',
        inputs: ['t_revealed'], outputs: ['done'],
        desc: 'Bob extracts t and claims ALPH' },
      // Cancel path
      { id: 'alice_cancel_refund', label: 'alice_refund', actor: 'Alice',
        inputs: ['alph_refundable'], outputs: ['recovery_done'],
        desc: 'Alice refunds ALPH after T2' },
      { id: 't1_timeout', label: 't1_timeout', actor: 'timeout',
        inputs: ['btc_cancel_wait'], outputs: ['btc_cancel_refundable'],
        desc: 'T1 expires — Bob can refund BTC' },
      { id: 'bob_cancel_refund', label: 'bob_refund', actor: 'Bob',
        inputs: ['btc_cancel_refundable'], outputs: ['recovery_done'],
        desc: 'Bob refunds BTC after T1' },
      { id: 'both_recovered', label: 'both_recov', actor: null,
        inputs: ['recovery_done', 'recovery_done'], outputs: ['done'],
        desc: 'Both refunds complete — join' },
      // Abort path
      { id: 't1_timeout_abort', label: 't1_abort', actor: 'timeout',
        inputs: ['btc_abort_wait'], outputs: ['btc_abort_refundable'],
        desc: 'T1 expires — Bob can refund locked BTC' },
      { id: 'bob_abort_refund', label: 'bob_abort', actor: 'Bob',
        inputs: ['btc_abort_refundable'], outputs: ['done'],
        desc: 'Bob refunds BTC (abort path)' },
      { id: 'stop', label: 'stop', actor: null,
        inputs: ['done'], outputs: [],
        desc: 'Protocol terminates — net is empty' },
    ];
  }

  // ── Layout (responsive) ────────────────────────────────────

  _applyLayout() {
    const wide = this.container.offsetWidth > 540;
    if (wide) this._layoutVertical(); else this._layoutHorizontal();
    this._render();
  }

  _pos(map, id, x, y) { map[id] = { x, y }; }

  _layoutVertical() {
    // Happy path: center column
    // Abort: left column        Cancel: right column (fully separate)
    const S = 55;
    const cx = 340, lx = 100, rx = 600;
    const pMap = {}, tMap = {};

    // Happy path — center column
    let y = 25;
    this._pos(tMap, 'start', cx, y);            y += S;
    this._pos(pMap, 'ready', cx, y);             y += S;
    this._pos(tMap, 'negotiate', cx, y);         y += S;
    this._pos(pMap, 'swap_agreed', cx, y);       y += S;
    this._pos(tMap, 'lock_btc', cx, y);          y += S;
    this._pos(pMap, 'btc_locked', cx, y);        y += S;
    this._pos(tMap, 'lock_alph', cx, y);         y += S;
    this._pos(pMap, 'both_locked', cx, y);       y += S;
    this._pos(tMap, 'exchange_presigs', cx, y);  y += S;
    this._pos(pMap, 'presigs_ready', cx, y);     y += S;
    this._pos(tMap, 'alice_claims_btc', cx, y);  y += S;
    this._pos(pMap, 't_revealed', cx, y);        y += S;
    this._pos(tMap, 'bob_claims_alph', cx, y);   y += S;
    this._pos(pMap, 'done', cx, y);              y += S;
    this._pos(tMap, 'stop', cx, y);
    const happyBottom = y;

    // Abort path (left column) — branches from swap_agreed and btc_locked
    const saY = pMap.swap_agreed.y;
    const blY = pMap.btc_locked.y;
    this._pos(tMap, 'negotiate_timeout', lx, saY);
    this._pos(tMap, 'lock_timeout', lx, blY);
    this._pos(pMap, 'btc_abort_wait', lx, blY + S);
    this._pos(tMap, 't1_timeout_abort', lx, blY + S * 2);
    this._pos(pMap, 'btc_abort_refundable', lx, blY + S * 3);
    this._pos(tMap, 'bob_abort_refund', lx, blY + S * 4);
    // bob_abort_refund → done: long arc to center, that's fine

    // Cancel path (right column, fully on the right)
    // Branches from both_locked and presigs_ready
    const bkY = pMap.both_locked.y;
    const prY = pMap.presigs_ready.y;
    this._pos(tMap, 'exchange_timeout', rx, bkY);
    this._pos(tMap, 't2_timeout', rx, prY);
    // Fork into two sub-columns under rx
    const forkY = prY + S;
    const rlx = rx - 60, rrx = rx + 60; // cancel left/right sub-columns
    this._pos(pMap, 'alph_refundable', rlx, forkY);
    this._pos(pMap, 'btc_cancel_wait', rrx, forkY);
    this._pos(tMap, 'alice_cancel_refund', rlx, forkY + S);
    this._pos(tMap, 't1_timeout', rrx, forkY + S);
    this._pos(pMap, 'btc_cancel_refundable', rrx, forkY + S * 2);
    this._pos(tMap, 'bob_cancel_refund', rrx, forkY + S * 3);
    // Join back at rx column
    this._pos(pMap, 'recovery_done', rx, forkY + S * 4);
    this._pos(tMap, 'both_recovered', rx, forkY + S * 5);
    // both_recovered → done: long arc back to center, that's fine

    for (const p of this.places) { const c = pMap[p.id]; if (c) { p.x = c.x; p.y = c.y; } }
    for (const t of this.transitions) { const c = tMap[t.id]; if (c) { t.x = c.x; t.y = c.y; } }

    const maxY = Math.max(happyBottom + 20, forkY + S * 5.5);
    this.svg.setAttribute('viewBox', `0 0 760 ${maxY}`);
  }

  _layoutHorizontal() {
    // Happy path: left to right, generous 55px steps
    // Abort: branch below-left   Cancel: branch below-right
    const S = 55;
    const cy = 50;
    const pMap = {}, tMap = {};

    let x = 30;
    this._pos(tMap, 'start', x, cy);            x += S;
    this._pos(pMap, 'ready', x, cy);             x += S;
    this._pos(tMap, 'negotiate', x, cy);         x += S;
    this._pos(pMap, 'swap_agreed', x, cy);       x += S;
    this._pos(tMap, 'lock_btc', x, cy);          x += S;
    this._pos(pMap, 'btc_locked', x, cy);        x += S;
    this._pos(tMap, 'lock_alph', x, cy);         x += S;
    this._pos(pMap, 'both_locked', x, cy);       x += S;
    this._pos(tMap, 'exchange_presigs', x, cy);  x += S;
    this._pos(pMap, 'presigs_ready', x, cy);     x += S;
    this._pos(tMap, 'alice_claims_btc', x, cy);  x += S;
    this._pos(pMap, 't_revealed', x, cy);        x += S;
    this._pos(tMap, 'bob_claims_alph', x, cy);   x += S;
    this._pos(pMap, 'done', x, cy);              x += S;
    this._pos(tMap, 'stop', x, cy);
    const totalW = x + 30;

    // Abort path (below left section)
    const saX = pMap.swap_agreed.x;
    const blX = pMap.btc_locked.x;
    const abY = cy + S;
    this._pos(tMap, 'negotiate_timeout', saX, abY);
    this._pos(tMap, 'lock_timeout', blX, abY);
    this._pos(pMap, 'btc_abort_wait', blX, abY + S);
    this._pos(tMap, 't1_timeout_abort', blX, abY + S * 2);
    this._pos(pMap, 'btc_abort_refundable', blX, abY + S * 3);
    this._pos(tMap, 'bob_abort_refund', blX, abY + S * 4);

    // Cancel path (below right section)
    const bkX = pMap.both_locked.x;
    const prX = pMap.presigs_ready.x;
    const cnY = cy + S;
    this._pos(tMap, 'exchange_timeout', bkX, cnY);
    this._pos(tMap, 't2_timeout', prX, cnY);
    const midX = (bkX + prX) / 2;
    this._pos(pMap, 'alph_refundable', midX - 40, cnY + S);
    this._pos(pMap, 'btc_cancel_wait', midX + 40, cnY + S);
    this._pos(tMap, 'alice_cancel_refund', midX - 40, cnY + S * 2);
    this._pos(tMap, 't1_timeout', midX + 40, cnY + S * 2);
    this._pos(pMap, 'btc_cancel_refundable', midX + 40, cnY + S * 3);
    this._pos(tMap, 'bob_cancel_refund', midX + 40, cnY + S * 4);
    this._pos(pMap, 'recovery_done', midX, cnY + S * 4);
    this._pos(tMap, 'both_recovered', midX, cnY + S * 5);

    for (const p of this.places) { const c = pMap[p.id]; if (c) { p.x = c.x; p.y = c.y; } }
    for (const t of this.transitions) { const c = tMap[t.id]; if (c) { t.x = c.x; t.y = c.y; } }

    const maxY = cnY + S * 5.5;
    this.svg.setAttribute('viewBox', `0 0 ${totalW} ${maxY}`);
  }

  // ── State logic ─────────────────────────────────────────────

  reset() {
    this.marking = {};
    this.log = [];
    this.completed = false;
    this._applyLayout();
  }

  _tokens(placeId) { return this.marking[placeId] || 0; }

  getEnabled() {
    return this.transitions.filter(t => {
      const needed = {};
      for (const p of t.inputs) needed[p] = (needed[p] || 0) + 1;
      return Object.entries(needed).every(([p, n]) => this._tokens(p) >= n);
    });
  }

  fire(id) {
    const t = this.transitions.find(tr => tr.id === id);
    if (!t) return;
    const needed = {};
    for (const p of t.inputs) needed[p] = (needed[p] || 0) + 1;
    for (const [p, n] of Object.entries(needed)) {
      if (this._tokens(p) < n) return;
    }
    for (const p of t.inputs) this.marking[p]--;
    for (const p of t.outputs) this.marking[p] = (this.marking[p] || 0) + 1;
    for (const p of Object.keys(this.marking)) {
      if (this.marking[p] <= 0) delete this.marking[p];
    }
    const actor = t.actor ? ` (${t.actor})` : '';
    this.log.push(`${t.label}${actor}`);
    if (t.id === 'stop') this.completed = true;
    this._render();
  }

  // ── SVG rendering ───────────────────────────────────────────

  _build() {
    this.container.innerHTML = '';

    // Controls
    const controls = document.createElement('div');
    controls.className = 'petri-controls';
    this.startBtn = document.createElement('button');
    this.startBtn.className = 'sm primary';
    this.startBtn.textContent = 'Start';
    this.startBtn.addEventListener('click', () => this.fire('start'));
    this.resetBtn = document.createElement('button');
    this.resetBtn.className = 'sm';
    this.resetBtn.textContent = 'Reset';
    this.resetBtn.addEventListener('click', () => this.reset());
    this.statusEl = document.createElement('span');
    this.statusEl.style.cssText = 'font-size:11px; color:#8b949e; margin-left:8px';
    controls.append(this.startBtn, this.resetBtn, this.statusEl);
    this.container.appendChild(controls);

    // Legend
    const legend = document.createElement('div');
    legend.style.cssText = 'display:flex; gap:12px; margin-bottom:6px; font-size:10px; flex-wrap:wrap;';
    legend.innerHTML = [
      ['#00d4aa', 'Alice'], ['#f7931a', 'Bob'], ['#d29922', 'Timeout'], ['#8b949e', 'System']
    ].map(([c, l]) => `<span><span style="display:inline-block;width:8px;height:8px;background:${c};border-radius:2px;margin-right:3px;vertical-align:middle"></span><span style="color:${c}">${l}</span></span>`).join('');
    this.container.appendChild(legend);

    // SVG
    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('width', '100%');
    this.svg.style.cssText = 'display:block; background:#0d1117; border:1px solid #30363d; border-radius:6px;';
    this.container.appendChild(this.svg);

    // Tooltip
    this.tooltip = document.createElement('div');
    this.tooltip.style.cssText = 'position:fixed; background:#161b22; border:1px solid #30363d; border-radius:4px; padding:4px 8px; font-size:10px; color:#c9d1d9; pointer-events:none; z-index:9999; display:none; max-width:220px;';
    document.body.appendChild(this.tooltip);

    // Log
    this.logEl = document.createElement('div');
    this.logEl.className = 'petri-log';
    this.container.appendChild(this.logEl);

    // Completion message
    this.completeEl = document.createElement('div');
    this.completeEl.style.cssText = 'text-align:center; padding:8px; font-size:11px; color:#2ea043; background:#2ea04311; border:1px solid #2ea04333; border-radius:4px; margin-top:6px; display:none;';
    this.completeEl.textContent = 'Protocol complete — all tokens consumed';
    this.container.appendChild(this.completeEl);

    // SVG defs
    const defs = this._svgEl('defs');
    for (const [id, fill] of [['arrowhead', '#484f58'], ['arrowhead-on', '#8b949e']]) {
      const marker = this._svgEl('marker', {
        id, markerWidth: 8, markerHeight: 6,
        refX: 7, refY: 3, orient: 'auto', markerUnits: 'userSpaceOnUse'
      });
      marker.appendChild(this._svgEl('path', { d: 'M0,0 L8,3 L0,6 Z', fill }));
      defs.appendChild(marker);
    }
    this.svg.appendChild(defs);
  }

  _svgEl(tag, attrs = {}) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  }

  _actorColor(actor) {
    if (actor === 'Alice') return '#00d4aa';
    if (actor === 'Bob') return '#f7931a';
    if (actor === 'timeout') return '#d29922';
    return '#8b949e';
  }

  _render() {
    const defs = this.svg.querySelector('defs');
    this.svg.innerHTML = '';
    this.svg.appendChild(defs);

    const enabled = new Set(this.getEnabled().map(t => t.id));
    const placeMap = {};
    for (const p of this.places) placeMap[p.id] = p;

    // Draw arcs
    for (const t of this.transitions) {
      const isOn = enabled.has(t.id);
      const seen = {};
      for (const pId of t.inputs) {
        if (!seen[pId]) { seen[pId] = 1; const p = placeMap[pId]; if (p) this._drawArc(p.x, p.y, t.x, t.y, isOn, 'to-t'); }
      }
      const seenO = {};
      for (const pId of t.outputs) {
        if (!seenO[pId]) { seenO[pId] = 1; const p = placeMap[pId]; if (p) this._drawArc(t.x, t.y, p.x, p.y, isOn, 'to-p'); }
      }
    }

    // Draw places
    for (const p of this.places) {
      const tok = this._tokens(p.id);
      const g = this._svgEl('g');
      g.appendChild(this._svgEl('circle', {
        cx: p.x, cy: p.y, r: 16,
        fill: tok > 0 ? '#161b22' : '#0d1117',
        stroke: tok > 0 ? '#58a6ff' : '#30363d',
        'stroke-width': tok > 0 ? 2 : 1
      }));
      if (tok === 1) {
        g.appendChild(this._svgEl('circle', { cx: p.x, cy: p.y, r: 5, fill: '#58a6ff' }));
      } else if (tok >= 2) {
        g.appendChild(this._svgEl('circle', { cx: p.x - 5, cy: p.y, r: 4, fill: '#58a6ff' }));
        g.appendChild(this._svgEl('circle', { cx: p.x + 5, cy: p.y, r: 4, fill: '#58a6ff' }));
      }
      const lbl = this._svgEl('text', {
        x: p.x, y: p.y + 27, 'text-anchor': 'middle',
        fill: '#8b949e', 'font-size': 8, 'font-family': 'monospace'
      });
      lbl.textContent = p.label;
      g.appendChild(lbl);
      this.svg.appendChild(g);
    }

    // Draw transitions
    for (const t of this.transitions) {
      const isOn = enabled.has(t.id);
      const color = this._actorColor(t.actor);
      const g = this._svgEl('g', {
        opacity: isOn ? 1 : 0.35,
        style: isOn ? 'cursor:pointer' : 'cursor:default'
      });
      if (isOn) {
        g.appendChild(this._svgEl('rect', {
          x: t.x - 30, y: t.y - 10, width: 60, height: 20, rx: 4,
          fill: color, opacity: 0.15
        }));
      }
      g.appendChild(this._svgEl('rect', {
        x: t.x - 28, y: t.y - 9, width: 56, height: 18, rx: 3,
        fill: '#161b22', stroke: color, 'stroke-width': isOn ? 1.5 : 1
      }));
      const lbl = this._svgEl('text', {
        x: t.x, y: t.y + 3, 'text-anchor': 'middle',
        fill: isOn ? '#e6edf3' : color,
        'font-size': 8, 'font-family': 'monospace', 'font-weight': 600
      });
      lbl.textContent = t.label;
      g.appendChild(lbl);
      if (isOn) g.addEventListener('click', () => this.fire(t.id));
      g.addEventListener('mouseenter', (e) => {
        this.tooltip.textContent = `${t.id}${t.actor ? ' @' + t.actor : ''}: ${t.desc}`;
        this.tooltip.style.display = 'block';
        this._moveTooltip(e);
      });
      g.addEventListener('mousemove', (e) => this._moveTooltip(e));
      g.addEventListener('mouseleave', () => { this.tooltip.style.display = 'none'; });
      this.svg.appendChild(g);
    }

    // Controls
    const hasTokens = Object.keys(this.marking).length > 0;
    this.startBtn.disabled = hasTokens || this.completed;
    if (this.completed) this.statusEl.textContent = '';
    else if (!hasTokens) this.statusEl.textContent = 'Click Start to begin';
    else {
      const names = this.getEnabled().map(t => t.label);
      this.statusEl.textContent = names.length ? `Enabled: ${names.join(', ')}` : 'Deadlock';
    }

    this.logEl.innerHTML = this.log.length
      ? this.log.map((l, i) => `<span style="color:#484f58">${i + 1}.</span> ${l}`).join(' &rarr; ')
      : '<span style="color:#484f58">No transitions fired yet</span>';
    this.logEl.scrollTop = this.logEl.scrollHeight;
    this.completeEl.style.display = this.completed ? 'block' : 'none';
  }

  _moveTooltip(e) {
    this.tooltip.style.left = (e.clientX + 12) + 'px';
    this.tooltip.style.top = (e.clientY - 8) + 'px';
  }

  _drawArc(x1, y1, x2, y2, isOn, dir) {
    const dx = x2 - x1, dy = y2 - y1;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 1) return;
    const ux = dx / dist, uy = dy / dist;
    const r = 16; // place radius
    const tr = 10; // half transition rect
    let sx, sy, ex, ey;
    if (dir === 'to-t') {
      sx = x1 + ux * (r + 1); sy = y1 + uy * (r + 1);
      ex = x2 - ux * tr; ey = y2 - uy * tr;
    } else {
      sx = x1 + ux * tr; sy = y1 + uy * tr;
      ex = x2 - ux * (r + 1); ey = y2 - uy * (r + 1);
    }
    this.svg.appendChild(this._svgEl('line', {
      x1: sx, y1: sy, x2: ex, y2: ey,
      stroke: isOn ? '#8b949e' : '#484f58',
      'stroke-width': isOn ? 1.2 : 0.8,
      'marker-end': isOn ? 'url(#arrowhead-on)' : 'url(#arrowhead)'
    }));
  }

  destroy() {
    window.removeEventListener('resize', this._onResize);
    if (this.tooltip?.parentNode) this.tooltip.parentNode.removeChild(this.tooltip);
  }
}
