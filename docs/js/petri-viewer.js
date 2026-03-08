// Petri Net Protocol Viewer — Interactive SVG simulator
// Matches the formal model in docs/protocol.md

export class PetriNetViewer {
  constructor(container) {
    this.container = container;
    this.marking = {};
    this.log = [];
    this.completed = false;
    this._define();
    this._build();
    this.reset();
  }

  // ── Net definition ──────────────────────────────────────────

  _define() {
    this.places = [
      { id: 'ready', label: 'ready', x: 425, y: 30 },
      { id: 'swap_agreed', label: 'swap_agreed', x: 425, y: 90 },
      { id: 'btc_locked', label: 'btc_locked', x: 425, y: 150 },
      { id: 'both_locked', label: 'both_locked', x: 425, y: 210 },
      { id: 'presigs_ready', label: 'presigs_ready', x: 425, y: 290 },
      { id: 't_revealed', label: 't_revealed', x: 425, y: 370 },
      { id: 'done', label: 'done', x: 425, y: 450 },
      // Cancel path
      { id: 'alph_refundable', label: 'alph_refundable', x: 220, y: 350 },
      { id: 'btc_cancel_wait', label: 'btc_cancel_wait', x: 630, y: 350 },
      { id: 'btc_cancel_refundable', label: 'btc_cancel_refundable', x: 630, y: 410 },
      { id: 'recovery_done', label: 'recovery_done', x: 425, y: 410 },
      // Abort path
      { id: 'btc_abort_wait', label: 'btc_abort_wait', x: 150, y: 180 },
      { id: 'btc_abort_refundable', label: 'btc_abort_refundable', x: 150, y: 240 },
    ];

    this.transitions = [
      { id: 'start', label: 'start', actor: null,
        inputs: [], outputs: ['ready'],
        desc: 'Initialize the protocol' },
      { id: 'negotiate', label: 'negotiate', actor: null,
        inputs: ['ready'], outputs: ['swap_agreed'],
        desc: 'Both parties agree on swap parameters' },
      { id: 'negotiate_timeout', label: 'negotiate_timeout', actor: 'timeout',
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
      { id: 'exchange_presigs', label: 'exchange_presigs', actor: null,
        inputs: ['both_locked'], outputs: ['presigs_ready'],
        desc: 'Exchange adaptor pre-signatures via Nostr' },
      { id: 'exchange_timeout', label: 'exchange_timeout', actor: 'timeout',
        inputs: ['both_locked'], outputs: ['alph_refundable', 'btc_cancel_wait'],
        desc: 'Pre-sig exchange stalls — fork to cancel' },
      { id: 'alice_claims_btc', label: 'alice_claims_btc', actor: 'Alice',
        inputs: ['presigs_ready'], outputs: ['t_revealed'],
        desc: 'Alice claims BTC, revealing adaptor secret t' },
      { id: 't2_timeout', label: 't2_timeout', actor: 'timeout',
        inputs: ['presigs_ready'], outputs: ['alph_refundable', 'btc_cancel_wait'],
        desc: 'Alice doesn\'t claim — fork to cancel' },
      { id: 'bob_claims_alph', label: 'bob_claims_alph', actor: 'Bob',
        inputs: ['t_revealed'], outputs: ['done'],
        desc: 'Bob extracts t and claims ALPH' },
      // Cancel path
      { id: 'alice_cancel_refund', label: 'alice_cancel_refund', actor: 'Alice',
        inputs: ['alph_refundable'], outputs: ['recovery_done'],
        desc: 'Alice refunds ALPH after T2' },
      { id: 't1_timeout', label: 't1_timeout', actor: 'timeout',
        inputs: ['btc_cancel_wait'], outputs: ['btc_cancel_refundable'],
        desc: 'T1 expires — Bob can refund BTC' },
      { id: 'bob_cancel_refund', label: 'bob_cancel_refund', actor: 'Bob',
        inputs: ['btc_cancel_refundable'], outputs: ['recovery_done'],
        desc: 'Bob refunds BTC after T1' },
      { id: 'both_recovered', label: 'both_recovered', actor: null,
        inputs: ['recovery_done', 'recovery_done'], outputs: ['done'],
        desc: 'Both refunds complete — join' },
      // Abort path
      { id: 't1_timeout_abort', label: 't1_timeout_abort', actor: 'timeout',
        inputs: ['btc_abort_wait'], outputs: ['btc_abort_refundable'],
        desc: 'T1 expires — Bob can refund locked BTC' },
      { id: 'bob_abort_refund', label: 'bob_abort_refund', actor: 'Bob',
        inputs: ['btc_abort_refundable'], outputs: ['done'],
        desc: 'Bob refunds BTC (abort path)' },
      { id: 'stop', label: 'stop', actor: null,
        inputs: ['done'], outputs: [],
        desc: 'Protocol terminates — net is empty' },
    ];

    // Transition positions (manual layout)
    const tPos = {
      start:               { x: 425, y: 10 },
      negotiate:           { x: 425, y: 60 },
      negotiate_timeout:   { x: 280, y: 90 },
      lock_btc:            { x: 425, y: 120 },
      lock_timeout:        { x: 280, y: 150 },
      lock_alph:           { x: 425, y: 180 },
      exchange_presigs:    { x: 425, y: 250 },
      exchange_timeout:    { x: 280, y: 240 },
      alice_claims_btc:    { x: 425, y: 330 },
      t2_timeout:          { x: 280, y: 310 },
      bob_claims_alph:     { x: 425, y: 410 },
      alice_cancel_refund: { x: 220, y: 390 },
      t1_timeout:          { x: 630, y: 380 },
      bob_cancel_refund:   { x: 630, y: 440 },
      both_recovered:      { x: 425, y: 440 },
      t1_timeout_abort:    { x: 150, y: 210 },
      bob_abort_refund:    { x: 150, y: 270 },
      stop:                { x: 425, y: 480 },
    };
    for (const t of this.transitions) {
      const p = tPos[t.id];
      if (p) { t.x = p.x; t.y = p.y; }
    }
  }

  // ── State logic ─────────────────────────────────────────────

  reset() {
    this.marking = {};
    this.log = [];
    this.completed = false;
    this._render();
  }

  _tokens(placeId) {
    return this.marking[placeId] || 0;
  }

  getEnabled() {
    return this.transitions.filter(t => {
      // Count required tokens per input place
      const needed = {};
      for (const p of t.inputs) needed[p] = (needed[p] || 0) + 1;
      return Object.entries(needed).every(([p, n]) => this._tokens(p) >= n);
    });
  }

  fire(id) {
    const t = this.transitions.find(tr => tr.id === id);
    if (!t) return;
    // Check enabled
    const needed = {};
    for (const p of t.inputs) needed[p] = (needed[p] || 0) + 1;
    for (const [p, n] of Object.entries(needed)) {
      if (this._tokens(p) < n) return;
    }
    // Consume inputs
    for (const p of t.inputs) this.marking[p]--;
    // Produce outputs
    for (const p of t.outputs) this.marking[p] = (this.marking[p] || 0) + 1;
    // Clean up zeros
    for (const p of Object.keys(this.marking)) {
      if (this.marking[p] <= 0) delete this.marking[p];
    }
    // Log
    const actor = t.actor ? ` (${t.actor})` : '';
    this.log.push(`${t.label}${actor}`);
    // Check stop
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

    // SVG
    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('width', '100%');
    this.svg.setAttribute('viewBox', '0 0 830 500');
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

    // Defs for arrowhead
    const defs = this._svgEl('defs');
    const marker = this._svgEl('marker', {
      id: 'arrowhead', markerWidth: 8, markerHeight: 6,
      refX: 7, refY: 3, orient: 'auto', markerUnits: 'userSpaceOnUse'
    });
    const arrowPath = this._svgEl('path', {
      d: 'M0,0 L8,3 L0,6 Z', fill: '#484f58'
    });
    marker.appendChild(arrowPath);
    defs.appendChild(marker);

    // Enabled arrowhead (brighter)
    const markerOn = this._svgEl('marker', {
      id: 'arrowhead-on', markerWidth: 8, markerHeight: 6,
      refX: 7, refY: 3, orient: 'auto', markerUnits: 'userSpaceOnUse'
    });
    markerOn.appendChild(this._svgEl('path', {
      d: 'M0,0 L8,3 L0,6 Z', fill: '#8b949e'
    }));
    defs.appendChild(markerOn);
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
    // Clear SVG content (keep defs)
    const defs = this.svg.querySelector('defs');
    this.svg.innerHTML = '';
    this.svg.appendChild(defs);

    const enabled = new Set(this.getEnabled().map(t => t.id));
    const placeMap = {};
    for (const p of this.places) placeMap[p.id] = p;

    // Draw arcs first (behind everything)
    for (const t of this.transitions) {
      const isEnabled = enabled.has(t.id);
      // Input arcs: place → transition
      const inputCounts = {};
      for (const p of t.inputs) inputCounts[p] = (inputCounts[p] || 0) + 1;
      for (const pId of Object.keys(inputCounts)) {
        const place = placeMap[pId];
        if (!place) continue;
        this._drawArc(place.x, place.y, t.x, t.y, isEnabled, 'to-transition');
      }
      // Output arcs: transition → place
      const outputCounts = {};
      for (const p of t.outputs) outputCounts[p] = (outputCounts[p] || 0) + 1;
      for (const pId of Object.keys(outputCounts)) {
        const place = placeMap[pId];
        if (!place) continue;
        this._drawArc(t.x, t.y, place.x, place.y, isEnabled, 'to-place');
      }
    }

    // Draw places
    for (const p of this.places) {
      const tokens = this._tokens(p.id);
      const g = this._svgEl('g');

      // Circle
      const circle = this._svgEl('circle', {
        cx: p.x, cy: p.y, r: 18,
        fill: tokens > 0 ? '#161b22' : '#0d1117',
        stroke: tokens > 0 ? '#58a6ff' : '#30363d',
        'stroke-width': tokens > 0 ? 2 : 1
      });
      g.appendChild(circle);

      // Tokens
      if (tokens === 1) {
        g.appendChild(this._svgEl('circle', {
          cx: p.x, cy: p.y, r: 5, fill: '#58a6ff'
        }));
      } else if (tokens === 2) {
        g.appendChild(this._svgEl('circle', {
          cx: p.x - 6, cy: p.y, r: 4, fill: '#58a6ff'
        }));
        g.appendChild(this._svgEl('circle', {
          cx: p.x + 6, cy: p.y, r: 4, fill: '#58a6ff'
        }));
      }

      // Label
      const label = this._svgEl('text', {
        x: p.x, y: p.y + 30, 'text-anchor': 'middle',
        fill: '#8b949e', 'font-size': 9, 'font-family': 'monospace'
      });
      label.textContent = p.label;
      g.appendChild(label);

      this.svg.appendChild(g);
    }

    // Draw transitions
    for (const t of this.transitions) {
      const isEnabled = enabled.has(t.id);
      const color = this._actorColor(t.actor);
      const g = this._svgEl('g', {
        opacity: isEnabled ? 1 : 0.35,
        style: isEnabled ? 'cursor:pointer' : 'cursor:default'
      });

      // Glow filter for enabled
      if (isEnabled) {
        const rect = this._svgEl('rect', {
          x: t.x - 28, y: t.y - 10, width: 56, height: 20, rx: 4,
          fill: color, opacity: 0.15
        });
        g.appendChild(rect);
      }

      // Rect
      const rect = this._svgEl('rect', {
        x: t.x - 26, y: t.y - 9, width: 52, height: 18, rx: 3,
        fill: '#161b22', stroke: color,
        'stroke-width': isEnabled ? 1.5 : 1
      });
      g.appendChild(rect);

      // Label
      const label = this._svgEl('text', {
        x: t.x, y: t.y + 3, 'text-anchor': 'middle',
        fill: isEnabled ? '#e6edf3' : color,
        'font-size': 8, 'font-family': 'monospace', 'font-weight': 600
      });
      label.textContent = t.label.length > 10 ? t.label.slice(0, 9) + '..' : t.label;
      g.appendChild(label);

      // Interaction
      if (isEnabled) {
        g.addEventListener('click', () => this.fire(t.id));
      }
      g.addEventListener('mouseenter', (e) => {
        const actor = t.actor ? ` [@${t.actor}]` : '';
        this.tooltip.textContent = `${t.label}${actor}: ${t.desc}`;
        this.tooltip.style.display = 'block';
        this.tooltip.style.left = (e.clientX + 12) + 'px';
        this.tooltip.style.top = (e.clientY - 8) + 'px';
      });
      g.addEventListener('mousemove', (e) => {
        this.tooltip.style.left = (e.clientX + 12) + 'px';
        this.tooltip.style.top = (e.clientY - 8) + 'px';
      });
      g.addEventListener('mouseleave', () => {
        this.tooltip.style.display = 'none';
      });

      this.svg.appendChild(g);
    }

    // Update controls
    const hasTokens = Object.keys(this.marking).length > 0;
    this.startBtn.disabled = hasTokens || this.completed;
    if (this.completed) {
      this.statusEl.textContent = '';
    } else if (!hasTokens) {
      this.statusEl.textContent = 'Click Start to begin';
    } else {
      const names = this.getEnabled().map(t => t.label);
      this.statusEl.textContent = names.length ? `Enabled: ${names.join(', ')}` : 'No transitions enabled (deadlock)';
    }

    // Log
    this.logEl.innerHTML = this.log.length
      ? this.log.map((l, i) => `<div style="padding:1px 0"><span style="color:#484f58">${i + 1}.</span> ${l}</div>`).join('')
      : '<div style="color:#484f58">No transitions fired yet</div>';
    this.logEl.scrollTop = this.logEl.scrollHeight;

    // Completion
    this.completeEl.style.display = this.completed ? 'block' : 'none';
  }

  _drawArc(x1, y1, x2, y2, isEnabled, direction) {
    // Shorten line to stop at circle/rect boundary
    const dx = x2 - x1, dy = y2 - y1;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 1) return;
    const ux = dx / dist, uy = dy / dist;

    let sx, sy, ex, ey;
    if (direction === 'to-transition') {
      // Start from circle edge (r=18), end at rect edge
      sx = x1 + ux * 19; sy = y1 + uy * 19;
      ex = x2 - ux * 12; ey = y2 - uy * 12;
    } else {
      // Start from rect edge, end at circle edge (r=18)
      sx = x1 + ux * 12; sy = y1 + uy * 12;
      ex = x2 - ux * 19; ey = y2 - uy * 19;
    }

    const line = this._svgEl('line', {
      x1: sx, y1: sy, x2: ex, y2: ey,
      stroke: isEnabled ? '#8b949e' : '#484f58',
      'stroke-width': isEnabled ? 1.2 : 0.8,
      'marker-end': isEnabled ? 'url(#arrowhead-on)' : 'url(#arrowhead)'
    });
    this.svg.appendChild(line);
  }

  destroy() {
    if (this.tooltip && this.tooltip.parentNode) {
      this.tooltip.parentNode.removeChild(this.tooltip);
    }
  }
}
