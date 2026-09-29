// Petri Net Protocol Viewer — Interactive SVG simulator
// Draws and fires the net defined in petri-net.js (the same definition documented in docs/protocol.md).
import { PLACES, TRANSITIONS } from './petri-net.js';
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
    this.places = PLACES.map((p) => ({ ...p, label: p.id }));
    this.transitions = TRANSITIONS.map((t) => ({ ...t, label: t.label || t.id.replace(/_/g, ' ') }));
  }

  // ── Layout (responsive) ────────────────────────────────────

  _applyLayout() {
    const wide = this.container.offsetWidth > 540;
    if (wide) this._layoutVertical(); else this._layoutHorizontal();
    this._render();
  }

  _pos(map, id, x, y) { map[id] = { x, y }; }

  // Nodes carry a (col, row) on a grid: columns are the happy path (1), the
  // Bitcoin timer and refunds (2), the Alephium timer and refunds (3) and the
  // early abort (0). Wide screens draw rows top to bottom, narrow ones left to right.
  _layoutVertical() {
    const colX = [70, 250, 470, 690], rowH = 48, top = 25;
    let maxRow = 0;
    for (const n of [...this.places, ...this.transitions]) { n.x = colX[n.col]; n.y = top + n.row * rowH; maxRow = Math.max(maxRow, n.row); }
    this.svg.setAttribute('viewBox', `0 0 800 ${top + (maxRow + 1) * rowH}`);
  }

  _layoutHorizontal() {
    const colY = [40, 110, 200, 290], rowW = 62, left = 30;
    let maxRow = 0;
    for (const n of [...this.places, ...this.transitions]) { n.x = left + n.row * rowW; n.y = colY[n.col]; maxRow = Math.max(maxRow, n.row); }
    this.svg.setAttribute('viewBox', `0 0 ${left + (maxRow + 1) * rowW} 340`);
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
      ['#00d4aa', 'Alice'], ['#f7931a', 'Bob'], ['#d29922', 'Timeout'], ['#58a6ff', 'Chain'], ['#a371f7', 'Anyone'], ['#8b949e', 'Both / system']
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
    if (actor === 'chain') return '#58a6ff';
    if (actor === 'anyone') return '#a371f7';
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
