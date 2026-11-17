/* TriageKit site: the app's particle planet with orbiting check areas, in plain WebGL (no libraries, ~4 KB).
   Starts only when visible, pauses when off-screen or in a background tab, draws one still frame for
   reduced motion, and leaves the static fallback in place when WebGL isn't available. */
(() => {
  'use strict';
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const VS = `
    attribute vec3 p; attribute vec4 c; attribute float s;
    uniform float t, aspect, ry, scale; uniform vec2 off;
    varying vec4 vc;
    void main() {
      float a = ry * c.w + t * (0.05 + c.w * 0.20);           // planet turns slowly, orbit nodes faster
      float cs = cos(a), sn = sin(a);
      vec3 q = vec3(cs * p.x + sn * p.z, p.y, -sn * p.x + cs * p.z);
      float tilt = mix(0.0, 0.32, c.w);                        // the orbit ring is tilted towards the viewer
      q = vec3(q.x, cos(tilt) * q.y - sin(tilt) * q.z, sin(tilt) * q.y + cos(tilt) * q.z);
      float z = q.z + 6.0;
      gl_Position = vec4((q.x / z) * scale / aspect + off.x, (q.y / z) * scale + off.y, 0.0, 1.0);
      float front = smoothstep(-3.0, 3.1, -q.z) * smoothstep(-3.4, 2.6, q.y);   // far side and lower half fade, as in the app               // far side of the planet is dimmer
      float tw = 0.6 + 0.4 * sin(t * 1.3 + s * 57.0);
      vc = vec4(c.rgb, mix(front * tw * 0.95, 0.25 + 0.75 * smoothstep(2.0, -2.0, q.z), c.w));   // ring nodes behind the shield are dimmer
      gl_PointSize = (mix(1.8 + fract(s * 13.0) * 2.2, 20.0, c.w)) * (6.0 / z) * (scale / 2.6) * DPR_;
    }`;
  const FS = `
    precision mediump float; varying vec4 vc;
    void main() {
      float d = length(gl_PointCoord - 0.5); if (d > 0.5) discard;
      float core = smoothstep(0.5, 0.12, d);
      gl_FragColor = vec4(vc.rgb * (0.75 + 0.6 * core), vc.a * core);
    }`;

  function hex(h) { const n = parseInt(h.slice(1), 16); return [(n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255]; }

  function start(canvas) {
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    const gl = canvas.getContext('webgl', { alpha: true, antialias: false, premultipliedAlpha: false, powerPreference: 'low-power' });
    if (!gl) return;
    const sh = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null; };
    const vs = sh(gl.VERTEX_SHADER, VS.replace('DPR_', dpr.toFixed(2))), fs = sh(gl.FRAGMENT_SHADER, FS);
    if (!vs || !fs) return;
    const pr = gl.createProgram(); gl.attachShader(pr, vs); gl.attachShader(pr, fs); gl.linkProgram(pr);
    if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return;
    gl.useProgram(pr);

    const small = canvas.clientWidth < 520;
    const N = small ? 3200 : 6400, R = 3.1;
    const tone = hex(canvas.dataset.tone || '#3d8bff');
    const nodes = (canvas.dataset.nodes || '#3ddc97,#58a6ff,#f2b84b,#ff7a45,#6fd3ff,#b48cff,#3ddc97,#58a6ff,#f2b84b,#6fd3ff').split(',').map(hex);
    const M = nodes.length, total = N + M;
    const P = new Float32Array(total * 3), C = new Float32Array(total * 4), S = new Float32Array(total);
    for (let i = 0; i < N; i++) {                              // Fibonacci sphere, like the app's planet
      const y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * 2.399963;
      P.set([Math.cos(th) * r * R, y * R, Math.sin(th) * r * R], i * 3);
      const hi = Math.random() > 0.97;
      C.set(hi ? [0.85, 0.93, 1, 0] : [tone[0], tone[1], tone[2], 0], i * 4); S[i] = Math.random();
    }
    for (let k = 0; k < M; k++) {                              // the check areas orbiting the planet
      const a = (k / M) * Math.PI * 2, i = N + k;
      P.set([Math.cos(a) * 2.3, R + 0.35, Math.sin(a) * 2.3], i * 3);   // a ring floating just above the horizon, around the shield
      C.set([nodes[k][0], nodes[k][1], nodes[k][2], 1], i * 4); S[i] = k / M;
    }
    const attr = (name, data, size) => { const b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW); const l = gl.getAttribLocation(pr, name); gl.enableVertexAttribArray(l); gl.vertexAttribPointer(l, size, gl.FLOAT, false, 0, 0); };
    attr('p', P, 3); attr('c', C, 4); attr('s', S, 1);
    const u = (n) => gl.getUniformLocation(pr, n);
    const uT = u('t'), uA = u('aspect'), uR = u('ry'), uS = u('scale'), uO = u('off');
    gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
    const cap = parseFloat(canvas.dataset.cap || '220');      // how many px of the planet rise above the bottom edge

    let w = 0, h = 0;
    function size() {
      const cw = canvas.clientWidth, ch = canvas.clientHeight;
      if (cw === w && ch === h) return; w = cw; h = ch;
      canvas.width = Math.round(cw * dpr); canvas.height = Math.round(ch * dpr);
      gl.viewport(0, 0, canvas.width, canvas.height);
    }
    let pointerX = 0;
    canvas.parentElement.addEventListener('pointermove', (e) => { const r = canvas.getBoundingClientRect(); pointerX = ((e.clientX - r.left) / r.width - 0.5) * 0.6; }, { passive: true });

    const t0 = performance.now(); let raf = 0, visible = false, ry = 0;
    function frame(now) {
      size();
      ry += (pointerX - ry) * 0.04;
      gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform1f(uT, reduce ? 8 : (now - t0) / 1000); gl.uniform1f(uA, w / Math.max(1, h));
      const rpx = Math.min(Math.max(w * 0.46, Math.min(w * 0.85, 340)), 620), aspect = w / Math.max(1, h);    // planet radius in px, like the app's horizon
      const scale = (rpx / (w / 2)) * aspect * 6 / R;
      gl.uniform1f(uR, ry); gl.uniform1f(uS, scale); gl.uniform2f(uO, 0, -1 + (cap - rpx) / (h / 2));
      gl.drawArrays(gl.POINTS, 0, total);
      raf = visible && !reduce && !document.hidden ? requestAnimationFrame(frame) : 0;
    }
    const kick = () => { if (!raf && visible && !document.hidden) raf = requestAnimationFrame(frame); };
    new IntersectionObserver(([e]) => { visible = e.isIntersecting; kick(); }, { rootMargin: '80px' }).observe(canvas);
    document.addEventListener('visibilitychange', kick);
    addEventListener('resize', () => { if (reduce) requestAnimationFrame(frame); }, { passive: true });
    canvas.classList.add('on');
    if (reduce) { visible = true; requestAnimationFrame(frame); visible = false; }
  }

  document.querySelectorAll('canvas[data-globe]').forEach(start);

  /* features page: category filter (the page works fully without it; sections stay reachable by anchors) */
  const bar = document.querySelector('[data-filter]');
  if (bar) {
    const cats = [...document.querySelectorAll('.fcat')];
    const set = (key) => {
      bar.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.key === key)));
      cats.forEach((c) => { c.hidden = key !== 'all' && c.id !== key; });
    };
    bar.hidden = false;
    bar.addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) { set(b.dataset.key); history.replaceState(null, '', b.dataset.key === 'all' ? location.pathname : '#' + b.dataset.key); } });
    const want = location.hash.slice(1);
    if (want && cats.some((c) => c.id === want)) set(want);
  }
})();
