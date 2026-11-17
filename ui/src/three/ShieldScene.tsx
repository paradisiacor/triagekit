import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { useEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';

/*
 * Hero centrepiece: a glass shield floating over a particle planet, with the 8 protection areas orbiting as
 * hotspots. Colour follows the verdict; while scanning, a scan band sweeps the shield and the orbit speeds up.
 * Everything is procedural (no textures/models to load), so it works offline inside the exe.
 */

export interface SceneProps { tone: string; hotspots: string[]; scanning?: boolean; emblem?: 'check' | 'alert' | 'none'; compact?: boolean }

function glowTexture() {
  const c = document.createElement('canvas'); c.width = c.height = 128;
  const g = c.getContext('2d')!; const grd = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grd.addColorStop(0, 'rgba(255,255,255,1)'); grd.addColorStop(0.25, 'rgba(255,255,255,.45)'); grd.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grd; g.fillRect(0, 0, 128, 128);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; return t;
}

function shieldShape() {
  const s = new THREE.Shape();
  s.moveTo(0, 1.5);
  s.bezierCurveTo(0.5, 1.12, 0.95, 1.02, 1.28, 1.02);
  s.lineTo(1.28, 0.12);
  s.bezierCurveTo(1.28, -0.78, 0.62, -1.22, 0, -1.55);
  s.bezierCurveTo(-0.62, -1.22, -1.28, -0.78, -1.28, 0.12);
  s.lineTo(-1.28, 1.02);
  s.bezierCurveTo(-0.95, 1.02, -0.5, 1.12, 0, 1.5);
  return s;
}

const shieldVert = /* glsl */ `
  varying vec3 vN; varying vec3 vV; varying vec3 vP;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vN = normalize(normalMatrix * normal); vV = -mv.xyz; vP = position;
    gl_Position = projectionMatrix * mv;
  }`;
const shieldFrag = /* glsl */ `
  uniform vec3 uTone; uniform float uTime; uniform float uScan;
  varying vec3 vN; varying vec3 vV; varying vec3 vP;
  float hex(vec2 p) { p *= vec2(1.0, 1.1547); p.x += mod(floor(p.y), 2.0) * 0.5; vec2 f = abs(fract(p) - 0.5); return smoothstep(0.42, 0.5, max(f.x * 1.5 + f.y, f.y * 2.0)); }
  void main() {
    vec3 n = normalize(vN); vec3 v = normalize(vV);
    float fres = pow(1.0 - abs(dot(n, v)), 2.4);
    float h = clamp((vP.y + 1.6) / 3.1, 0.0, 1.0);
    vec3 deep = vec3(0.02, 0.03, 0.05);
    vec3 base = mix(deep, uTone * 0.42, 0.18 + 0.5 * h);
    float grid = hex(vP.xy * 9.0) * (0.035 + 0.05 * h);
    float band = 0.0;
    if (uScan > 0.5) { float y = mod(uTime * 0.9, 4.0) - 2.0; band = smoothstep(0.22, 0.0, abs(vP.y - y)); }
    float sheen = smoothstep(0.35, 0.0, abs(vP.x * 0.6 + vP.y * 0.4 - 0.55 + sin(uTime * 0.4) * 0.6)) * 0.18;
    vec3 col = base + uTone * (grid + fres * 1.5 + band * 1.2) + vec3(sheen);
    col += vec3(1.0) * pow(fres, 6.0) * 0.35;
    gl_FragColor = vec4(col, 0.78 + fres * 0.22);
  }`;

const atmoVert = /* glsl */ `
  varying vec3 vN; varying vec3 vV;
  void main() { vec4 mv = modelViewMatrix * vec4(position, 1.0); vN = normalize(normalMatrix * normal); vV = -mv.xyz; gl_Position = projectionMatrix * mv; }`;
const atmoFrag = /* glsl */ `
  uniform vec3 uTone; varying vec3 vN; varying vec3 vV;
  void main() { float f = pow(1.0 - abs(dot(normalize(vN), normalize(vV))), 3.0); gl_FragColor = vec4(uTone * f * 1.6, f); }`;

function useColor(hex: string) {
  const target = useMemo(() => new THREE.Color(hex), [hex]);
  return target;
}

function Shield({ tone, scanning, emblem }: { tone: string; scanning?: boolean; emblem: string }) {
  const group = useRef<THREE.Group>(null!);
  const target = useColor(tone);
  const geo = useMemo(() => {
    const g = new THREE.ExtrudeGeometry(shieldShape(), { depth: 0.28, bevelEnabled: true, bevelThickness: 0.14, bevelSize: 0.1, bevelSegments: 8, curveSegments: 64 });
    g.center(); g.computeVertexNormals(); return g;
  }, []);
  const mat = useMemo(() => new THREE.ShaderMaterial({ vertexShader: shieldVert, fragmentShader: shieldFrag, transparent: true,
    uniforms: { uTone: { value: new THREE.Color(tone) }, uTime: { value: 0 }, uScan: { value: 0 } } }), []);
  const rim = useMemo(() => new THREE.MeshBasicMaterial({ color: tone, transparent: true, opacity: 0.18, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.BackSide }), []);
  const emblemMat = useMemo(() => new THREE.MeshBasicMaterial({ color: new THREE.Color(tone).lerp(new THREE.Color('#ffffff'), 0.55), toneMapped: false }), []);
  const emblemGeo = useMemo(() => {
    if (emblem === 'check') return [new THREE.TubeGeometry(new THREE.CatmullRomCurve3([new THREE.Vector3(-0.48, 0.02, 0), new THREE.Vector3(-0.12, -0.34, 0), new THREE.Vector3(0.52, 0.38, 0)], false, 'catmullrom', 0.05), 48, 0.085, 16)];
    if (emblem === 'alert') return [new THREE.CapsuleGeometry(0.085, 0.55, 8, 16), new THREE.SphereGeometry(0.1, 24, 24)];
    return [];
  }, [emblem]);

  useFrame((st, dt) => {
    const t = st.clock.elapsedTime;
    (mat.uniforms.uTone.value as THREE.Color).lerp(target, Math.min(1, dt * 3));
    rim.color.lerp(target, Math.min(1, dt * 3));
    emblemMat.color.lerp(target.clone().lerp(new THREE.Color('#ffffff'), 0.55), Math.min(1, dt * 3));
    mat.uniforms.uTime.value = t; mat.uniforms.uScan.value = scanning ? 1 : 0;
    group.current.position.y = 0.4 + Math.sin(t * 0.9) * 0.08;
    group.current.rotation.y = Math.sin(t * 0.35) * 0.32 + (scanning ? Math.sin(t * 1.4) * 0.15 : 0);
    group.current.rotation.x = Math.sin(t * 0.5) * 0.04;
  });
  return (
    <group ref={group} scale={0.8}>
      <mesh geometry={geo} material={mat} />
      <mesh geometry={geo} material={rim} scale={1.08} />
      <group position={[0, 0.05, 0.3]}>
        {emblem === 'check' && <mesh geometry={emblemGeo[0]} material={emblemMat} />}
        {emblem === 'alert' && <>
          <mesh geometry={emblemGeo[0]} material={emblemMat} position={[0, 0.2, 0]} />
          <mesh geometry={emblemGeo[1]} material={emblemMat} position={[0, -0.42, 0]} />
        </>}
      </group>
    </group>
  );
}

function Planet({ tone, compact }: { tone: string; compact?: boolean }) {
  const pts = useRef<THREE.Points>(null!);
  const target = useColor(tone);
  const { geo, mat } = useMemo(() => {
    const n = 3600, r = 3.4, pos = new Float32Array(n * 3), seed = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2, rad = Math.sqrt(1 - y * y), th = i * 2.399963;
      pos.set([Math.cos(th) * rad * r, y * r, Math.sin(th) * rad * r], i * 3); seed[i] = Math.random();
    }
    const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(pos, 3)); g.setAttribute('seed', new THREE.BufferAttribute(seed, 1));
    const m = new THREE.ShaderMaterial({
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      uniforms: { uTone: { value: new THREE.Color(tone) }, uTime: { value: 0 } },
      vertexShader: `attribute float seed; uniform float uTime; varying float vA; varying float vS;
        void main(){ vec4 mv = modelViewMatrix*vec4(position,1.0); gl_Position = projectionMatrix*mv; vS = seed;
          float tw = 0.55 + 0.45*sin(uTime*1.3 + seed*40.0); vA = tw * smoothstep(-2.0, 3.4, position.y);
          gl_PointSize = (1.4 + seed*1.8) * (9.0 / -mv.z); }`,
      fragmentShader: `uniform vec3 uTone; varying float vA; varying float vS;
        void main(){ float d = length(gl_PointCoord-0.5); if(d>0.5) discard; vec3 c = mix(uTone, vec3(1.0), vS > 0.97 ? 0.7 : 0.1);
          gl_FragColor = vec4(c, vA * smoothstep(0.5, 0.0, d)); }`,
    });
    return { geo: g, mat: m };
  }, []);
  const atmo = useMemo(() => new THREE.ShaderMaterial({ vertexShader: atmoVert, fragmentShader: atmoFrag, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.BackSide, uniforms: { uTone: { value: new THREE.Color(tone) } } }), []);
  useFrame((st, dt) => {
    pts.current.rotation.y += dt * 0.03;
    (mat.uniforms.uTone.value as THREE.Color).lerp(target, Math.min(1, dt * 3));
    (atmo.uniforms.uTone.value as THREE.Color).lerp(target, Math.min(1, dt * 3));
    mat.uniforms.uTime.value = st.clock.elapsedTime;
  });
  return (
    <group position={[0, compact ? -4.3 : -4.55, -0.6]}>
      <points ref={pts} geometry={geo} material={mat} />
      <mesh material={atmo}><sphereGeometry args={[3.75, 64, 64]} /></mesh>
    </group>
  );
}

function Orbit({ hotspots, scanning }: { hotspots: string[]; scanning?: boolean }) {
  const group = useRef<THREE.Group>(null!);
  const tex = useMemo(glowTexture, []);
  const ring = useMemo(() => {
    const pts: THREE.Vector3[] = []; for (let i = 0; i <= 160; i++) { const a = (i / 160) * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(a) * 2.35, 0, Math.sin(a) * 2.35)); }
    return new THREE.BufferGeometry().setFromPoints(pts);
  }, []);
  const speed = useRef(0.12);
  useFrame((st, dt) => {
    speed.current += ((scanning ? 0.9 : 0.12) - speed.current) * Math.min(1, dt * 2);
    group.current.rotation.y += dt * speed.current;
    group.current.children.forEach((c, i) => { if (c.userData.pulse) { const s = 0.42 + Math.sin(st.clock.elapsedTime * 3 + i) * 0.12; c.scale.setScalar(s); } });
  });
  return (
    <group rotation={[0.32, 0, -0.08]} position={[0, 0.35, 0]}>
      <lineLoop geometry={ring}><lineBasicMaterial color="#ffffff" transparent opacity={0.12} /></lineLoop>
      <group ref={group}>
        {hotspots.map((col, i) => {
          const a = (i / hotspots.length) * Math.PI * 2, x = Math.cos(a) * 2.35, z = Math.sin(a) * 2.35;
          const risky = col !== '#34e0a1';
          return (
            <group key={i} position={[x, 0, z]}>
              <mesh><sphereGeometry args={[0.06, 16, 16]} /><meshBasicMaterial color={col} toneMapped={false} /></mesh>
              <sprite scale={risky ? 0.5 : 0.36} userData={{ pulse: risky }}>
                <spriteMaterial map={tex} color={col} transparent depthWrite={false} blending={THREE.AdditiveBlending} />
              </sprite>
            </group>
          );
        })}
      </group>
    </group>
  );
}

function Dust({ tone }: { tone: string }) {
  const ref = useRef<THREE.Points>(null!);
  const geo = useMemo(() => {
    const n = 220, p = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) p.set([(Math.random() - 0.5) * 12, (Math.random() - 0.3) * 7, (Math.random() - 0.5) * 6 - 1], i * 3);
    const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(p, 3)); return g;
  }, []);
  useFrame((_, dt) => { ref.current.rotation.y += dt * 0.01; ref.current.position.y = (ref.current.position.y + dt * 0.03) % 1; });
  return <points ref={ref} geometry={geo}><pointsMaterial size={0.025} color={tone} transparent opacity={0.55} depthWrite={false} blending={THREE.AdditiveBlending} /></points>;
}

function Halo({ tone }: { tone: string }) {
  const tex = useMemo(glowTexture, []);
  const m = useRef<THREE.SpriteMaterial>(null!);
  const target = useColor(tone);
  useFrame((st, dt) => { m.current.color.lerp(target, Math.min(1, dt * 3)); m.current.opacity = 0.32 + Math.sin(st.clock.elapsedTime * 1.2) * 0.05; });
  return <sprite position={[0, 0.5, -1]} scale={[6.5, 6.5, 1]}><spriteMaterial ref={m} map={tex} color={tone} transparent opacity={0.3} depthWrite={false} blending={THREE.AdditiveBlending} /></sprite>;
}

function Parallax({ children }: { children: React.ReactNode }) {
  const g = useRef<THREE.Group>(null!);
  const { pointer } = useThree();
  useFrame((_, dt) => {
    g.current.rotation.y += (pointer.x * 0.18 - g.current.rotation.y) * Math.min(1, dt * 2.5);
    g.current.rotation.x += (-pointer.y * 0.08 - g.current.rotation.x) * Math.min(1, dt * 2.5);
  });
  return <group ref={g}>{children}</group>;
}

/**
 * Animates only while something is happening (scanning, a result just arrived, or the pointer is over the scene),
 * then stops rendering so an idle window uses no GPU. Also stops whenever the window is hidden.
 */
function useActive(scanning?: boolean, tone?: string) {
  const [awake, setAwake] = useState(true);
  const [visible, setVisible] = useState(!document.hidden);
  useEffect(() => { setAwake(true); const t = setTimeout(() => setAwake(false), 6000); return () => clearTimeout(t); }, [tone]);
  useEffect(() => { const f = () => setVisible(!document.hidden); document.addEventListener('visibilitychange', f); window.addEventListener('blur', f); window.addEventListener('focus', f); return () => { document.removeEventListener('visibilitychange', f); window.removeEventListener('blur', f); window.removeEventListener('focus', f); }; }, []);
  const reduce = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [hover, setHover] = useState(false);
  return { active: visible && !reduce && (scanning || awake || hover), setHover };
}

export default function ShieldScene({ tone, hotspots, scanning, emblem = 'none', compact }: SceneProps) {
  const { active, setHover } = useActive(scanning, tone);
  return (
    <Canvas frameloop={active ? 'always' : 'demand'} onPointerEnter={() => setHover(true)} onPointerLeave={() => setHover(false)} dpr={[1, 1.5]} camera={{ position: [0, 0.4, 9], fov: compact ? 36 : 34 }} gl={{ antialias: true, alpha: true, powerPreference: 'default' }} style={{ background: 'transparent' }}>
      <Parallax>
        <Halo tone={tone} />
        <Planet tone={tone} compact={compact} />
        <Orbit hotspots={hotspots} scanning={scanning} />
        <Shield tone={tone} scanning={scanning} emblem={emblem} />
        <Dust tone={tone} />
      </Parallax>
    </Canvas>
  );
}
