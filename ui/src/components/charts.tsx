import { motion } from 'motion/react';
import { useId } from 'react';
import { VERDICT_COLOR } from '../lib/format';
import type { ScanSummary } from '../lib/types';

/** CyFocus-style threat surface: one axis per protection area, filled polygon = risk. */
export function RadarChart({ axes, values, color, size = 300 }: { axes: string[]; values: number[]; color: string; size?: number }) {
  const id = useId().replace(/:/g, '');
  const c = size / 2, R = size / 2 - 62, n = axes.length;
  const pt = (i: number, r: number) => { const a = -Math.PI / 2 + (i / n) * Math.PI * 2; return [c + Math.cos(a) * r, c + Math.sin(a) * r]; };
  const poly = (r: (i: number) => number) => axes.map((_, i) => pt(i, r(i)).join(',')).join(' ');
  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full overflow-visible">
      <defs>
        <radialGradient id={`rg${id}`}><stop offset="0" stopColor={color} stopOpacity=".05" /><stop offset="1" stopColor={color} stopOpacity=".55" /></radialGradient>
        <filter id={`gl${id}`}><feGaussianBlur stdDeviation="6" /></filter>
      </defs>
      {[0.25, 0.5, 0.75, 1].map((k) => <polygon key={k} points={poly(() => R * k)} fill="none" stroke="#ffffff" strokeOpacity={k === 1 ? 0.14 : 0.06} />)}
      {axes.map((_, i) => { const [x, y] = pt(i, R); return <line key={i} x1={c} y1={c} x2={x} y2={y} stroke="#ffffff" strokeOpacity=".06" />; })}
      <motion.polygon initial={{ opacity: 0, scale: 0.4 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }} style={{ transformOrigin: 'center' }}
        points={poly((i) => R * Math.max(0.06, values[i]))} fill={`url(#rg${id})`} stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
      <polygon points={poly((i) => R * Math.max(0.06, values[i]))} fill="none" stroke={color} strokeWidth="5" opacity=".35" filter={`url(#gl${id})`} />
      {axes.map((a, i) => {
        const [x, y] = pt(i, R + 20); const [px, py] = pt(i, R * Math.max(0.06, values[i]));
        return (
          <g key={a}>
            <circle cx={px} cy={py} r="3" fill="#05070a" stroke={color} strokeWidth="1.5" />
            <text x={x} y={y} textAnchor={Math.abs(x - c) < 8 ? 'middle' : x > c ? 'start' : 'end'} dominantBaseline="middle" fill="#8b95a3" fontSize="11" fontFamily="var(--font-sans)">{a}</text>
          </g>
        );
      })}
    </svg>
  );
}

/** Score trend as an area chart with glow. */
export function TrendChart({ scans, height = 200, onPick, picked }: { scans: ScanSummary[]; height?: number; onPick?: (id: number) => void; picked?: number }) {
  const id = useId().replace(/:/g, '');
  const pts = scans.slice().reverse();
  const W = 900, H = height, P = 18;
  const X = (i: number) => (pts.length <= 1 ? W / 2 : P + ((W - 2 * P) * i) / (pts.length - 1));
  const Y = (s: number) => H - P - ((H - 2 * P) * s) / 100;
  const smooth = pts.map((s, i) => {
    if (i === 0) return `M${X(0)},${Y(s.score)}`;
    const x0 = X(i - 1), y0 = Y(pts[i - 1].score), x1 = X(i), y1 = Y(s.score), mx = (x0 + x1) / 2;
    return `C${mx},${y0} ${mx},${y1} ${x1},${y1}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block w-full" style={{ height }}>
      <defs>
        <linearGradient id={`tg${id}`} x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#4c9dff" stopOpacity=".35" /><stop offset="1" stopColor="#4c9dff" stopOpacity="0" /></linearGradient>
        <filter id={`tgl${id}`}><feGaussianBlur stdDeviation="5" /></filter>
      </defs>
      {[25, 50, 75, 100].map((y) => <line key={y} x1={P} x2={W - P} y1={Y(y)} y2={Y(y)} stroke="#fff" strokeOpacity={y === 85 ? 0.15 : 0.05} strokeDasharray="3 6" vectorEffect="non-scaling-stroke" />)}
      {pts.length > 0 && <>
        <path d={`${smooth} L${X(pts.length - 1)},${H - P} L${X(0)},${H - P} Z`} fill={`url(#tg${id})`} />
        <path d={smooth} fill="none" stroke="#4c9dff" strokeWidth="6" opacity=".35" filter={`url(#tgl${id})`} vectorEffect="non-scaling-stroke" />
        <motion.path d={smooth} fill="none" stroke="#8cc8ff" strokeWidth="2" vectorEffect="non-scaling-stroke" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }} />
      </>}
      {pts.map((s, i) => (
        <g key={s.id} onClick={() => onPick?.(s.id)} style={{ cursor: onPick ? 'pointer' : undefined }}>
          <circle cx={X(i)} cy={Y(s.score)} r="14" fill="transparent" />
          <circle cx={X(i)} cy={Y(s.score)} r={picked === s.id ? 6 : 4} fill="#05070a" stroke={VERDICT_COLOR[s.verdict]} strokeWidth={picked === s.id ? 3 : 2} vectorEffect="non-scaling-stroke" />
        </g>
      ))}
    </svg>
  );
}

/** Thin ring progress (scan). */
export function Ring({ pct, color = '#4c9dff', size = 220, stroke = 3 }: { pct: number; color?: string; size?: number; stroke?: number }) {
  const r = size / 2 - 10, C = 2 * Math.PI * r;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#ffffff10" strokeWidth={stroke} />
      <motion.circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={C}
        animate={{ strokeDashoffset: C * (1 - pct / 100) }} transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }} style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
    </svg>
  );
}
