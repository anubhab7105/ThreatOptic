import { useEffect } from 'react';
import { useSceneStore } from './sceneStore';







const PHASES = ['Ingest', 'Analyze', 'Score', 'Investigate'] as const;

export function PipelineScene(_props: { progress?: number; reduced?: boolean }) {
  const storeProgress = useSceneStore((s) => s.progress);
  const progress = typeof _props.progress === 'number' ? _props.progress : storeProgress;
  void _props.reduced;

  useEffect(() => {

    const host = document.getElementById('pipeline-scene-host');
    if (host) host.setAttribute('aria-valuenow', String(Math.round(progress * 100)));
  }, [progress]);

  const active = Math.min(3, Math.floor(progress * 4));
  const fillW = 60 + progress * 520;

  return (
    <div
      className="landing-new__well"
      style={{ aspectRatio: 'auto', minHeight: 190, padding: 16 }}
      role="progressbar"
      aria-label="Pipeline scroll progress"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(progress * 100)}
      aria-hidden={false}
    >
      <svg viewBox="0 0 640 170" role="presentation" style={{ width: '100%', height: 'auto', display: 'block' }} aria-hidden="true">
        <line x1="60" y1="85" x2="580" y2="85" stroke="var(--scene-line)" strokeWidth="3" strokeLinecap="round" />
        <line x1="60" y1="85" x2={fillW} y2="85" stroke="var(--scene-accent)" strokeWidth="3" strokeLinecap="round" />
        {PHASES.map((label, i) => {
          const x = 60 + i * ((520 / 3));
          const isActive = i <= active;
          const isCurrent = i === active;
          return (
            <g key={label}>
              <circle cx={x} cy="85" r={isCurrent ? 20 : 15} fill={isActive ? 'var(--scene-accent)' : 'var(--scene-clay)'} stroke="var(--scene-line)" strokeWidth="1.5" />
              {isCurrent ? <circle cx={x} cy="85" r="7" fill="var(--surface-raised)" /> : null}
              {i === 0 ? <rect x={x - 9} y={76 - 26} width="18" height="12" rx="2" fill={isActive ? 'var(--scene-accent)' : 'var(--scene-clay)'} stroke="var(--scene-line)" /> : null}
              {i === 1 ? <g stroke={isActive ? 'var(--surface-raised)' : 'var(--scene-line)'} strokeWidth="1.6"><line x1={x - 8} y1="80" x2={x + 8} y2="80" /><line x1={x - 8} y1="85" x2={x + 8} y2="85" /><line x1={x - 8} y1="90" x2={x + 8} y2="90" /></g> : null}
              {i === 2 ? <text x={x} y="90" textAnchor="middle" fontSize="11" fontWeight="800" fill={isActive ? 'var(--surface-raised)' : 'var(--scene-accent)'}>87</text> : null}
              {i === 3 ? <g fill={isActive ? 'var(--surface-raised)' : 'var(--scene-accent)'}><circle cx={x - 6} cy="82" r="2.4" /><circle cx={x + 6} cy="82" r="2.4" /><circle cx={x} cy="90" r="2.4" /></g> : null}
              <text x={x} y="130" textAnchor="middle" fontSize="12" fontWeight={isCurrent ? 800 : 600} fill="var(--text-primary)">{label}</text>
              <text x={x} y="146" textAnchor="middle" fontSize="10" fill="var(--text-muted)">
                {i === 0 ? 'upload · paste · Gmail' : i === 1 ? 'headers · links · files' : i === 2 ? 'reasons, not black box' : 'graph · case · report'}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
