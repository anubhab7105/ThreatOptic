import React from 'react';






export function HeroPoster({ id = 'hero-poster' }: { id?: string }) {
  return (
    <svg
      id={id}
      viewBox="0 0 640 480"
      role="img"
      aria-label="Illustration of an envelope being inspected inside a chamber: orbit rings, scan plane and connected nodes. Static sample preview."
      style={{ width: '100%', height: 'auto', display: 'block' }}
    >
      <title>Inspection chamber preview</title>
      <rect x="0" y="0" width="640" height="480" rx="16" fill="var(--scene-bg)" />
      {}
      <g stroke="var(--scene-line)" strokeWidth="1" opacity="0.6">
        <line x1="40" y1="420" x2="240" y2="140" />
        <line x1="40" y1="420" x2="360" y2="90" />
        <line x1="40" y1="420" x2="520" y2="150" />
        <circle cx="320" cy="230" r="150" fill="none" strokeDasharray="4 6" />
        <circle cx="320" cy="230" r="112" fill="none" strokeDasharray="3 7" />
        <circle cx="320" cy="230" r="76" fill="none" strokeDasharray="2 6" />
      </g>
      {}
      <ellipse cx="320" cy="392" rx="130" ry="18" fill="var(--scene-clay-shade)" opacity="0.85" />
      {}
      <g>
        <rect x="215" y="180" width="210" height="140" rx="14" fill="var(--scene-clay)" stroke="var(--scene-line)" strokeWidth="1.5" />
        <polygon points="215,194 320,272 425,194 425,180 215,180" fill="var(--scene-clay-shade)" stroke="var(--scene-line)" strokeWidth="1.5" />
        <rect x="248" y="300" width="144" height="10" rx="5" fill="var(--scene-line)" opacity="0.55" />
        {}
        <rect x="215" y="236" width="210" height="10" fill="var(--scene-accent)" opacity="0.55" />
        <rect x="215" y="236" width="210" height="2" fill="var(--scene-accent)" />
      </g>
      {}
      <ellipse cx="320" cy="250" rx="150" ry="44" fill="none" stroke="var(--scene-accent)" strokeWidth="2" opacity="0.7" />
      {}
      <g fill="var(--scene-accent)">
        <circle cx="170" cy="150" r="7" />
        <circle cx="480" cy="130" r="6" />
        <circle cx="510" cy="300" r="8" />
        <circle cx="140" cy="320" r="6" />
        <circle cx="250" cy="90" r="5" />
      </g>
      <g stroke="var(--scene-line)" strokeWidth="1.2">
        <line x1="170" y1="150" x2="250" y2="90" />
        <line x1="480" y1="130" x2="510" y2="300" />
        <line x1="140" y1="320" x2="215" y2="250" />
      </g>
      {}
      <g>
        <rect x="392" y="120" width="168" height="44" rx="10" fill="var(--surface-raised)" stroke="var(--border-subtle)" />
        <circle cx="412" cy="142" r="7" fill="var(--scene-risk)" />
        <rect x="424" y="132" width="110" height="9" rx="4.5" fill="var(--scene-clay-shade)" />
        <rect x="424" y="145" width="76" height="8" rx="4" fill="var(--scene-line)" opacity="0.6" />
      </g>
    </svg>
  );
}
