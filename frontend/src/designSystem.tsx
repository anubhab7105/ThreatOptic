import React, { useState } from 'react';
import {
  Alert, Badge, Button, Card, Checkbox, Drawer, EmptyState, ErrorState, IconButton,
  Input, Modal, Radio, SegmentedControl, Select, SeverityBadge, SeverityIcon,
  Skeleton, SortTh, Spinner, StatusIndicator, Table, Tabs, Textarea, Toggle, Tooltip, Well,
} from './primitives';
import { useTheme } from './theme';
import { useChartTheme } from './useChartTheme';




function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card title={title}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>{children}</div>
    </Card>
  );
}

export function DesignSystem() {
  const { theme } = useTheme();
  const ct = useChartTheme();
  const [seg, setSeg] = useState('upload');
  const [tab, setTab] = useState(0);
  const [modal, setModal] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [sortDir, setSortDir] = useState<'ascending' | 'descending' | 'none'>('ascending');
  const [checked, setChecked] = useState(true);
  const [toggled, setToggled] = useState(false);
  const tokens = ['--bg', '--surface', '--surface-raised', '--surface-inset', '--text-primary',
    '--text-secondary', '--text-muted', '--accent-primary', '--accent-secondary', '--accent-info',
    '--risk-critical', '--risk-high', '--risk-medium', '--risk-low', '--chart-1', '--chart-2',
    '--chart-3', '--chart-4', '--chart-5', '--chart-6'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <Card
        title={`Design system (current theme: ${theme})`}
        description="Toggle the theme in the header to review both themes. No page outside this route uses these components yet — Phase 2 migrates pages."
        actions={<Badge tone="info">DEV ONLY</Badge>}
      >
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {tokens.map((t) => (
            <span key={t} title={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              <span style={{ width: 16, height: 16, borderRadius: 4, background: `var(${t})`, border: '1px solid var(--border-subtle)' }} />
              {t}
            </span>
          ))}
        </div>
      </Card>

      <Section title="Buttons — variants, sizes, states">
        <Button variant="primary">Primary</Button>
        <Button>Secondary</Button>
        <Button variant="ghost">Ghost</Button>
        <Button variant="danger">Destructive</Button>
        <Button size="sm" variant="primary">Small</Button>
        <Button size="lg" variant="primary">Large</Button>
        <Button loading variant="primary">Saving</Button>
        <Button disabled>Disabled</Button>
        <IconButton label="Zoom in" tooltip="Zoom in">+</IconButton>
        <IconButton label="Zoom out" tooltip="Zoom out" aria-pressed>−</IconButton>
      </Section>

      <Section title="Inputs">
        <div style={{ minWidth: 220, flex: 1 }}><Input label="Subject" placeholder="Re: invoice" help="Label always visible; never placeholder-only." /></div>
        <div style={{ minWidth: 220, flex: 1 }}><Input label="Sender" defaultValue="bad@evil.test" error="Sender domain failed DMARC." /></div>
        <div style={{ minWidth: 220, flex: 1 }}><Input label="Disabled" disabled defaultValue="—" /></div>
        <div style={{ minWidth: 220, flex: 1 }}>
          <Select label="Verdict"><option>Low</option><option>Medium</option><option>High</option></Select>
        </div>
        <div style={{ minWidth: 220, flex: 1 }}><Textarea label="Raw headers" rows={2} defaultValue="Received: ..." /></div>
      </Section>

      <Section title="Checkbox / Radio / Toggle / Segmented">
        <Checkbox label="Hold for review" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
        <Radio label="Option A" name="ds-radio" defaultChecked /> <Radio label="Option B" name="ds-radio" />
        <Toggle label={toggled ? 'Polling on' : 'Polling off'} checked={toggled} onChange={(e) => setToggled(e.target.checked)} />
        <SegmentedControl
          label="Ingest source"
          value={seg}
          onChange={setSeg}
          options={[{ value: 'upload', label: 'Upload' }, { value: 'paste', label: 'Paste' }, { value: 'mailbox', label: 'Mailbox' }]}
        />
      </Section>

      <Card title="Table + Tabs" description="Inset well, sticky header, hairline rows; tabs use arrow keys." actions={<Badge tone="neutral">flat rows · no shadows</Badge>}>
        <Tabs tabs={['Summary', 'Why this score?', 'Headers']} active={tab} onChange={setTab} label="Demo tabs" />
        <div style={{ marginTop: 12 }}>
          <Table label="Demo threats">
            <thead><tr><th scope="col">Subject</th>
              <SortTh label="Score" direction={sortDir} onSort={() => setSortDir(sortDir === 'ascending' ? 'descending' : 'ascending')}>Score</SortTh>
              <th scope="col">Severity</th></tr></thead>
            <tbody>
              <tr><td>Invoice #441</td><td>82</td><td><SeverityBadge score={82} /></td></tr>
              <tr><td>Quarterly report</td><td>12</td><td><SeverityBadge score={12} /></td></tr>
            </tbody>
          </Table>
        </div>
      </Card>

      <Section title="Badges + status">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <Badge key={s} tone={s} icon={<SeverityIcon severity={s} />}>{s}</Badge>
        ))}
        <Badge tone="info">Info</Badge><Badge tone="neutral">Draft</Badge>
        <SeverityBadge score={95} /><SeverityBadge score={20} />
        <StatusIndicator color={ct.risk.low} label="Connected" />
        <StatusIndicator color={ct.risk.critical} label="Error" />
      </Section>

      <Section title="Alerts + loading + empty + error">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1, minWidth: 260 }}>
          <Alert tone="info" title="Sync finished">3 emails ingested.</Alert>
          <Alert tone="warning">Polling is off — sync is manual.</Alert>
          <Alert tone="error" title="Ingest failed">Malformed RFC822 body.</Alert>
          <Alert tone="success" dismissible>Case created.</Alert>
        </div>
        <Spinner /> <Skeleton height={44} width={180} />
        <div style={{ flex: 1, minWidth: 260 }}><EmptyState message="No related entities yet." action={<Button variant="primary" size="sm">Ingest email</Button>} /></div>
        <div style={{ flex: 1, minWidth: 260 }}><ErrorState message="Could not load mailbox." detail="GET /oauth/status → 503" onRetry={() => {}} /></div>
      </Section>

      <Section title="Modal / Drawer / Tooltip / Well">
        <Button onClick={() => setModal(true)}>Open modal</Button>
        <Button onClick={() => setDrawer(true)}>Open drawer</Button>
        <Tooltip label="Copy message ID"><button type="button" className="neu-btn neu-btn--sm">Hover or focus me</button></Tooltip>
        <div style={{ flex: 1, minWidth: 260 }}><Well>Flat content lives in inset wells, never in nested raised cards.</Well></div>
      </Section>

      {modal ? <Modal title="Confirm delete" onClose={() => setModal(false)}><p>Destructive actions require a confirm dialog and live in a danger zone (Phase 2).</p><Button variant="danger">Delete</Button></Modal> : null}
      {drawer ? <Drawer title="Investigation detail" onClose={() => setDrawer(false)}><p>Slide-over panel used on tablet and mobile.</p></Drawer> : null}
    </div>
  );
}
