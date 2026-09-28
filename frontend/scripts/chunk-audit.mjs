// One-off chunk audit: prints cross-chunk imports and marker hits per chunk.
import { readFileSync, readdirSync } from 'node:fs';

const dir = new URL('../dist/assets/', import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith('.js'));
for (const f of files) {
  const t = readFileSync(new URL(f, dir), 'utf8');
  const imports = [...t.matchAll(/from"\.\/([a-zA-Z0-9_-]+)-[A-Za-z0-9_-]+\.js"/g)].map((m) => m[1]);
  const uniq = [...new Set(imports)];
  const marks = ['reconciler', 'useSyncExternalStore', 'createPortal', 'useLayoutEffect', 'zustand'].filter((m) => t.includes(m));
  console.log(`${f} raw=${t.length} imports=[${uniq.join(',')}] marks=[${marks.join(',')}]`);
}
