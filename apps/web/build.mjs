// Phase 1 web placeholder build: copies the static shell into dist/. A real Vite/React app replaces this in a
// later phase. Kept dependency-free so the monorepo bootstraps without a frontend toolchain yet.
import { mkdir, copyFile } from 'node:fs/promises';

await mkdir(new URL('./dist/', import.meta.url), { recursive: true });
await copyFile(
  new URL('./index.html', import.meta.url),
  new URL('./dist/index.html', import.meta.url),
);
process.stdout.write('web: built static shell to dist/index.html\n');
